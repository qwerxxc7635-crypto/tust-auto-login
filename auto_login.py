#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 whitexxc
# SPDX-License-Identifier: GPL-3.0-or-later
#
"""TUST 校园网自动登录（无头版，无 GUI 依赖）

Dr.COM eportal 网页认证的无人值守实现：开机自启、在线不打扰、掉线自动重连。

协议细节（接口路径、user_account 的 ",0," 前缀、运营商后缀、wlan_user_ip 的取法）
来自对校园网门户页面及其脚本的观察，并参考了同校开源项目；本文件为独立重写。

用法：
    python auto_login.py --setup       # 首次配置：录入学号/密码/联网方式（DPAPI 加密保存）
    python auto_login.py --diagnose    # 环境自检：IP 选择、代理、网关、Clash/TUN 状态
    python auto_login.py --status      # 只看状态，不登录
    python auto_login.py               # 执行一次：未在线才登录
    python auto_login.py --watch       # 常驻巡检（开机自启用这个）
    python auto_login.py --logout      # 注销当前设备，并暂停自动登录
    python auto_login.py --resume      # 恢复自动登录

退出码：
    0 成功 / 已在线 / 已暂停    1 登录失败或状态未知    2 未配置账号
    3 在线但不是当前账号        4 网络未就绪            5 需要人工处理（密码或上网方式错误）
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import ipaddress
import json
import os
import re
import socket
import sys
import time
import traceback
from datetime import datetime
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener

VERSION = "1.1.2"

# ---------------------------------------------------------------- 常量

APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TustAutoLogin"
CRED_PATH = APP_DIR / "cred.dat"
LOG_PATH = APP_DIR / "auto-login.log"
PAUSE_PATH = APP_DIR / "paused"
LOG_MAX_BYTES = 512 * 1024

GATEWAY_HOST = "10.10.102.50"
GATEWAY_PORT = 80
PORTAL_HOST = f"http://{GATEWAY_HOST}"
PORTAL_LOGIN = f"{PORTAL_HOST}:801/eportal/portal/login"
PORTAL_LOGOUT = f"{PORTAL_HOST}:801/eportal/portal/logout"
PORTAL_ONLINE_LIST = f"{PORTAL_HOST}:801/eportal/portal/online_list"
AC_IP = "10.10.102.49"
AC_NAME = ""

OPERATORS = [
    ("校园网", ""),
    ("中国联通", "@unicom"),
    ("中国移动", "@cmcc"),
    ("中国电信", "@telecom"),
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TUST-AutoLogin/1.1"

# 校园网内网段：用来排除 Clash/VPN 的虚拟网卡地址。若你校网不是 10/8，用 --campus-cidr 覆盖。
CAMPUS_CIDR = "10.0.0.0/8"
# 这些段永远不算校园网地址：Clash/Mihomo TUN(198.18/15)、CGNAT(100.64/10)、链路本地、回环
EXCLUDED_NETS = ("198.18.0.0/15", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8")

FAST_INTERVAL = 600       # 掉线/异常时的巡检间隔（秒）
SLOW_INTERVAL = 3600      # 连续稳定在线后的巡检间隔（秒）
STABLE_CHECKS = 5         # 连续几次在线后降频
DEFAULT_WAIT = 180        # 等网络就绪的最长秒数
NET_POLL = 3.0            # 等网络时的轮询间隔
BLIND_AFTER = 3           # 连续读不到状态多少轮后，允许盲登一次
BLIND_COOLDOWN = 3600.0   # 两次盲登的最小间隔（秒）
SLEEP_CHUNK = 5.0         # 分片睡眠粒度，用于检测休眠唤醒

PASSWORD_ERROR_MARKS = ("统一身份认证密码错误", "密码错误", "password error")
DOMAIN_ERROR_MARKS = ("domain error",)

ST_UNKNOWN = -1
ST_OFFLINE = 0
ST_ONLINE = 1

QUIET = False
_last_state = None
_unknown_streak = 0
_last_blind = 0.0

# ---------------------------------------------------------------- 日志

_SECRET_RE = re.compile(r"((?:user_)?password=)([^&\s\"']+)", re.IGNORECASE)


def _redact(text: str) -> str:
    """兜底脱敏：任何情况下都不让 URL 里的密码进日志。"""
    return _SECRET_RE.sub(r"\1***", str(text))


def _log_rotate() -> None:
    try:
        if LOG_PATH.exists() and LOG_PATH.stat().st_size >= LOG_MAX_BYTES:
            old = LOG_PATH.with_name(LOG_PATH.name + ".1")
            if old.exists():
                old.unlink()
            LOG_PATH.replace(old)
    except OSError:
        pass


def log(message: str, level: str = "INFO") -> None:
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} [{level}] {_redact(message)}"
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        _log_rotate()
        # 首次创建带 BOM：PowerShell 5.1 的 Get-Content 和记事本都能正确显示中文
        new_file = not LOG_PATH.exists()
        with open(LOG_PATH, "a", encoding="utf-8-sig" if new_file else "utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    if not QUIET and sys.stdout is not None:
        try:
            print(line, flush=True)
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------- DPAPI 凭据


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]


_crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

_BLOB_PTR = ctypes.POINTER(_DATA_BLOB)
_crypt32.CryptProtectData.argtypes = [
    _BLOB_PTR, ctypes.c_wchar_p, _BLOB_PTR, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_ulong, _BLOB_PTR,
]
_crypt32.CryptProtectData.restype = ctypes.c_int
_crypt32.CryptUnprotectData.argtypes = [
    _BLOB_PTR, ctypes.c_void_p, _BLOB_PTR, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_ulong, _BLOB_PTR,
]
_crypt32.CryptUnprotectData.restype = ctypes.c_int
_k32.LocalFree.argtypes = [ctypes.c_void_p]
_k32.LocalFree.restype = ctypes.c_void_p

CRYPTPROTECT_UI_FORBIDDEN = 0x1
ENTROPY = b"TustAutoLogin-v1"


def _blob(data: bytes) -> _DATA_BLOB:
    n = len(data)
    buf = ctypes.create_string_buffer(bytes(data), n if n else 1)
    return _DATA_BLOB(n, ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def dpapi_protect(data: bytes) -> bytes:
    blob_in, blob_ent, blob_out = _blob(data), _blob(ENTROPY), _DATA_BLOB()
    ok = _crypt32.CryptProtectData(
        ctypes.byref(blob_in), "TustAutoLogin", ctypes.byref(blob_ent),
        None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _k32.LocalFree(blob_out.pbData)


def dpapi_unprotect(data: bytes) -> bytes:
    blob_in, blob_ent, blob_out = _blob(data), _blob(ENTROPY), _DATA_BLOB()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, ctypes.byref(blob_ent),
        None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _k32.LocalFree(blob_out.pbData)


def save_creds(account: str, password: str, operator: str) -> None:
    """原子写入，避免巡检正好读到写了一半的文件。"""
    payload = json.dumps(
        {"v": 1, "account": account, "password": password, "operator": operator},
        ensure_ascii=False,
    ).encode("utf-8")
    blob = dpapi_protect(payload)
    APP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CRED_PATH.with_name(CRED_PATH.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(blob)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, CRED_PATH)


def load_creds_checked():
    """返回 (creds, error)。

    creds 为 None 且 error 为 None → 从未配置；
    creds 为 None 且 error 有值 → 文件在但读不了（DPAPI/权限/内容问题），不要当成"未配置"。
    """
    if not CRED_PATH.exists():
        return None, None
    try:
        raw = CRED_PATH.read_bytes()
    except OSError as exc:
        return None, f"读取 {CRED_PATH.name} 失败：{exc}"
    try:
        data = json.loads(dpapi_unprotect(raw).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001  DPAPI 的 WinError 也是 OSError，一并记录
        return None, f"解密失败（换过 Windows 账户或重置过密码会导致此错误）：{type(exc).__name__}: {exc}"
    if not isinstance(data, dict) or not data.get("account") or not data.get("password"):
        return None, "凭据内容不完整"
    return data, None


def load_creds():
    return load_creds_checked()[0]


# ---------------------------------------------------------------- 本机地址选择


def _parse_net(value: str, default: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return ipaddress.ip_network(default)


def _excluded_nets():
    return tuple(ipaddress.ip_network(n) for n in EXCLUDED_NETS)


def campus_net_of(value: str = ""):
    return _parse_net(value or CAMPUS_CIDR, CAMPUS_CIDR)


def classify_ip(ip: str, campus_net):
    """(是否可作校园网源地址, 原因)"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, "非法地址"
    if addr.version != 4:
        return False, "不是 IPv4"
    for net in _excluded_nets():
        if addr in net:
            return False, f"{net} 是虚拟网卡/保留网段"
    if addr not in campus_net:
        return False, f"不在校园网段 {campus_net}"
    return True, ""


def gateway_source_ip() -> str:
    """系统路由表认为访问网关时会用的源地址（UDP connect 不发包，只查路由）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.connect((GATEWAY_HOST, GATEWAY_PORT))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


def ipv4_candidates() -> list:
    found: list = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in found:
                found.append(ip)
    except OSError:
        pass
    route_ip = gateway_source_ip()
    if route_ip and route_ip not in found:
        found.append(route_ip)
    return found


def pick_source_ip(campus_net, override: str = ""):
    """挑出该提交给网关的本机 IPv4。

    不直接用「到网关的路由源地址」，因为 Clash TUN 会把 10.x 也劫持进 198.18/15，
    那样提交上去的 wlan_user_ip 就是 TUN 地址，认证必然失败。
    """
    if override:
        ok, why = classify_ip(override, campus_net)
        if ok:
            return override, "手动指定（--source-ip）"
        return "", f"--source-ip {override} 不可用：{why}"

    route_ip = gateway_source_ip()
    cands = ipv4_candidates()
    good = [ip for ip in cands if classify_ip(ip, campus_net)[0]]

    if len(good) == 1:
        note = "自动识别"
        if route_ip and route_ip != good[0]:
            note = f"自动识别（路由出口是 {route_ip}，已改用 {good[0]}）"
        return good[0], note
    if len(good) > 1:
        if route_ip in good:
            return route_ip, "多个候选地址，取路由出口那个"
        good.sort()
        return good[0], f"多个候选地址 {good}，取第一个（可用 --source-ip 指定）"

    if route_ip:
        ok, why = classify_ip(route_ip, campus_net)
        if not ok:
            hint = ""
            if any(ipaddress.ip_address(route_ip) in n for n in _excluded_nets()):
                hint = "；检测到 Clash/VPN 的 TUN 虚拟网卡抢占了路由，请在 Clash 里把校园网段设为 DIRECT，或关闭 TUN，或用 --source-ip 指定"
            return "", f"出口地址 {route_ip} 不可用（{why}）{hint}"
    return "", "未找到校园网内网地址（是否还没连上校园 Wi-Fi？）"


def is_campus_ip(ip: str, campus_net=None) -> bool:
    return classify_ip(ip, campus_net or campus_net_of())[0]


def tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except OSError:
        return False


def local_ipv6() -> str:
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6):
            ip = info[4][0]
            if ip and not ip.startswith("fe80") and ip != "::1":
                return ip.split("%", 1)[0]
    except OSError:
        pass
    return ""


def wait_for_network(max_wait: int, campus_net, source_ip: str = ""):
    """等「拿到校园网地址 + 网关可达」，返回 (ip, 说明) 或 ("", 原因)。"""
    deadline = time.monotonic() + max(1, max_wait)
    reason = "尚未就绪"
    while True:
        ip, note = pick_source_ip(campus_net, source_ip)
        if ip:
            if tcp_reachable(GATEWAY_HOST, GATEWAY_PORT):
                return ip, note
            reason = f"网关 {GATEWAY_HOST}:{GATEWAY_PORT} 不可达"
        else:
            reason = note
        if time.monotonic() >= deadline:
            log(f"等待网络就绪超时（{max_wait}s）：{reason}", "WARN")
            return "", reason
        time.sleep(NET_POLL)


# ---------------------------------------------------------------- 门户协议


def portal_page_url(ip: str) -> str:
    return (
        f"{PORTAL_HOST}/a79.htm?"
        f"wlanuserip={quote(ip)}&wlanacname={quote(AC_NAME)}&wlanacip={quote(AC_IP)}"
    )


def login_url(ip: str, account: str, password: str, operator: str) -> str:
    suffix = dict(OPERATORS).get(operator, "")
    params = {
        "callback": "dr1239",
        "login_method": "1",
        "user_account": f",0,{account}{suffix}",
        "user_password": password,
        "wlan_user_ip": ip,
        "wlan_user_ipv6": local_ipv6(),
        "wlan_user_mac": "000000000000",
        "wlan_ac_ip": AC_IP,
        "wlan_ac_name": AC_NAME,
        "jsVersion": "4.1.3",
        "terminal_type": "1",
        "lang": "zh-cn",
        "v": "1873",
    }
    return PORTAL_LOGIN + "?" + urlencode(params)


def logout_url(ip: str) -> str:
    params = {
        "callback": "dr1003",
        "login_method": "1",
        "user_account": "drcom",
        "user_password": "123",
        "ac_logout": "1",
        "register_mode": "1",
        "wlan_user_ip": ip,
        "wlan_user_ipv6": "",
        "wlan_vlan_id": "1",
        "wlan_user_mac": "000000000000",
        "wlan_ac_ip": "",
        "wlan_ac_name": "",
        "jsVersion": "4.1.3",
        "v": "9016",
        "lang": "zh",
    }
    return PORTAL_LOGOUT + "?" + urlencode(params)


def online_list_url(ip: str) -> str:
    try:
        parts = [int(p) for p in ip.split(".")]
        num = str(((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) & 0xFFFFFFFF)
    except (ValueError, IndexError):
        num = "0"
    params = {
        "callback": "dr1019",
        "user_account": "",
        "user_password": "123",
        "wlan_user_mac": "000000000000",
        "wlan_user_ip": num,
        "curr_user_ip": num,
        "jsVersion": "4.1.3",
        "v": "3344",
        "lang": "zh",
    }
    return PORTAL_ONLINE_LIST + "?" + urlencode(params)


class Portal:
    """所有请求都强制直连：绝不走系统代理。

    urllib 的 build_opener() 默认会装 ProxyHandler，Windows 上读的是 IE 设置。
    一旦系统代理开着且绕过列表没覆盖网关，请求会带着明文密码进代理进程，
    而本地 TCP 探测却是直连的 —— 报错会非常难懂。
    """

    def __init__(self) -> None:
        self.opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))

    def get(self, url: str, timeout: float = 10.0) -> str:
        req = Request(url, headers={"User-Agent": UA})
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                return decode_body(resp.read())
        except HTTPError as exc:  # 网关参数出错时常返回 4xx，但正文里有原因
            try:
                return decode_body(exc.read())
            except Exception:
                raise


def decode_body(raw: bytes) -> str:
    """门户页是 gb2312，接口是 utf-8/jsonp，按顺序试。用错编码会让中文关键字全部失效。"""
    for encoding in ("utf-8", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


# ---------------------------------------------------------------- 解析与判定


def parse_json(text: str):
    """从 JSONP（dr1019({...})）或纯 JSON 里取出第一个对象。"""
    if not text:
        return None
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except ValueError:
        return None


HTML_MARKS = ("<html", "<!doctype", "<script", "<meta ")


def parse_online_list(text: str):
    """只负责从 JSONP 里取 list：返回 list 或 None（取不到）。"""
    data = parse_json(text)
    if not isinstance(data, dict):
        return None
    items = data.get("list")
    return items if isinstance(items, list) else None


def classify_probe(raw_text: str, ip: str):
    """把 online_list 的返回归一成三态。

    实测：未认证时网关不会返回 JSONP，而是把这个接口请求改写成登录页 HTML。
    早先的实现把"没有 list"一律当成"读不懂"，结果未登录时被判成"状态未知"，
    于是开机该登录时反而不登录 —— 这里按返回形态区分。
    """
    data = parse_json(raw_text)
    answered = "dr1019(" in (raw_text or "")

    if answered and isinstance(data, dict):
        items = data.get("list")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and str(item.get("online_ip", "")) == ip:
                    return ST_ONLINE, item
            return ST_OFFLINE, None
        # 接口正常作答但没有 list 字段：查不到会话
        return ST_OFFLINE, None

    low = (raw_text or "")[:512].lower()
    if any(mark in low for mark in HTML_MARKS):
        # 门户把请求改写成登录页 = 当前未认证
        return ST_OFFLINE, None

    return ST_UNKNOWN, None


def account_local(value: str) -> str:
    return (value or "").split("@")[0].strip()


def same_account(value: str, account: str) -> bool:
    if not value or not account:
        return False
    return account_local(value) == account.strip()


def mask_account(value: str) -> str:
    value = value or ""
    local = account_local(value)
    if not local:
        return ""
    suffix = value[len(local):]
    if len(local) <= 4:
        return local + "****" + suffix
    return f"{local[:4]}****{suffix}"


def operator_from_account(value: str) -> str:
    lowered = (value or "").lower()
    for name, suffix in OPERATORS:
        if suffix and lowered.endswith(suffix):
            return name
    return ""


def _contains(text: str, marks) -> bool:
    return any(m in (text or "") for m in marks)


def message_of(raw: str) -> str:
    data = parse_json(raw)
    if isinstance(data, dict):
        for key in ("msg", "message", "info"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def classify_login_result(raw: str):
    """返回 (verdict, detail)。verdict ∈ ok / already / permanent / fail。"""
    data = parse_json(raw)
    message = message_of(raw)
    if isinstance(data, dict):
        if str(data.get("result")) == "1" or "认证成功" in message:
            return "ok", message
        ret = data.get("ret_code")
        # 精确比较：原实现用子串匹配 "ret_code":2，会误中 20~29
        if ret in (2, "2") or "已经在网" in message or "已在网" in message:
            return "already", message
    text = raw or ""
    if _contains(text, ("协议认证成功", "认证成功")):
        return "ok", message
    if _contains(text, ("已经在网", "已在网", "already online")):
        return "already", message
    if _contains(text, PASSWORD_ERROR_MARKS) or _contains(text, DOMAIN_ERROR_MARKS):
        return "permanent", explain_failure(text)
    return "fail", explain_failure(text)


def explain_failure(text: str) -> str:
    if _contains(text, PASSWORD_ERROR_MARKS):
        return "密码错误（统一身份认证未通过）"
    if _contains(text, DOMAIN_ERROR_MARKS):
        return "上网方式选择错误（运营商后缀与账号不匹配）"
    message = message_of(text)
    if message:
        return message[:160]
    compact = " ".join((text or "").split())
    if not compact:
        return "网关没有返回任何内容（可能是网络中断或网关异常）"
    return compact[:160] + ("..." if len(compact) > 160 else "")


def probe(portal: Portal, ip: str):
    """返回 (状态, 会话)。三态：在线 / 离线 / 读不懂。

    只打一个请求（在线列表），它已经包含本机 IP、账号、上线时间，
    门户页那个判据实测在线时也不含关键字，没有价值，已移除。
    """
    try:
        text = portal.get(online_list_url(ip), 8)
    except Exception as exc:  # noqa: BLE001
        log(f"读取在线列表失败：{exc}", "WARN")
        return ST_UNKNOWN, None
    state, session = classify_probe(text, ip)
    if state == ST_UNKNOWN:
        snippet = " ".join((text or "").split())[:120]
        log(f"在线列表无法判定（网关返回：{snippet or '空'}），本轮状态未知", "WARN")
    return state, session


def detect_current_session(campus_net):
    """当前是否已经在线；--setup 时用来预填账号和上网方式。"""
    ip, _ = pick_source_ip(campus_net)
    if not ip or not tcp_reachable(GATEWAY_HOST, GATEWAY_PORT):
        return None
    try:
        state, session = probe(Portal(), ip)
        return session if state == ST_ONLINE else None
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- 业务流程


def _cred_stamp() -> int:
    try:
        return CRED_PATH.stat().st_mtime_ns
    except OSError:
        return 0


def _state_changed(state) -> bool:
    global _last_state
    changed = state != _last_state
    _last_state = state
    return changed


def do_login(max_wait: int, campus_net, source_ip: str = "") -> int:
    global _unknown_streak, _last_blind

    creds, cred_err = load_creds_checked()
    if creds is None and cred_err is None:
        log("尚未配置账号，请先运行： python auto_login.py --setup", "ERROR")
        return 2
    if creds is None:
        log(f"凭据读不了：{cred_err}", "ERROR")
        return 1

    if PAUSE_PATH.exists():
        log("已手动注销，自动登录暂停（--resume 恢复）")
        return 0

    ip, note = wait_for_network(max_wait, campus_net, source_ip)
    if not ip:
        return 4

    portal = Portal()
    state, session = probe(portal, ip)

    if state == ST_ONLINE:
        _unknown_streak = 0
        online = str(session.get("user_account", ""))
        if online and same_account(online, creds["account"]):
            if _state_changed("online"):
                log(f"已在线（{mask_account(online)}，IP {ip}），无需登录")
            return 0
        if _state_changed("other"):
            log(
                f"IP {ip} 上已有会话（{mask_account(online) or '账号未知'}），"
                "为避免互踢，本次不发起登录",
                "WARN",
            )
        return 3

    if state == ST_UNKNOWN:
        _unknown_streak += 1
        now = time.time()
        if _unknown_streak < BLIND_AFTER or now - _last_blind < BLIND_COOLDOWN:
            _state_changed("unknown")
            log(f"无法确认在线状态（连续 {_unknown_streak} 次），本轮不登录", "WARN")
            return 1
        _last_blind = now
        log(f"连续 {_unknown_streak} 次读不到状态，放行一次登录尝试", "WARN")
    else:
        _unknown_streak = 0

    if _state_changed("offline"):
        log(f"未登录（IP {ip}，{note}），开始认证")

    try:
        raw = portal.get(
            login_url(ip, creds["account"], creds["password"], creds["operator"]), 12
        )
    except Exception as exc:  # noqa: BLE001
        log(f"登录请求失败：{exc}", "ERROR")
        return 1

    verdict, detail = classify_login_result(raw)
    if verdict == "ok":
        log(f"登录成功（{mask_account(creds['account'])}，IP {ip}）")
        _last_state = "online"
        return 0
    if verdict == "already":
        # 二次确认：网关说"已在别处在线"，但本机到底通没通，要看在线列表
        state2, session2 = probe(portal, ip)
        if state2 == ST_ONLINE and same_account(str(session2.get("user_account", "")), creds["account"]):
            log(f"账号已在网关在线，本机 IP {ip} 已确认可用")
            _last_state = "online"
            return 0
        log("网关提示账号已在其它设备在线，但本机没有会话；按失败处理并退避", "WARN")
        return 1
    if verdict == "permanent":
        log(f"登录失败：{detail}。已停止自动重试，请用 --setup 修正账号/密码/上网方式", "ERROR")
        return 5

    log(f"登录失败：{detail}", "ERROR")
    return 1


def do_status(max_wait: int, campus_net, source_ip: str = "") -> int:
    ip, note = wait_for_network(min(max_wait, 30), campus_net, source_ip)
    if not ip:
        return 4
    state, session = probe(Portal(), ip)
    if state == ST_ONLINE:
        online = str(session.get("user_account", ""))
        log(f"状态：已在线（{mask_account(online) or '账号未知'}，IP {ip}）")
        if session.get("online_time"):
            log(
                f"      上线时间 {session.get('online_time')}，"
                f"已在线 {session.get('time_long', '?')} 秒"
            )
        creds = load_creds()
        if creds and online and not same_account(online, creds["account"]):
            log(f"      注意：在线账号与已配置的 {creds['account']} 不一致", "WARN")
    elif state == ST_UNKNOWN:
        log(f"状态：无法确认（IP {ip}）")
    else:
        log(f"状态：未登录（IP {ip}）")
    if PAUSE_PATH.exists():
        log("      自动登录处于暂停状态（--resume 恢复）")
    log(f"日志文件：{LOG_PATH}")
    return 0


def do_logout(max_wait: int, campus_net, source_ip: str = "") -> int:
    ip, _ = wait_for_network(min(max_wait, 60), campus_net, source_ip)
    if not ip:
        return 4
    try:
        result = Portal().get(logout_url(ip), 10)
    except Exception as exc:  # noqa: BLE001
        log(f"注销请求失败：{exc}", "ERROR")
        return 1
    # 注销后必须暂停自动登录，否则下一轮巡检会立刻把你重新登上去
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        PAUSE_PATH.write_text(str(time.time()), encoding="utf-8")
    except OSError as exc:
        log(f"写入暂停标记失败：{exc}", "WARN")
    if _contains(result, ("注销成功", '"result":"1"', "上网登录页")):
        log(f"已注销（IP {ip}），自动登录已暂停；--resume 恢复")
        return 0
    log(f"注销结果未确认：{' '.join(result.split())[:120]}", "WARN")
    log("已暂停自动登录；--resume 恢复")
    return 0


def _fmt_secs(value: int) -> str:
    if value >= 120 and value % 60 == 0:
        return f"{value // 60} 分钟"
    return f"{value} 秒"


def _sleep_with_wake_detection(delay: float) -> bool:
    """分片睡眠。检测到系统休眠恢复或时钟跳变时提前返回 True。

    分片是为了在唤醒后立刻重新巡检，而不是傻等满一轮（最长可达 1 小时）。
    """
    end = time.time() + max(0.0, delay)
    last = time.time()
    while True:
        remain = end - time.time()
        if remain <= 0:
            return False
        time.sleep(min(remain, SLEEP_CHUNK))
        cur = time.time()
        if cur - last > SLEEP_CHUNK * 6:
            return True
        if cur < last:
            return True
        last = cur


def do_watch(args, campus_net) -> int:
    if not CRED_PATH.exists():
        log("尚未配置账号，巡检不启动。请先运行： python auto_login.py --setup", "ERROR")
        return 2
    try:
        PAUSE_PATH.unlink()
    except OSError:
        pass

    fast = max(10, args.interval)
    slow = max(fast, args.interval_slow)
    log(f"巡检已启动 v{VERSION}：稳定在线时每 {_fmt_secs(slow)}，掉线/异常时每 {_fmt_secs(fast)} 检查一次")

    stable = 0
    while True:
        try:
            code = do_login(args.wait, campus_net, args.source_ip)
        except KeyboardInterrupt:
            log("收到退出信号，巡检结束")
            return 0
        except Exception:  # noqa: BLE001
            log("巡检异常：\n" + traceback.format_exc(), "ERROR")
            code = 1

        if code == 2:
            log("账号配置已丢失，停止巡检")
            return 2

        if code == 5:
            # 密码错 / 上网方式错：重试只会累积失败次数，等凭据更新
            stamp = _cred_stamp()
            log(f"需要人工处理，已停止访问网关；重新运行 --setup 后自动恢复（监视 {CRED_PATH.name}）", "ERROR")
            while _cred_stamp() == stamp:
                time.sleep(60)
            stable = 0
            continue

        if code == 0:
            stable = min(stable + 1, STABLE_CHECKS)
        else:
            stable = 0

        if code == 3:
            delay = max(slow, 300)
        elif code == 0 and stable >= STABLE_CHECKS:
            delay = slow
        else:
            delay = fast

        try:
            if _sleep_with_wake_detection(delay):
                log("检测到系统休眠恢复或时钟跳变，立即重新检查", "INFO")
        except KeyboardInterrupt:
            log("收到退出信号，巡检结束")
            return 0


# ---------------------------------------------------------------- 单实例


def acquire_mutex():
    """返回句柄；None 表示已有实例在跑；创建失败直接抛错（不要冒充"已有实例"）。"""
    _k32.CreateMutexW.restype = ctypes.c_void_p
    _k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    handle = _k32.CreateMutexW(None, 0, "Local\\TustAutoLogin")
    err = ctypes.get_last_error()
    if not handle:
        raise ctypes.WinError(err)
    if err == 183:  # ERROR_ALREADY_EXISTS
        _k32.CloseHandle(ctypes.c_void_p(handle))
        return None
    return handle


# ---------------------------------------------------------------- 自检


def do_diagnose(campus_net, source_ip: str = "") -> int:
    import urllib.request as _ur

    log(f"===== 环境自检 v{VERSION} =====")
    log(f"Python      : {sys.version.split()[0]}  ({sys.executable})")
    log(f"脚本        : {Path(__file__).resolve()}")
    log(f"数据目录    : {APP_DIR}")

    creds, err = load_creds_checked()
    if creds:
        log(f"凭据        : 正常（{mask_account(creds['account'])}，{creds.get('operator', '?')}）")
    elif err:
        log(f"凭据        : 无法读取 —— {err}", "WARN")
    else:
        log("凭据        : 未配置（先运行 --setup）", "WARN")
    log(f"暂停标记    : {'存在（已暂停）' if PAUSE_PATH.exists() else '无'}")

    log(f"校园网段    : {campus_net}")
    route_ip = gateway_source_ip()
    ok, why = classify_ip(route_ip, campus_net) if route_ip else (False, "无")
    log(f"路由出口 IP : {route_ip or '(无)'} → {'可用' if ok else '不可用：' + why}", "INFO" if ok else "WARN")
    for cand in ipv4_candidates():
        cok, cwhy = classify_ip(cand, campus_net)
        log(f"  候选地址  : {cand:16} {'可用' if cok else '不可用（' + cwhy + '）'}")
    chosen, note = pick_source_ip(campus_net, source_ip)
    log(f"选定源地址  : {chosen or '(无)'}  {note}", "INFO" if chosen else "ERROR")

    proxies = _ur.getproxies()
    log(f"系统代理    : {proxies or '无'}")
    if proxies:
        log(
            f"              网关是否绕过代理：{'是' if _ur.proxy_bypass(GATEWAY_HOST) else '否'}"
            "（本工具始终强制直连，不受影响）"
        )
    log(f"网关 TCP    : {'可达' if tcp_reachable(GATEWAY_HOST, GATEWAY_PORT) else '不可达'}")

    if chosen:
        state, session = probe(Portal(), chosen)
        if state == ST_ONLINE:
            log(f"门户状态    : 已在线（{mask_account(str(session.get('user_account', ''))) or '账号未知'}）")
        elif state == ST_UNKNOWN:
            log("门户状态    : 无法确认（在线列表读不懂）", "WARN")
        else:
            log("门户状态    : 未登录")
    try:
        size = LOG_PATH.stat().st_size
        log(f"日志        : {LOG_PATH}（{size} 字节）")
    except OSError:
        log(f"日志        : {LOG_PATH}（尚未创建）")
    return 0


# ---------------------------------------------------------------- 配置


def cmd_setup(campus_net) -> int:
    print("== TUST 校园网自动登录 · 首次配置 ==")
    print("账号密码用 Windows DPAPI 加密后保存到：")
    print(f"  {CRED_PATH}")
    print("（只有当前 Windows 用户能解密，复制到别的电脑或账户都用不了）")
    print()

    session = detect_current_session(campus_net) or {}
    hint_raw = str(session.get("user_account", ""))
    hint_account = account_local(hint_raw)
    hint_operator = operator_from_account(hint_raw)
    if hint_account:
        print(f"检测到当前已在线：{mask_account(hint_raw)}（{hint_operator or '未识别上网方式'}）")
        print("直接回车即可沿用。\n")

    account_prompt = f"学号 [{hint_account}]：" if hint_account else "学号："
    account = input(account_prompt).strip() or hint_account
    if not account:
        print("学号不能为空")
        return 2

    if sys.stdin is not None and not sys.stdin.isatty():
        # stdin 被重定向时没有控制台可隐藏输入，退回普通读行，否则会卡住等按键
        password = input("密码（当前环境无法隐藏输入，会回显）：")
    else:
        password = getpass.getpass("密码（输入时不显示）：")
    if not password:
        print("密码不能为空")
        return 2

    print("\n上网方式：")
    for i, (name, _suffix) in enumerate(OPERATORS, 1):
        print(f"  {i}. {name}")
    default_index = 1
    if hint_operator:
        for i, (name, _suffix) in enumerate(OPERATORS, 1):
            if name == hint_operator:
                default_index = i
    hint = f"，直接回车默认 {default_index}（{OPERATORS[default_index - 1][0]}）"
    choice = input(f"请选择 [1-{len(OPERATORS)}]{hint}：").strip() or str(default_index)
    try:
        operator = OPERATORS[int(choice) - 1][0]
    except (ValueError, IndexError):
        print(f"选择无效，使用默认：{OPERATORS[default_index - 1][0]}")
        operator = OPERATORS[default_index - 1][0]

    save_creds(account, password, operator)
    # 重新配置意味着用户想恢复自动登录
    try:
        PAUSE_PATH.unlink()
    except OSError:
        pass
    print(f"\n已保存（账号 {account}，上网方式 {operator}）")
    print("下一步：")
    print("  1) 环境自检：  python auto_login.py --diagnose")
    print("  2) 安装自启：  powershell -ExecutionPolicy Bypass -File .\\install.ps1")
    return 0


def main(argv=None) -> int:
    global QUIET

    parser = argparse.ArgumentParser(
        description="TUST 校园网自动登录（无头版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--setup", action="store_true", help="配置账号密码")
    parser.add_argument("--diagnose", action="store_true", help="环境自检（IP/代理/网关/TUN）")
    parser.add_argument("--status", action="store_true", help="只查状态，不登录")
    parser.add_argument("--logout", action="store_true", help="注销当前设备并暂停自动登录")
    parser.add_argument("--resume", action="store_true", help="恢复自动登录")
    parser.add_argument("--watch", action="store_true", help="常驻巡检（开机自启用）")
    parser.add_argument("--interval", type=int, default=FAST_INTERVAL, help=f"异常时巡检间隔秒，默认 {FAST_INTERVAL}")
    parser.add_argument("--interval-slow", type=int, default=SLOW_INTERVAL, help=f"稳定在线后巡检间隔秒，默认 {SLOW_INTERVAL}")
    parser.add_argument("--wait", type=int, default=DEFAULT_WAIT, help=f"等网络就绪秒数，默认 {DEFAULT_WAIT}")
    parser.add_argument("--campus-cidr", default=CAMPUS_CIDR, help=f"校园网段，默认 {CAMPUS_CIDR}")
    parser.add_argument("--source-ip", default="", help="手动指定本机校园网 IPv4（TUN 抢占路由时用）")
    parser.add_argument("--quiet", action="store_true", help="不输出到控制台，只写日志")
    args = parser.parse_args(argv)

    QUIET = args.quiet
    campus_net = campus_net_of(args.campus_cidr)

    if args.setup:
        return cmd_setup(campus_net)
    if args.diagnose:
        return do_diagnose(campus_net, args.source_ip)
    if args.resume:
        try:
            PAUSE_PATH.unlink()
            log("已恢复自动登录")
        except OSError:
            log("当前没有暂停标记，无需恢复")
        return 0
    if args.status:
        return do_status(args.wait, campus_net, args.source_ip)
    if args.logout:
        return do_logout(args.wait, campus_net, args.source_ip)

    try:
        handle = acquire_mutex()
    except OSError as exc:
        log(f"创建单实例互斥体失败：{exc}", "ERROR")
        return 1
    if handle is None:
        log("已有实例在运行，本次退出")
        return 0

    try:
        if args.watch:
            return do_watch(args, campus_net)
        # 手动执行一次：视为用户想恢复自动登录
        try:
            PAUSE_PATH.unlink()
        except OSError:
            pass
        return do_login(args.wait, campus_net, args.source_ip)
    finally:
        try:
            _k32.CloseHandle(ctypes.c_void_p(handle))
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001  pythonw 没有 stderr，未捕获异常必须落盘
        log("未捕获异常：\n" + traceback.format_exc(), "ERROR")
        sys.exit(70)
