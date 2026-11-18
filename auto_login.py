#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 whitexxc
# SPDX-License-Identifier: GPL-3.0-or-later
#
"""TUST 校园网自动登录（无头版，无 GUI 依赖）

协议实现参考 gethub-15/TUST-Campus-Network-Auto-Login----Android-and-Windows- 的
Windows 版（Dr.COM eportal 网页认证），去掉了 tkinter 界面，改为可开机自动执行。

用法：
    python auto_login.py --setup      # 首次配置：录入学号/密码/联网方式，DPAPI 加密保存
    python auto_login.py --status     # 只看状态，不登录
    python auto_login.py              # 执行一次：未在线才登录
    python auto_login.py --watch      # 常驻：每 5 分钟巡检一次（开机自启用这个）
    python auto_login.py --logout     # 注销当前设备

退出码：
    0 成功 / 已在线        1 登录失败        2 未配置账号
    3 在线但不是当前账号    4 网络未就绪

注意：本脚本只把账号密码提交给校园网认证服务器（10.10.102.50），不访问任何第三方。
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
from datetime import datetime
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

# ---------------------------------------------------------------- 常量

APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "TustAutoLogin"
CRED_PATH = APP_DIR / "cred.dat"
LOG_PATH = APP_DIR / "auto-login.log"
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

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TUST-AutoLogin/1.0"

DEFAULT_INTERVAL = 300   # 巡检间隔（秒）
DEFAULT_WAIT = 180       # 等网络就绪的最长时间（秒）
NET_POLL = 3.0           # 等网络时的轮询间隔（秒）

LOGIN_OK_MARKS = ("协议认证成功", '"result":"1"', "认证成功")
LOGIN_ALREADY_MARKS = ("已经在网", "已在网", "already online", '"ret_code":2', '"ret_code": "2"')
PASSWORD_ERROR_MARKS = ("统一身份认证密码错误", "密码错误", "password error")
DOMAIN_ERROR_MARKS = ("domain error",)

QUIET = False

# ---------------------------------------------------------------- 日志


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
    """写日志文件；非 --quiet 且有控制台时同时打印。"""
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} [{level}] {message}"
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        _log_rotate()
        # 首次创建时带 BOM：这样 PowerShell 5.1 的 Get-Content 和记事本都能正确显示中文
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
    payload = json.dumps(
        {"v": 1, "account": account, "password": password, "operator": operator},
        ensure_ascii=False,
    ).encode("utf-8")
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CRED_PATH.write_bytes(dpapi_protect(payload))
    try:  # 仅当前用户的 ACL（尽力而为，失败不影响功能）
        os.chmod(CRED_PATH, 0o600)
    except OSError:
        pass


def load_creds() -> dict | None:
    if not CRED_PATH.exists():
        return None
    try:
        data = json.loads(dpapi_unprotect(CRED_PATH.read_bytes()).decode("utf-8"))
    except Exception:
        return None
    if not data.get("account") or not data.get("password"):
        return None
    return data


# ---------------------------------------------------------------- 网络探测


def gateway_source_ip() -> str:
    """本机访问校园网关时会使用的源地址。

    直接问「到网关走哪条路由」，比问 8.8.8.8 更准：
    装了 VPN/虚拟网卡时，8.8.8.8 可能落到虚拟网卡上而拿到错误地址。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.connect((GATEWAY_HOST, GATEWAY_PORT))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


def is_campus_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    return addr.is_private and not addr.is_loopback and not addr.is_link_local


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


def wait_for_network(max_wait: int) -> str:
    """循环等到「拿到校园网内网 IP 且网关可达」，返回 IP；超时返回空串。"""
    deadline = time.monotonic() + max(1, max_wait)
    last_reason = "尚未获取到 IPv4 地址"
    while True:
        ip = gateway_source_ip()
        if not ip:
            last_reason = "尚未获取到 IPv4 地址（网卡可能还没连上 Wi-Fi）"
        elif not is_campus_ip(ip):
            last_reason = (
                f"本机出口地址是 {ip}，不属于校园网内网段"
                "（通常是有 VPN / 虚拟网卡抢占了默认路由）"
            )
        elif not tcp_reachable(GATEWAY_HOST, GATEWAY_PORT):
            last_reason = f"校园网关 {GATEWAY_HOST}:{GATEWAY_PORT} 不可达"
        else:
            return ip
        if time.monotonic() >= deadline:
            log(f"等待网络就绪超时（{max_wait}s）：{last_reason}", "WARN")
            return ""
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
        num = str(
            (int(ip.split(".")[0]) << 24)
            + (int(ip.split(".")[1]) << 16)
            + (int(ip.split(".")[2]) << 8)
            + int(ip.split(".")[3])
        )
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
    def __init__(self) -> None:
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()))

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
    """Dr.COM 门户页是 gb2312，接口是 utf-8/jsonp，按顺序试。

    用错编码会让「注销页/认证成功」这类中文关键字全部匹配不上。
    """
    for encoding in ("utf-8", "gb18030"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


ACCOUNT_RE = re.compile(
    r'"(?:user_account|userAccount|userName|userIdNumber|user_name)"\s*:\s*"([^"]*)"'
)


def account_local(value: str) -> str:
    """把 `23083214@unicom` 归一成 `23083214`。"""
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


def parse_online_list(text: str) -> list:
    """解析 dr1019({...}) 形式的在线设备列表。"""
    match = re.search(r"\{.*\}", text or "", re.S)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except ValueError:
        return []
    items = data.get("list")
    return items if isinstance(items, list) else []


def _contains(text: str, marks) -> bool:
    return any(m in (text or "") for m in marks)


def is_accepted(text: str) -> bool:
    return _contains(text, LOGIN_OK_MARKS)


def is_already_online(text: str) -> bool:
    return _contains(text, LOGIN_ALREADY_MARKS)


def is_current_account(text: str, account: str) -> bool:
    """兼容旧调用：在整段文本里找该学号对应的账号字段。"""
    if not text or not account:
        return False
    for match in ACCOUNT_RE.finditer(text):
        if same_account(match.group(1), account):
            return True
    return False


def explain_failure(text: str) -> str:
    if _contains(text, PASSWORD_ERROR_MARKS):
        return "密码错误（统一身份认证未通过）"
    if _contains(text, DOMAIN_ERROR_MARKS):
        return "上网方式选择错误（联通/移动/电信后缀与账号不匹配）"
    compact = " ".join((text or "").split())
    if not compact:
        return "网关没有返回任何内容（可能是网络中断或网关异常）"
    return compact[:160] + ("..." if len(compact) > 160 else "")


def probe(portal: Portal, ip: str):
    """查本机在网关上的会话。

    返回 (session 或 None, 门户页文本)。session 是本机这个 IP 的在线记录，
    不是「网关上有没有别的设备在线」——这一点很关键，否则会重复认证自踢。
    """
    page = ""
    items: list = []
    try:
        page = portal.get(portal_page_url(ip), 8)
    except Exception as exc:  # noqa: BLE001
        log(f"读取门户页失败：{exc}", "WARN")
    try:
        items = parse_online_list(portal.get(online_list_url(ip), 8))
    except Exception as exc:  # noqa: BLE001
        log(f"读取在线列表失败：{exc}", "WARN")

    for item in items:
        if str(item.get("online_ip", "")) == ip:
            return item, page

    if not items and ("olflow=" in page or "注销页" in page):
        # 在线列表读不到时用门户页兜底；宁可这一轮不动，也不要重复认证把设备踢掉
        return {"user_account": "", "_fallback": True}, page
    return None, page


def detect_current_session():
    """当前是否已经在线；setup 时用来预填账号和上网方式。"""
    ip = gateway_source_ip()
    if not ip or not is_campus_ip(ip):
        return None
    if not tcp_reachable(GATEWAY_HOST, GATEWAY_PORT):
        return None
    try:
        session, _ = probe(Portal(), ip)
        return session
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- 业务流程


def do_login(max_wait: int) -> int:
    creds = load_creds()
    if not creds:
        log("尚未配置账号，请先运行： python auto_login.py --setup", "ERROR")
        return 2

    ip = wait_for_network(max_wait)
    if not ip:
        return 4

    portal = Portal()
    session, _page = probe(portal, ip)

    if session:
        online = str(session.get("user_account", ""))
        if online and same_account(online, creds["account"]):
            log(f"已在线（{mask_account(online)}，IP {ip}），无需登录")
            return 0
        log(
            f"IP {ip} 上已有会话（{mask_account(online) or '账号未知'}），"
            "为避免互踢，本次不发起登录",
            "WARN",
        )
        return 3

    try:
        result = portal.get(login_url(ip, creds["account"], creds["password"], creds["operator"]), 12)
    except Exception as exc:  # noqa: BLE001
        log(f"登录请求失败：{exc}", "ERROR")
        return 1

    if is_accepted(result):
        log(f"登录成功（{mask_account(creds['account'])}，IP {ip}）")
        return 0
    if is_already_online(result):
        log("账号已在其他设备在线，网关跳过了本次认证")
        return 0

    log(f"登录失败：{explain_failure(result)}", "ERROR")
    return 1


def do_status(max_wait: int) -> int:
    ip = wait_for_network(max_wait)
    if not ip:
        return 4
    session, _page = probe(Portal(), ip)
    if session:
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
    else:
        log(f"状态：未登录（IP {ip}）")
    log(f"日志文件：{LOG_PATH}")
    return 0


def do_logout(max_wait: int) -> int:
    ip = wait_for_network(max_wait)
    if not ip:
        return 4
    try:
        result = Portal().get(logout_url(ip), 10)
    except Exception as exc:  # noqa: BLE001
        log(f"注销请求失败：{exc}", "ERROR")
        return 1
    if _contains(result, ("注销成功", '"result":"1"', "上网登录页")):
        log(f"已注销（IP {ip}）")
        return 0
    log(f"注销结果未确认：{' '.join(result.split())[:120]}", "WARN")
    return 0


def do_watch(args) -> int:
    if not load_creds():
        log("尚未配置账号，巡检不启动。请先运行： python auto_login.py --setup", "ERROR")
        return 2
    log(f"巡检已启动：每 {args.interval}s 检查一次")
    while True:
        try:
            code = do_login(args.wait)
        except KeyboardInterrupt:
            log("收到退出信号，巡检结束")
            return 0
        except Exception as exc:  # noqa: BLE001
            log(f"巡检异常：{exc}", "ERROR")
            code = 1
        if code == 2:
            log("账号配置已丢失，停止巡检")
            return 2
        # 失败时更快重试（校园网偶尔抽风，30s 后再试一次）
        delay = args.interval if code == 0 else min(30, args.interval)
        try:
            time.sleep(delay)
        except KeyboardInterrupt:
            log("收到退出信号，巡检结束")
            return 0


# ---------------------------------------------------------------- 单实例 & 配置


def acquire_mutex():
    """防止多个实例同时登录把彼此踢下线。返回句柄，None 表示已有实例。"""
    _k32.CreateMutexW.restype = ctypes.c_void_p
    _k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    handle = _k32.CreateMutexW(None, 0, "Local\\TustAutoLogin")
    if not handle:
        return None
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        _k32.CloseHandle(ctypes.c_void_p(handle))
        return None
    return handle


def cmd_setup() -> int:
    print("== TUST 校园网自动登录 · 首次配置 ==")
    print("账号密码用 Windows DPAPI 加密后保存到：")
    print(f"  {CRED_PATH}")
    print("（只有当前 Windows 用户能解密，复制到别的电脑或账户都用不了）")
    print()

    # 如果此刻已经在线，直接用网关上的信息预填，回车即用
    session = detect_current_session() or {}
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
    for i, (name, _) in enumerate(OPERATORS, 1):
        print(f"  {i}. {name}")
    default_index = 1
    if hint_operator:
        for i, (name, _) in enumerate(OPERATORS, 1):
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
    print(f"\n已保存（账号 {account}，上网方式 {operator}）")
    print("下一步：")
    print("  1) 先自检一次：  python auto_login.py --status")
    print("  2) 安装自启：    powershell -ExecutionPolicy Bypass -File .\\install.ps1")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="TUST 校园网自动登录（无头版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--setup", action="store_true", help="配置账号密码")
    parser.add_argument("--status", action="store_true", help="只查状态，不登录")
    parser.add_argument("--logout", action="store_true", help="注销当前设备")
    parser.add_argument("--watch", action="store_true", help="常驻巡检（开机自启用）")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="巡检间隔秒，默认 300")
    parser.add_argument("--wait", type=int, default=DEFAULT_WAIT, help="等网络就绪秒数，默认 180")
    parser.add_argument("--quiet", action="store_true", help="不输出到控制台，只写日志")
    args = parser.parse_args(argv)

    global QUIET
    QUIET = args.quiet

    if args.setup:
        return cmd_setup()
    if args.status:
        return do_status(min(args.wait, 30))
    if args.logout:
        return do_logout(min(args.wait, 60))

    handle = acquire_mutex()
    if handle is None:
        log("已有实例在运行，本次退出")
        return 0
    try:
        if args.watch:
            return do_watch(args)
        return do_login(args.wait)
    finally:
        try:
            _k32.CloseHandle(ctypes.c_void_p(handle))
        except Exception:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
