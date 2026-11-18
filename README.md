# TUST 校园网自动登录（开机自启版）

在原项目 [TUST-Campus-Network-Auto-Login](https://github.com/gethub-15/TUST-Campus-Network-Auto-Login----Android-and-Windows-)
的协议逻辑基础上，做了一个**无界面、可开机自动执行**的版本。

原版的 Windows 程序是 GUI，启动后只会「检测」状态，联网必须手点按钮；
这个版本登录、断线重连、巡检全部自动，不弹窗口。

## 快速开始（两条命令）

在 PowerShell 里进入本目录，执行：

```powershell
# 1) 录入账号（会自动探测当前在线的账号和上网方式，直接回车即可沿用）
python auto_login.py --setup

# 2) 安装开机自启，并在后台立即启动
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

装完就完事了：以后每次登录 Windows 自动运行，之后每 5 分钟静默巡检一次，
已在线就什么都不做，掉线才重新认证。

## 常用命令

| 命令 | 作用 |
|---|---|
| `python auto_login.py --setup` | 录入 / 修改账号密码 |
| `python auto_login.py --status` | 只查状态，不登录（排查问题先看这个） |
| `python auto_login.py` | 现在手动执行一次 |
| `python auto_login.py --logout` | 注销当前设备 |
| `python auto_login.py --watch` | 常驻巡检（开机自启用它，手动跑可加 `--interval 60` 调频率） |
| `.\install.ps1 -Uninstall` | 卸载：删启动项 + 结束巡检进程 |

日志：`%LOCALAPPDATA%\TustAutoLogin\auto-login.log`（超过 512 KB 自动轮转一份 `.log.1`）

```powershell
Get-Content -Tail 20 -Wait "$env:LOCALAPPDATA\TustAutoLogin\auto-login.log"
```

## 文件说明

| 文件 | 说明 |
|---|---|
| `auto_login.py` | 主脚本。只用 Python 标准库，无第三方依赖 |
| `install.ps1` | 写当前用户的启动项（不需要管理员权限） |
| `%LOCALAPPDATA%\TustAutoLogin\cred.dat` | 账号密码，Windows DPAPI 加密，只有当前用户能解密 |
| `%LOCALAPPDATA%\TustAutoLogin\auto-login.log` | 运行日志 |

## 它怎么判断「要不要登录」

每轮巡检做三件事，顺序很重要：

1. **等网络就绪**：确认本机出口 IP 落在内网段、且网关 `10.10.102.50:80` 可达。
   开机瞬间 Wi-Fi 还没关联时会一直等（默认最多 180 秒），不是固定 sleep。
2. **查本机这个 IP 的会话**：调用 `portal/online_list`，在返回列表里找
   `online_ip` 等于本机 IP 的那一条。
3. **再决定**：
   - 有会话且 `user_account` 就是自己 → 记录「已在线」，直接退出，**不发登录请求**；
   - 有会话但是别的账号 → 记录警告，**不发登录请求**（避免把别人踢下线）；
   - 没有本机会话 → 才发起认证。

> 只查「网关上有没有设备在线」是不够的：如果那样做，每 5 分钟就会重复认证一次，
> 把自己反复踢下线。所以判断依据必须是「本机 IP 是否有会话」。

## 已知限制

- **上网方式必须选对**。账号后缀（`@unicom` / `@cmcc` / `@telecom` / 无）和运营商要匹配，
  选错会报「domain error」。`--setup` 会自动探测并预选，正常情况下回车即可。
- **改过密码要重跑 `--setup`**，否则巡检会一直报「密码错误」。
- 装 VPN（如 Radmin VPN）且它抢走默认路由时，脚本会检测到出口 IP 不是内网段并拒绝登录，
  日志里会写清楚原因 —— 这种状态下即使强行提交也会失败。
- 校园网门户改版会导致接口/字段变化，需要更新脚本。这正是原项目 v1.1 在修的那类问题。
- 巡检每 5 分钟产生 2 个很小的 HTTP 请求，基本可以忽略。
- 单实例互斥只在当前 Windows 会话内生效；同一账号在多台设备上同时用仍会互踢。

## 来源与致谢

协议细节（Dr.COM eportal 的接口路径、`user_account` 的 `,0,` 前缀格式、运营商后缀、
`wlan_user_ip` 的取法）参考了同校项目
[TUST-Campus-Network-Auto-Login](https://github.com/gethub-15/TUST-Campus-Network-Auto-Login----Android-and-Windows-)。
本项目是独立的无界面重写，**没有复制其源码**。

其中有两处判断逻辑在原项目中会失效，本项目已修正：

1. 门户页是 **gb2312** 编码，按 UTF-8 解码会让「注销页 / 认证成功」这类中文关键字全部匹配不上；
2. 在线列表的字段是 `online_ip` / `user_account` / `total`，**不是** `loginTime`。
   照原来的写法，明明在线也会被判成「未登录」，于是反复重复认证、把自己踢下线。

## 免责声明

- 本项目与天津科技大学及校园网运营方**无任何隶属关系**，未获其授权或认可。
- 仅用于让自己已授权的设备自动完成网页认证，请遵守学校网络使用规范。
- 账号密码保存在本机（Windows DPAPI 加密），不会上传到任何第三方；
  但「无人值守」的前提就是密码必须常驻本机，这一点请自行权衡。
- 使用本工具造成的任何后果由使用者自行承担。

## 许可证

[GPL-3.0](LICENSE) © 2026 whitexxc

