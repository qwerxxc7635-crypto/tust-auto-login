<#
  TUST 校园网自动登录 —— 安装 / 卸载脚本
  Copyright (C) 2026 whitexxc
  SPDX-License-Identifier: GPL-3.0-or-later

  用法（在脚本所在目录打开 PowerShell）：
    .\install.ps1              安装：把「后台巡检」写入当前用户的启动项，已配置账号则立即启动
    .\install.ps1 -Uninstall   卸载：删除启动项并结束正在运行的巡检进程（账号凭据保留）

  说明：
    - 写入的是「当前用户」的启动项，不需要管理员权限；
    - 每次登录 Windows 后自动运行，之后每 5 分钟静默巡检一次，
      已在线就什么都不做，掉线才重新认证；
    - 日志固定在 %LOCALAPPDATA%\TustAutoLogin\auto-login.log。
#>
param([switch]$Uninstall)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPy  = Join-Path $scriptDir 'auto_login.py'
$lnkPath   = Join-Path ([Environment]::GetFolderPath('Startup')) 'TUST-AutoLogin.lnk'
$appDir    = Join-Path $env:LOCALAPPDATA 'TustAutoLogin'
$credPath  = Join-Path $appDir 'cred.dat'
$logPath   = Join-Path $appDir 'auto-login.log'

function Get-WatcherProcess {
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like '*auto_login.py*' }
}

if ($Uninstall) {
    if (Test-Path -LiteralPath $lnkPath) {
        Remove-Item -LiteralPath $lnkPath -Force
        "已删除启动项：$lnkPath"
    } else {
        "启动项不存在，无需删除。"
    }
    foreach ($p in Get-WatcherProcess) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        "已结束巡检进程 PID $($p.ProcessId)"
    }
    "账号凭据仍保留在：$credPath"
    "如需彻底清除，请手动删除整个目录：$appDir"
    return
}

if (-not (Test-Path -LiteralPath $scriptPy)) { throw "找不到 auto_login.py：$scriptPy" }

$pyExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $pyExe) { throw '未在 PATH 中找到 python.exe，请先安装 Python 3.8+（安装时勾选 Add python.exe to PATH）' }
$pywExe = Join-Path (Split-Path $pyExe) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pywExe)) { throw "找不到 pythonw.exe：$pywExe" }

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($lnkPath)
$shortcut.TargetPath       = $pywExe
$shortcut.Arguments        = '"' + $scriptPy + '" --watch --quiet'
$shortcut.WorkingDirectory = $scriptDir
$shortcut.WindowStyle      = 7
$shortcut.Description      = 'TUST 校园网自动登录（后台巡检）'
$shortcut.Save()

"已创建启动项：$lnkPath"
"  命令：`"$pywExe`" `"$scriptPy`" --watch --quiet"

if (-not (Test-Path -LiteralPath $credPath)) {
    ""
    "账号尚未配置，请先执行下面两条命令："
    "  & `"$pyExe`" `"$scriptPy`" --setup"
    "  .\install.ps1"
    return
}

# 已在跑就先停掉，避免出现两个实例
foreach ($p in Get-WatcherProcess) {
    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
}

Start-Process -FilePath $pywExe -ArgumentList ('"' + $scriptPy + '" --watch --quiet')
""
"已在后台启动巡检。"
"查看日志： Get-Content -Tail 20 -Wait `"$logPath`""
