<#
  TUST 校园网自动登录 —— 安装 / 卸载脚本
  Copyright (C) 2026 whitexxc
  SPDX-License-Identifier: GPL-3.0-or-later

  用法（在本目录打开 PowerShell）：
    .\install.ps1              安装：写入当前用户启动项，已配置账号则立即后台启动并自检
    .\install.ps1 -Uninstall   卸载：删除启动项、结束巡检进程（账号凭据保留）
    .\install.ps1 -Uninstall -Purge
                               卸载并清除账号凭据与日志

  说明：
    - 写的是「当前用户」的启动项，不需要管理员权限；
    - 每次登录 Windows 自动运行，稳定在线时每 60 分钟、掉线时每 10 分钟巡检；
    - 日志：%LOCALAPPDATA%\TustAutoLogin\auto-login.log
    - 注意：升级或重装 Python 后，需要重新运行本脚本（快捷方式里记录了 pythonw.exe 的路径）。
#>
param([switch]$Uninstall, [switch]$Purge)

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

function Stop-Watcher {
    foreach ($p in Get-WatcherProcess) {
        try {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
            # 必须等进程真正退出，否则它持有的单实例互斥体还在，新实例会直接退出
            Wait-Process -Id $p.ProcessId -Timeout 5 -ErrorAction SilentlyContinue
            "已结束巡检进程 PID $($p.ProcessId)"
        } catch {
            "结束进程 PID $($p.ProcessId) 失败：$($_.Exception.Message)"
        }
    }
}

if ($Uninstall) {
    if (Test-Path -LiteralPath $lnkPath) {
        Remove-Item -LiteralPath $lnkPath -Force
        "已删除启动项：$lnkPath"
    } else {
        "启动项不存在，无需删除。"
    }
    Stop-Watcher
    if ($Purge) {
        if (Test-Path -LiteralPath $appDir) {
            Remove-Item -LiteralPath $appDir -Recurse -Force
            "已清除账号凭据与日志：$appDir"
        } else {
            "没有需要清除的数据目录。"
        }
    } else {
        "账号凭据仍保留在：$credPath"
        "如需彻底清除，重新执行：.\install.ps1 -Uninstall -Purge"
    }
    return
}

if (-not (Test-Path -LiteralPath $scriptPy)) { throw "找不到 auto_login.py：$scriptPy" }

$pyExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $pyExe) { throw '未在 PATH 中找到 python.exe，请先安装 Python 3.8+（安装时勾选 Add python.exe to PATH）' }
$pywExe = Join-Path (Split-Path $pyExe) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pywExe)) { throw "找不到 pythonw.exe：$pywExe" }

if ($pyExe -like '*\WindowsApps\*') {
    Write-Warning '检测到 Microsoft Store 版 Python：写入的数据目录可能被重定向，建议改用 python.org 安装包。'
}

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

Stop-Watcher
Start-Process -FilePath $pywExe -ArgumentList ('"' + $scriptPy + '" --watch --quiet')

# 启动后自检：pythonw 没有控制台，进程起不来时不会有任何提示
Start-Sleep -Seconds 3
if (-not (Get-WatcherProcess)) {
    Write-Warning "巡检进程没有存活，请查看日志：$logPath"
    return
}

""
"已在后台启动，稳定在线时每 60 分钟、掉线时每 10 分钟巡检。"
"查看日志： Get-Content -Tail 20 -Wait `"$logPath`""
"环境自检： & `"$pyExe`" `"$scriptPy`" --diagnose"
