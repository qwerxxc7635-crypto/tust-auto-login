<#
  TUST 校园网 —— 登录前自动认证（开机任务）
  Copyright (C) 2026 whitexxc
  SPDX-License-Identifier: GPL-3.0-or-later

  用途：在「用户登录 Windows 之前」就把校园网认证做掉，这样锁屏/登录界面就有网络，
        远程控制（UU 远程、ToDesk 等）才能连进来让你输密码。

  用法（必须以管理员身份运行 PowerShell）：
    .\install-boot-task.ps1          创建/更新开机任务
    .\install-boot-task.ps1 -Test    立刻触发一次，并显示 boot.log
    .\install-boot-task.ps1 -Uninstall  删除任务

  和普通自启的区别：
    - 普通自启（install.ps1）在你登录后才跑，负责日常巡检；
    - 这个任务以 SYSTEM 身份在开机时跑，只做「一次性认证」，不常驻，
      所以两者不会互相抢登录。
#>
param([switch]$Uninstall, [switch]$Test)

$ErrorActionPreference = 'Stop'
$TaskName = 'TUST-BootLogin'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPy  = Join-Path $scriptDir 'auto_login.py'
$bootDir   = Join-Path $env:ProgramData 'TustAutoLogin'
$bootCred  = Join-Path $bootDir 'boot.dat'
$bootLog   = Join-Path $bootDir 'boot.log'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $ok = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $ok) {
        throw '需要管理员权限：请右键 PowerShell -> 以管理员身份运行，再执行本脚本。'
    }
}

Assert-Admin

if ($Uninstall) {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($t) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        "已删除计划任务：$TaskName"
    } else {
        "计划任务不存在，无需删除。"
    }
    "开机凭据与日志仍保留在：$bootDir"
    "如需彻底清除，删除该目录即可（会同时清掉登录前认证的凭据）。"
    return
}

if ($Test) {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $t) { throw "任务不存在，先运行不带参数的 .\install-boot-task.ps1" }
    "立即触发一次……"
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 5
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    "上次运行时间 : $($info.LastRunTime)"
    "上次结果     : $($info.LastTaskResult)"
    if (Test-Path "$bootLog") {
        ""
        "boot.log 最后 10 行："
        Get-Content -Tail 10 "$bootLog" | ForEach-Object { "  $_" }
    } else {
        "  （还没有 boot.log，说明任务没能把脚本跑起来，检查上面的结果码）"
    }
    return
}

if (-not (Test-Path -LiteralPath $scriptPy)) { throw "找不到 auto_login.py：$scriptPy" }

$pyExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $pyExe) { throw '未在 PATH 中找到 python.exe' }
$pywExe = Join-Path (Split-Path $pyExe) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pywExe)) { throw "找不到 pythonw.exe：$pywExe" }

if (-not (Test-Path -LiteralPath $bootCred)) {
    Write-Warning "还没有开机凭据：$bootCred"
    Write-Warning "先以当前用户运行一次  python auto_login.py --setup  再回来执行本脚本。"
    Write-Warning "任务仍会创建，但在生成凭据前每次都会在 boot.log 里报「开机凭据不存在」。"
}

# 动作：pythonw 无窗口运行一次 --boot
$action = New-ScheduledTaskAction -Execute $pywExe `
    -Argument ('"' + $scriptPy + '" --boot') `
    -WorkingDirectory $scriptDir

# 触发器：开机 + 延迟 60 秒（等 Wi-Fi 关联和 DHCP）+ 每 10 分钟重复（无限期）。
# 用 XML 注册：cmdlet 的 -RepetitionDuration ([TimeSpan]::MaxValue) 会被序列化成
# P99999999DT23H59M59S，任务计划程序判定越界（0x80041318）。
# XML 里不写 <Duration> 就是"无限期"，这是唯一干净的表达方式。
$xmlSafePy  = [Security.SecurityElement]::Escape($pywExe)
$xmlSafeArg = [Security.SecurityElement]::Escape('"' + $scriptPy + '" --boot')
$xmlSafeDir = [Security.SecurityElement]::Escape($scriptDir)

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>TUST campus network: authenticate before user logon so the lock screen has network</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT60S</Delay>
      <Repetition>
        <Interval>PT10M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$xmlSafePy</Command>
      <Arguments>$xmlSafeArg</Arguments>
      <WorkingDirectory>$xmlSafeDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$registerMode = ''
try {
    Register-ScheduledTask -TaskName $TaskName -Xml $taskXml -Force -ErrorAction Stop | Out-Null
    $registerMode = 'XML（每 10 分钟无限期重复）'
} catch {
    Write-Warning "XML 注册失败：$($_.Exception.Message)"
    Write-Warning '改用备用方式：cmdlet + 24 小时重复窗口'
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT60S'
    $rep = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 10) `
        -RepetitionDuration (New-TimeSpan -Days 1)
    $trigger.Repetition = $rep.Repetition
    $action = New-ScheduledTaskAction -Execute $pywExe `
        -Argument ('"' + $scriptPy + '" --boot') -WorkingDirectory $scriptDir
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
        -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
    $registerMode = 'cmdlet（每 10 分钟，持续 24 小时）'
}

"已创建计划任务：$TaskName"
"  身份   : SYSTEM（不需要保存任何账户密码）"
"  触发   : 开机后 60 秒，之后 $registerMode"
"  动作   : `"$pywExe`" `"$scriptPy`" --boot"
"  日志   : $bootLog"
""
"验证："
"  1) .\install-boot-task.ps1 -Test     立即触发一次并看日志"
"  2) 重启电脑，停在登录界面等 1~2 分钟，用手机 UU 连接"
""
"两个容易漏的前提："
"  - 若开着「快速启动」，关机再开机是混合启动，开机触发器可能不触发。"
"    建议先测「重启」；确认没问题后再决定是否关闭快速启动。"
"  - 手机热点等其它 Wi-Fi 若也设为自动连接，开机可能连到热点导致没有校园网。"
"    建议把热点改为「手动连接」。"
