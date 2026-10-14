# install.ps1 — 安装 Parsec 客户端汉化(分发用,需管理员)
#
# 作用:
#   1. 把 parsec-zh.dll 与 parsec-zh-launcher.exe 复制到 C:\Windows\parsec-zh\
#      (Parsec 收窄了 DLL 搜索路径,运行期 DLL 只能从 C:\Windows 下加载)
#   2. 注册一个"当前用户"的登录计划任务 ParsecZH(登录启动 + 每 2 分钟健康检查;
#      最高权限、与客户端同一会话)。DLL 与启动器通过 Local\parsec-zh-* 命名事件
#      握手,而 Local\ 只在同一会话可见,因此必须是"会话内"运行;
#      同时会清除历史遗留的 HKCU\...\Run\ParsecZH。
#   3. 结束当前 parsecd 让新 DLL 生效,并启动监听器
#   4. 校验汉化是否生效
#
# 不会修改 Parsec 自身的任何文件;卸载见 uninstall.ps1。
# 请用"将要使用 Parsec 的那个用户"(且已提升为管理员)运行本脚本。
param([switch]$NoStart)
$ErrorActionPreference = 'Stop'

# 运行 native 命令(takeown/icacls)时,避免其 stderr 因 ErrorActionPreference=Stop
# 中断脚本;失败只忽略,不抛出。
function Invoke-NativeQuiet {
    $exe = $args[0]
    $rest = @()
    if ($args.Count -gt 1) { $rest = $args[1..($args.Count - 1)] }
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $exe @rest 2>$null | Out-Null } catch {} finally { $ErrorActionPreference = $old }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "请以管理员身份运行本脚本。" -ForegroundColor Red; exit 1 }

# 计划任务/自启注册给"当前用户",因此请以将要使用 Parsec 的那个用户运行并提权。
try {
    $consoleUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
} catch { $consoleUser = $null }
if ($consoleUser -and ($consoleUser -replace '^.*\\', '') -ne $env:USERNAME) {
    Write-Host "警告:当前用户是 $env:USERNAME,而登录会话用户是 $consoleUser。" -ForegroundColor Yellow
    Write-Host "自启任务会注册到 $env:USERNAME 名下;请改用 $consoleUser 账户(已提权)重新运行,否则 $consoleUser 登录后不会自动汉化。" -ForegroundColor Yellow
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stage = 'C:\Windows\parsec-zh'

function Find-File([string]$name) {
    foreach ($p in @((Join-Path $root $name), (Join-Path $root ('build\' + $name)))) {
        if (Test-Path $p) { return $p }
    }
    throw "找不到 $name,请把它放在本脚本同目录。"
}

# 定位 Parsec 客户端(默认位置优先,否则用正在运行进程的真实路径)
$parsecExe = 'C:\Program Files\Parsec\parsecd.exe'
if (-not (Test-Path $parsecExe)) {
    $pg = Get-Process parsecd -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pg) { try { $parsecExe = $pg.Path } catch {} }
}
if (-not (Test-Path $parsecExe)) {
    $parsecExe = $null
    Write-Host "未检测到 Parsec 客户端(parsecd.exe);稍后请手动打开 Parsec。" -ForegroundColor Yellow
}

$srcDll = Find-File 'parsec-zh.dll'
$srcExe = Find-File 'parsec-zh-launcher.exe'

Write-Host "1) 停止旧任务/监听器与 parsecd"
# 先"停用(不注销)"旧任务,避免它在替换文件时把启动器又拉起来占用 DLL/EXE;
# 不注销是为了:若随后的复制/注册失败,原有自启仍在,不至于把可用安装降级。
try { Stop-ScheduledTask -TaskName 'ParsecZH' -ErrorAction SilentlyContinue } catch {}
try { Unregister-ScheduledTask -TaskName 'ParsecZH-logon' -Confirm:$false -ErrorAction SilentlyContinue } catch {}
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'ParsecZH' -ErrorAction SilentlyContinue
Get-Process parsec-zh-launcher -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process parsecd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

Write-Host "2) 部署运行期文件到 $stage"
New-Item -ItemType Directory -Force -Path $stage | Out-Null
# 显式收紧目录权限。只在"目录"上设置、且不用 /T —— 绝不能对文件用 (OI)(CI)+/T,
# 那会把文件的 DACL 清空(文件不接受 OI/CI),导致文件既不能覆盖也不能执行。
Invoke-NativeQuiet icacls $stage /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"

function Deploy-File([string]$src, [string]$dstName) {
    $dst = Join-Path $stage $dstName
    $tmp = Join-Path $stage ($dstName + '.new')
    try { Copy-Item $src $tmp -Force -ErrorAction Stop; Move-Item -Force $tmp $dst -ErrorAction Stop; return }
    catch {
        # 旧文件可能被杀软锁定或权限异常:接管权限后再原子替换一次
        Invoke-NativeQuiet takeown /F $dst /A
        Invoke-NativeQuiet icacls $dst /reset
        try { Copy-Item $src $tmp -Force -ErrorAction Stop; Move-Item -Force $tmp $dst -ErrorAction Stop; return }
        catch {
            Write-Host "部署 $dstName 失败:$($_.Exception.Message)" -ForegroundColor Red
            Write-Host "这通常是杀毒软件(火绒 / 腾讯电脑管家等)拦截注入类程序所致。请把目录 $stage 加入其白名单/信任区,或临时关闭防护后重试。" -ForegroundColor Red
            exit 1
        }
    }
}
Deploy-File $srcDll 'parsec-zh.dll'
Deploy-File $srcExe 'parsec-zh-launcher.exe'
$exe = Join-Path $stage 'parsec-zh-launcher.exe'

# 目录对普通用户只读,但运行期进程以用户身份运行需要写日志:预建两个日志文件,
# 并分别(icacls 一次只能接受一个目标)只对这两个文件授予 Users 写权限。
$dllLog = Join-Path $stage 'parsec-zh.log'
$lchLog = Join-Path $stage 'parsec-zh-launcher.log'
New-Item -ItemType File -Force -Path $dllLog, $lchLog | Out-Null
Invoke-NativeQuiet icacls $dllLog /grant "*S-1-5-32-545:(M)"
Invoke-NativeQuiet icacls $lchLog /grant "*S-1-5-32-545:(M)"

Write-Host "3) 注册登录自启(计划任务 ParsecZH:当前用户 / 同会话 / 最高权限)"
# - 与客户端同一会话 -> Local\parsec-zh-* 命名事件可见(自愈判定有效);
# - 最高权限 -> 能注入由服务启动的宿主进程,其 CreateProcess 钩子会同步注入 UI 子进程,重开无缝;
# - 每 2 分钟触发器 -> 启动器被杀后自动拉起;启动器无窗口。
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name   # DOMAIN\user(本地/域账户通用)
$action = New-ScheduledTaskAction -Execute $exe
$principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
$trigLogon = New-ScheduledTaskTrigger -AtLogOn -User $me
$trigRepeat = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Days 3650)
$registered = $false
try {
    Register-ScheduledTask -TaskName 'ParsecZH' -Action $action -Trigger @($trigLogon, $trigRepeat) -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
    $registered = $true
} catch {
    # 某些系统可能拒绝超长 RepetitionDuration;退化为"仅登录自启"再试一次
    try {
        Register-ScheduledTask -TaskName 'ParsecZH' -Action $action -Trigger $trigLogon -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        $registered = $true
        Write-Host "提示:已退化为仅登录自启(每 2 分钟健康检查不可用)。" -ForegroundColor Yellow
    } catch {
        Write-Host "注册计划任务失败:$($_.Exception.Message)" -ForegroundColor Red
    }
}
if (-not $registered -or -not (Get-ScheduledTask -TaskName 'ParsecZH' -ErrorAction SilentlyContinue)) {
    Write-Host "无法注册登录自启(可能被组策略禁止)。本次仍会启动监听器(仅本次会话有效);重启后需手动启动:$exe" -ForegroundColor Red
    if (-not $NoStart) { Start-Process -FilePath $exe }
    exit 1
}

# 立即启动一次(无需注销)
Get-Process parsec-zh-launcher -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 300
if (-not $NoStart) {
    try { Start-ScheduledTask -TaskName 'ParsecZH' -ErrorAction Stop } catch { Start-Process -FilePath $exe }
    Start-Sleep -Seconds 2
}

Write-Host "4) 启动 Parsec 并校验"
Start-Service Parsec -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
if ($parsecExe) {
    # 通过 explorer 以当前用户的中等完整性身份启动客户端(不额外提权)
    try { Start-Process -FilePath "$env:WINDIR\explorer.exe" -ArgumentList ('"' + $parsecExe + '"') -ErrorAction Stop | Out-Null } catch {}
    Start-Sleep -Seconds 3
    if (-not (Get-Process parsecd -ErrorAction SilentlyContinue)) { Start-Process -FilePath $parsecExe }
} else {
    Write-Host "请手动打开 Parsec。" -ForegroundColor Yellow
}
Start-Sleep -Seconds 12
$n = (tasklist /m /fi "imagename eq parsecd.exe" 2>&1 | Select-String 'parsec-zh' | Measure-Object).Count
Write-Host "parsec-zh.dll 已注入的 parsecd 进程数: $n (应 >= 1)"
$task = Get-ScheduledTask -TaskName 'ParsecZH' -ErrorAction SilentlyContinue
Write-Host ("登录自启任务 ParsecZH: " + $(if ($task) { $task.State } else { '缺失!' }))
Write-Host "日志: $stage\parsec-zh.log   监听器日志: $stage\parsec-zh-launcher.log"
Write-Host "如首次仍是英文,监听器会在数秒内自动重启一次客户端使其变为中文。"
