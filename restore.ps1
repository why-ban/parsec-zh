# restore.ps1 — 把机器恢复到"原始 Parsec"状态(清除本项目的所有运行期产物)
# 只删除本项目放到系统里的文件/自启项;不会触碰 Parsec 自身的任何文件。
# 需要管理员(写入 C:\Windows、删除计划任务)。
$ErrorActionPreference = 'Continue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "警告:未以管理员运行,部分清理可能失败。" -ForegroundColor Yellow }

Write-Host "1) 停止监听与 Parsec 客户端"
Get-Process parsec-zh-launcher,parsecd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

Write-Host "1b) 移除开机自启(计划任务 + HKCU Run)"
foreach ($tn in @('ParsecZH','ParsecZH-logon')) {
    schtasks /Query /TN $tn *> $null
    if ($LASTEXITCODE -eq 0) { schtasks /Delete /TN $tn /F *> $null; Write-Host "   removed task $tn" }
}
try {
    Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'ParsecZH' -ErrorAction SilentlyContinue
} catch {}

Write-Host "2) 删除部署的运行期 DLL/日志/监听器"
$targets = @(
  "C:\Windows\parsec-zh",
  "C:\ProgramData\parsec-zh",
  "C:\Windows\Temp\zzprobe.dll",
  "C:\Windows\zzprobe.dll",
  "C:\Windows\System32\zzprobe.dll",
  (Join-Path $env:TEMP "parsec-zh-test"),
  "C:\Program Files\Parsec\dwmapi.dll",
  "C:\Program Files\Parsec\parsecd_zh.exe",
  "$env:APPDATA\Parsec\dwmapi.dll"
)
foreach ($p in $targets) {
    if (Test-Path $p) {
        for ($i = 0; $i -lt 5 -and (Test-Path $p); $i++) {
            Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path $p) { Start-Sleep -Milliseconds 500 }
        }
        if (Test-Path $p) { Write-Host "   FAILED to remove $p" -ForegroundColor Yellow }
        else { Write-Host "   removed $p" }
    }
}

Write-Host "3) 清除崩溃计数/锁文件(否则 loader 可能拒绝启动)"
Get-ChildItem "$env:APPDATA\Parsec" -Filter 'cc*.txt' -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item "$env:APPDATA\Parsec\lock","$env:APPDATA\Parsec\lock_client" -Force -ErrorAction SilentlyContinue

Write-Host "3b) 清除可能存在的 IFEO 调试器项(_abandoned 安装脚本遗留)"
foreach ($exe in @('parsecd.exe','pservice.exe')) {
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        $k = Join-Path $root $exe
        if (Test-Path $k) {
            $v = (Get-ItemProperty -Path $k -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($v) { Remove-ItemProperty -Path $k -Name Debugger -Force -ErrorAction SilentlyContinue; Write-Host "   removed IFEO Debugger for $exe" }
        }
    }
}

Write-Host "4) 启动服务并拉起客户端"
Start-Service Parsec -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"

Write-Host "5) 校验"
Start-Sleep -Seconds 12
Get-Process parsecd -ErrorAction SilentlyContinue | Format-Table Id, MainWindowTitle -AutoSize
$n = (tasklist /m /fi "imagename eq parsecd.exe" 2>&1 | Select-String 'parsec-zh' | Measure-Object).Count
Write-Host "parsec-zh.dll 仍被加载的进程数: $n (应为 0)"
