# uninstall.ps1 — 卸载 Parsec 客户端汉化(需管理员)
#
# 反向清理 install.ps1 所做的一切:
#   1. 停止并注销计划任务 ParsecZH / ParsecZH-logon
#   2. 删除 HKCU Run 里的 ParsecZH(历史遗留方式)
#   3. 结束监听器与 parsecd,删除 C:\Windows\parsec-zh
#   4. 仅在确属本工具时才清理历史遗留(如指向本目录的 IFEO Debugger)
# 不会触碰 Parsec 自身的文件。
$ErrorActionPreference = 'Continue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "警告:未以管理员运行,删除 C:\Windows\parsec-zh 与计划任务可能失败。" -ForegroundColor Yellow }

Write-Host "1) 停止并注销自启"
foreach ($tn in @('ParsecZH','ParsecZH-logon')) {
    try { Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue } catch {}
}
try { Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'ParsecZH' -ErrorAction SilentlyContinue } catch {}

Write-Host "2) 停止监听器与 parsecd"
Get-Process parsec-zh-launcher,parsecd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

Write-Host "3) 删除运行期目录"
$stage = 'C:\Windows\parsec-zh'
for ($i = 0; $i -lt 10 -and (Test-Path $stage); $i++) {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $stage) { Start-Sleep -Milliseconds 500 }
}
if (Test-Path $stage) { Write-Host "   删除失败,可能有进程占用: $stage" -ForegroundColor Yellow } else { Write-Host "   已删除 $stage" }

Write-Host "4) 清理可能的遗留物"
# 只清理本工具确实创建的目录;不去删 Program Files\Parsec 或 System32 下的同名文件,
# 以免误伤 Parsec 自带或第三方文件。
$legacyDirs = @('C:\ProgramData\parsec-zh')
foreach ($p in $legacyDirs) {
    if (Test-Path $p) {
        Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $p) { Write-Host "   未能删除 $p" -ForegroundColor Yellow } else { Write-Host "   removed $p" }
    }
}

# IFEO:本工具从不写入 IFEO;仅当 Debugger 明确指向 C:\Windows\parsec-zh 时才清理
foreach ($exe in @('parsecd.exe','pservice.exe')) {
    foreach ($rootk in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        $k = Join-Path $rootk $exe
        if (Test-Path $k) {
            $v = (Get-ItemProperty -Path $k -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($v -and ($v -like '*parsec-zh*')) {
                Remove-ItemProperty -Path $k -Name Debugger -Force -ErrorAction SilentlyContinue
                Write-Host "   removed IFEO Debugger for $exe"
            }
        }
    }
}

Write-Host "5) 重启客户端"
Start-Service Parsec -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$parsecExe = 'C:\Program Files\Parsec\parsecd.exe'
if (-not (Test-Path $parsecExe)) {
    $pg = Get-Process parsecd -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pg) { try { $parsecExe = $pg.Path } catch {} }
}
if (Test-Path $parsecExe) { Start-Process -FilePath $parsecExe -ErrorAction SilentlyContinue }
else { Write-Host "未找到 parsecd.exe,请手动打开 Parsec。" -ForegroundColor Yellow }

Write-Host "6) 校验"
Start-Sleep -Seconds 10
$n = (tasklist /m /fi "imagename eq parsecd.exe" 2>&1 | Select-String 'parsec-zh' | Measure-Object).Count
$taskLeft = (Get-ScheduledTask -TaskName 'ParsecZH','ParsecZH-logon' -ErrorAction SilentlyContinue | Measure-Object).Count
$dirLeft  = Test-Path $stage
Write-Host "parsec-zh.dll 仍被加载的进程数: $n (应为 0)"
Write-Host "计划任务 ParsecZH 残留: $taskLeft (应为 0);目录残留: $dirLeft (应为 False)"
if ($n -eq 0 -and $taskLeft -eq 0 -and -not $dirLeft) {
    Write-Host "卸载完成。" -ForegroundColor Green
    exit 0
}
Write-Host "卸载未完全成功,请查看上面提示(可能被安全软件占用)。" -ForegroundColor Yellow
exit 1
