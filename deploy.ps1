# deploy.ps1 — 构建并部署 parsec-zh(开发机用)
#
# 重要:Parsec 客户端启用了 BlockRemoteImageLoads 且把默认 DLL 搜索路径收窄到
# System32,实测只有 C:\Windows\ 下的 DLL 能被它加载,因此运行期 DLL 必须放在
# C:\Windows\parsec-zh\ 下(源码仍然留在本工作目录)。
#
# 用法:
#   pwsh -File deploy.ps1            # 构建 + 部署 + 启动监听(会杀掉并让 Parsec 重启以替换 DLL)
#   pwsh -File deploy.ps1 -Restart   # 同上,并显式重新拉起客户端
#
# 分发安装请改用 install.ps1(会注册开机自启);本脚本仅用于开发机迭代。
param([switch]$Restart)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# 需要管理员:写入 C:\Windows、以 SeDebugPrivilege 注入由 SYSTEM 服务启动的进程。
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "需要管理员权限运行(pwsh 以管理员身份打开)。" -ForegroundColor Red
    exit 1
}

$STAGE = "C:\Windows\parsec-zh"

# 1) 构建
& pwsh -NoProfile -File (Join-Path $root 'build.ps1')

# 2) 部署到 C:\Windows(必须;D:/C:/ProgramData 都会被客户端拒绝加载)
New-Item -ItemType Directory -Force -Path $STAGE | Out-Null
Write-Host "停止 parsecd 以便替换运行期 DLL ..."
Get-Process parsecd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
Copy-Item (Join-Path $root 'build\parsec-zh.dll') (Join-Path $STAGE 'parsec-zh.dll') -Force
Copy-Item (Join-Path $root 'build\parsec-zh-launcher.exe') (Join-Path $STAGE 'parsec-zh-launcher.exe') -Force
Write-Host "deployed -> $STAGE"

# 3) 启动监听(常驻,负责把 DLL 注入 Parsec 进程)
Get-Process parsec-zh-launcher -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 300
Start-Process -FilePath (Join-Path $STAGE 'parsec-zh-launcher.exe') -WindowStyle Hidden
Write-Host "watcher started (injects every parsecd.exe process; self-heal enabled)"

if ($Restart) {
    Get-ChildItem "$env:APPDATA\Parsec" -Filter 'cc*.txt' -ErrorAction SilentlyContinue | Remove-Item -Force
    Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"
    Write-Host "Parsec restarted"
}

Write-Host ""
Write-Host "日志: $STAGE\parsec-zh.log   (文本替换是否生效可看其中的 TR[...] 行;"
Write-Host "       高噪声诊断(逐帧采样/MISS)默认关闭,需要时设环境变量 PARSEC_ZH_VERBOSE=1)"
