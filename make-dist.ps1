# make-dist.ps1 — 生成"一键安装"分发包(dist\parsec-zh-<date>\ 与 .zip)
# 分发包内容:parsec-zh.dll、parsec-zh-launcher.exe、install.ps1、uninstall.ps1、
#             install.cmd、uninstall.cmd、README.txt、LICENSE、THIRD_PARTY_NOTICES.txt
#
# 注意:分发包内的 .ps1/.txt 一律写成 UTF-8 with BOM,因为 install.cmd 调用的是
# Windows PowerShell 5.1 —— 无 BOM 的中文脚本在 5.1 下会按 ANSI 解码而乱码。
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Test-Path 'build\parsec-zh.dll') -or -not (Test-Path 'build\parsec-zh-launcher.exe')) {
    Write-Host "未找到构建产物,先执行 build.ps1 ..."
    & pwsh -NoProfile -File (Join-Path $root 'build.ps1')
}

$stamp = Get-Date -Format 'yyyyMMdd'
$dist  = Join-Path $root 'dist'
$stage = Join-Path $dist "parsec-zh-$stamp"
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item 'build\parsec-zh.dll'          $stage -Force
Copy-Item 'build\parsec-zh-launcher.exe' $stage -Force
Copy-Item 'LICENSE'                      $stage -Force
Copy-Item 'THIRD_PARTY_NOTICES.txt'      $stage -Force

$utf8bom   = New-Object System.Text.UTF8Encoding($true)
$utf8nobom = New-Object System.Text.UTF8Encoding($false)
function Copy-Utf8Bom([string]$src, [string]$dst) {
    $text = [IO.File]::ReadAllText((Join-Path $root $src), $utf8nobom)
    [IO.File]::WriteAllText((Join-Path $stage $dst), $text, $utf8bom)
}
Copy-Utf8Bom 'install.ps1'   'install.ps1'
Copy-Utf8Bom 'uninstall.ps1' 'uninstall.ps1'

function Write-CmdText([string]$name, [string]$body) {
    $crlf  = ($body -replace "`r`n", "`n") -replace "`n", "`r`n"
    $ascii = New-Object System.Text.ASCIIEncoding
    [IO.File]::WriteAllText((Join-Path $stage $name), $crlf, $ascii)
}

$installCmd = @'
@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -Command "exit([int](-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))"
if errorlevel 1 (
  echo Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath ""%~f0"""
  exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set RC=%errorlevel%
echo.
pause
exit /b %RC%
'@
$uninstallCmd = @'
@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -Command "exit([int](-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))"
if errorlevel 1 (
  echo Requesting administrator privileges...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath ""%~f0"""
  exit /b
)
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
set RC=%errorlevel%
echo.
pause
exit /b %RC%
'@
Write-CmdText 'install.cmd'   $installCmd
Write-CmdText 'uninstall.cmd' $uninstallCmd

$readme = @'
parsec-zh —— Parsec 客户端中文汉化（一键安装包）
====================================================

安装
----
1. 解压本压缩包到一个普通目录（例如“下载”）。
2. 若压缩包是下载来的：先右键压缩包 → 属性 → 勾选“解除锁定(Unblock)” → 确定，
   再解压（否则 Windows 可能拦截包内的脚本与程序）。
3. 双击 install.cmd，在 UAC 弹窗选择“是”（安装会先结束并重启 Parsec 客户端，会短暂中断正在进行的远程会话）。
4. 等待完成。若客户端当前是英文，监听器会在数秒内自动重启一次，界面即变为中文。
   请用“将要使用 Parsec 的那个 Windows 用户”并以管理员身份运行。

卸载
----
双击 uninstall.cmd，在 UAC 弹窗选择“是”。卸载后客户端恢复为英文原版界面。

被安全软件拦截怎么办
--------------------
本工具未做代码签名，且行为特征（注入进程内存）容易被安全软件拦截。
常见表现：安装时提示“对路径 C:\Windows\parsec-zh\parsec-zh.dll 的访问被拒绝”、
文件被锁住无法覆盖、或程序被隔离。请把下面这个目录加入安全软件的“信任区/白名单/排除项”，
或安装时临时关闭其实时防护，然后重新运行 install.cmd：
    C:\Windows\parsec-zh
 - Windows 安全中心：病毒和威胁防护 → 管理设置 → 排除项 → 添加“文件夹”。
 - 火绒安全：设置 → 信任区 → 添加目录/文件。
 - 腾讯电脑管家：设置 → 病毒查杀 → 信任区（或“权限雷达”放行）。
 - 360 / 其他：在其“信任区/白名单”中添加同名目录。
安装完成后，即使后续被拦截，已复制的文件与自启项仍然有效。

说明
----
- 需要 Windows 10/11 64 位，且已安装官方 Parsec 客户端。
- 不改动 Parsec 的任何文件；DLL 与监听器自身不写注册表、不装服务。
  安装脚本会注册一个当前用户的登录计划任务 ParsecZH（登录启动、每 2 分钟健康检查），卸载会删除。
- 监听器没有窗口，不会出现在任务栏；请勿用任务管理器结束“parsec-zh-launcher.exe”（若结束，计划任务会在约 2 分钟内自动拉起）。
- 不联网、不收集数据；日志默认不含用户名/主机名/PeerID，且限制 4MB。
- 日志位置：C:\Windows\parsec-zh\parsec-zh.log（及 parsec-zh-launcher.log）。
- 与 Parsec / Unity 无任何隶属关系；请自行评估并承担使用风险。

校验（可选）
------------
可在本包的发布页（GitHub Release）核对 zip 的 SHA-256，再用以下命令计算本地值：
  certutil -hashfile parsec-zh-<版本>.zip SHA256

详见本包发布页（Release）的说明。
'@
[IO.File]::WriteAllText((Join-Path $stage 'README.txt'), $readme, $utf8bom)

$zip = Join-Path $dist "parsec-zh-$stamp.zip"
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force

$h = (Get-FileHash $zip -Algorithm SHA256).Hash
Set-Content -Path "$zip.sha256" -Value ("$h  parsec-zh-$stamp.zip") -Encoding ascii

Write-Host ""
Write-Host "dist: $stage"
Write-Host "zip : $zip"
Write-Host "sha256:"
Write-Host "  parsec-zh.dll          " (Get-FileHash (Join-Path $stage 'parsec-zh.dll') -Algorithm SHA256).Hash
Write-Host "  parsec-zh-launcher.exe " (Get-FileHash (Join-Path $stage 'parsec-zh-launcher.exe') -Algorithm SHA256).Hash
Write-Host "  $stamp.zip             $h"
Get-ChildItem $stage | Format-Table Name,Length -AutoSize
