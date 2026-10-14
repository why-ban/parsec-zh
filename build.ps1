$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Locate a MinGW-w64 gcc without hard-coding anyone's machine:
#   1) $env:PARSEC_ZH_MINGW\gcc.exe   2) gcc on PATH   3) common install dirs
$gcc = $null
if ($env:PARSEC_ZH_MINGW) {
    $c = Join-Path $env:PARSEC_ZH_MINGW 'gcc.exe'
    if (Test-Path $c) { $gcc = $c }
}
if (-not $gcc) { $g = Get-Command gcc -ErrorAction SilentlyContinue; if ($g) { $gcc = $g.Source } }
if (-not $gcc) {
    foreach ($p in @("$env:ProgramFiles\mingw64\bin\gcc.exe",
                     "$env:USERPROFILE\scoop\apps\mingw\current\bin\gcc.exe",
                     "C:\msys64\mingw64\bin\gcc.exe",
                     "C:\mingw64\bin\gcc.exe")) {
        if ($p -and (Test-Path $p)) { $gcc = $p; break }
    }
}
if (-not $gcc) { throw "gcc not found. Set PARSEC_ZH_MINGW to your MinGW bin dir, or add gcc to PATH." }
$env:PATH = "$(Split-Path -Parent $gcc);$env:PATH"
Write-Host "gcc: $gcc"
& $gcc --version | Select-Object -First 1

New-Item -ItemType Directory -Force -Path build | Out-Null

# 1) regenerate translation tables
python tools\gen_translations.py

$INC = @('-I','minhook/include','-I','minhook/src','-I','minhook/src/hde','-I','src')
$CFLAGS = @('-O2','-m64','-Wall','-D_WIN32_WINNT=0x0601','-DPARSEC_ZH_EXPORTS','-D_M_X64','-D_WIN64','-D_M_AMD64')

Write-Host "== assembling render_stub.S =="
& $gcc '-c' '-m64' 'src/render_stub.S' '-o' 'build/render_stub.o'

Write-Host "== compiling MinHook =="
$mh = @('minhook/src/hook.c','minhook/src/buffer.c','minhook/src/trampoline.c','minhook/src/hde/hde64.c')
$mhObj = @()
foreach ($f in $mh) {
  $o = 'build/' + [System.IO.Path]::GetFileNameWithoutExtension($f) + '.o'
  & $gcc @CFLAGS @INC '-c' $f '-o' $o
  $mhObj += $o
}

Write-Host "== compiling parsec_zh.c =="
& $gcc @CFLAGS @INC '-c' 'src/parsec_zh.c' '-o' 'build/parsec_zh.o'

Write-Host "== linking parsec-zh.dll =="
$linkObjs = @('build/parsec_zh.o','build/render_stub.o') + $mhObj
& $gcc '-m64' '-shared' '-o' 'build/parsec-zh.dll' @linkObjs '-static-libgcc' '-lkernel32' '-luser32'

Write-Host "== compiling launcher =="
& $gcc '-O2' '-m64' '-Wall' '-mwindows' '-o' 'build/parsec-zh-launcher.exe' 'src/inject.c' '-static-libgcc' '-lkernel32' '-luser32'

Write-Host "== done =="
Get-ChildItem build | Select-Object Name,Length
