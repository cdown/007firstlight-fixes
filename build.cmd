@echo off
setlocal

if defined VSCMD_VER goto build

set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
set "vsdevcmd="
for /f "usebackq delims=" %%i in (
    `vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find Common7\Tools\VsDevCmd.bat`
) do set "vsdevcmd=%%i"
if not defined vsdevcmd (
    echo MSVC C++ tools not found. >&2
    exit /b 1
)
call "%vsdevcmd%" -no_logo -arch=x64 -host_arch=x64 || exit /b 1

:build
pushd "%~dp0" || exit /b 1
if not exist dist mkdir dist
cl /nologo /std:c11 /W4 /WX /O2 /MD /LD ^
    /D_CRT_SECURE_NO_WARNINGS fov.c /Fe:dist\dinput8.dll
