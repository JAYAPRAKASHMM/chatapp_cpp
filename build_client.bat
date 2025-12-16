@echo off
echo ===============================
echo Loading MSVC x64 environment
echo ===============================

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

if errorlevel 1 (
    echo Failed to load MSVC environment
    pause
    exit /b 1
)

echo.
echo ===============================
echo Building CLIENT
echo ===============================

cl /EHsc /MD ^
 /I"%~dp0common" ^
 "%~dp0src\client\client.cpp" ^
 /link Ws2_32.lib ^
 /OUT:"%~dp0bin\client\client.exe"

if errorlevel 1 (
    echo Client build FAILED
    pause
    exit /b 1
)

echo.
echo CLIENT BUILD SUCCESSFUL
pause
