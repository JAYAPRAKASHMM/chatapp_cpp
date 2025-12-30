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
echo Building SERVER
echo ===============================

cl /EHsc /MD ^
 /I"C:\src" ^
 /I"%~dp0common" ^
 "%~dp0src\server\main.cpp" ^
 "%~dp0src\server\server.cpp" ^
 "%~dp0src\server\server_logger.cpp" ^
 /link ^
 /LIBPATH:"C:\src\hiredis\build\Release" ^
 "C:\src\hiredis\build\Release\hiredis.lib" Ws2_32.lib Mswsock.lib ^
 /OUT:"%~dp0bin\server\server.exe"

if errorlevel 1 (
    echo Server build FAILED
    pause
    exit /b 1
)

echo.
echo Copying hiredis.dll
copy /Y "C:\src\hiredis\build\Release\hiredis.dll" "%~dp0bin\server\"

echo.
echo SERVER BUILD SUCCESSFUL
pause
