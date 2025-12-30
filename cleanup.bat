@echo off
setlocal EnableDelayedExpansion

:: Cleanup helper for chatApp
:: Usage: cleanup.bat [server] [client]
:: If no flags passed, prompts to clean both.

if ""=="%~1" goto :PROMPT
if /I "%~1"=="/?" goto :HELP
if /I "%~1"=="-h" goto :HELP
if /I "%~1"=="--help" goto :HELP
if /I "%~1"=="help" goto :HELP

set "CLEAN_SERVER=0"
set "CLEAN_CLIENT=0"

:PARSE_ARGS
for %%a in (%*) do (
  if /I "%%~a"=="server" set "CLEAN_SERVER=1"
  if /I "%%~a"=="client" set "CLEAN_CLIENT=1"
  if /I "%%~a"=="--server" set "CLEAN_SERVER=1"
  if /I "%%~a"=="--client" set "CLEAN_CLIENT=1"
  if /I "%%~a"=="/server" set "CLEAN_SERVER=1"
  if /I "%%~a"=="/client" set "CLEAN_CLIENT=1"
)
goto :PROCEED

:PROMPT
echo No flags passed (server client). Do you want to clean both server and client builds?
choice /M "Clean both server and client builds?"
if errorlevel 2 (
  echo Aborting cleanup.
  goto :END
)
set "CLEAN_SERVER=1"
set "CLEAN_CLIENT=1"

:PROCEED
echo.
if "%CLEAN_SERVER%"=="1" (
  if exist "%~dp0bin\server\" (
    echo Cleaning server build in "%~dp0bin\server\" ...
    del /Q "%~dp0bin\server\*" 2>nul
    for /D %%D in ("%~dp0bin\server\*") do rd /S /Q "%%D" 2>nul
  ) else (
    echo No server build folder to clean at "%~dp0bin\server\".
  )
)

if "%CLEAN_CLIENT%"=="1" (
  if exist "%~dp0bin\client\" (
    echo Cleaning client build in "%~dp0bin\client\" ...
    del /Q "%~dp0bin\client\*" 2>nul
    for /D %%D in ("%~dp0bin\client\*") do rd /S /Q "%%D" 2>nul
  ) else (
    echo No client build folder to clean at "%~dp0bin\client\".
  )
)

echo.
echo Cleaning object files in root...
del /Q "%~dp0*.obj" 2>nul
del /Q "%~dp0*.exe" 2>nul

echo.
echo Cleanup complete.
goto :END

:HELP
echo Usage: cleanup.bat [server] [client]
echo.
echo If no flags provided you'll be prompted to clean both server and client builds.
echo Flags:
echo   server    Clean server build (%~dp0bin\server\)
echo   client    Clean client build (%~dp0bin\client\)
echo   --server  Same as server
echo   --client  Same as client
echo   /? -h --help Show this help
echo.
goto :END

:END
endlocal
exit /b 0