@echo off
setlocal
cd /d "%~dp0"

set "SENTINEL_TOKENROUTER_BASE_URL=https://api.tokenrouter.com/v1"
set "SENTINEL_TOKENROUTER_MODEL=z-ai/glm-5.2-free"

if not "%SENTINEL_TOKENROUTER_API_KEY%"=="" goto :start_demo

echo Sentinel will ask for your TokenRouter key without displaying or saving it.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$secure = Read-Host 'Paste TokenRouter key (hidden)' -AsSecureString; $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure); try { $env:SENTINEL_TOKENROUTER_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer); $env:SENTINEL_TOKENROUTER_BASE_URL = 'https://api.tokenrouter.com/v1'; $env:SENTINEL_TOKENROUTER_MODEL = 'z-ai/glm-5.2-free'; & '.\Start Sentinel Demo.cmd' '--use-ai'; exit $LASTEXITCODE } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }"
exit /b %ERRORLEVEL%

:start_demo
call "%~dp0Start Sentinel Demo.cmd" --use-ai
exit /b %ERRORLEVEL%
