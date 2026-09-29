@echo off
setlocal
cd /d "%~dp0"
if not exist node_modules (
  echo Installing dependencies...
  call npm install
  if errorlevel 1 (
    echo.
    echo npm install failed. Check your Internet connection and Node.js installation.
    pause
    exit /b 1
  )
)
if not exist .env copy .env.example .env >nul
node server.js
pause
