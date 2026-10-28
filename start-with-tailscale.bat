@echo off
rem Start AdLeak Detector so your own devices on your private Tailscale network
rem can open it too. See PHONE_ACCESS.md for the one-time setup.
call "%~dp0start-windows.bat" --tailscale %*
