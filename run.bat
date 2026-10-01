@echo off
cd /d "%~dp0"
echo Installing VaultLock dependencies...
pip install -r requirements.txt
echo.
echo Launching VaultLock...
python vault_lock.py
pause
