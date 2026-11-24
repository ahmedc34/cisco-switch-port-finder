@echo off
python -m pip install -r requirements.txt pyinstaller
python -m PyInstaller --onefile --noconsole --uac-admin --name switch_bulucu switch_bulucu.py
echo.
echo Bitti. Exe: dist\switch_bulucu.exe
pause
