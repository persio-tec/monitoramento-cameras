@echo off
echo Instalando dependencias...
pip install -r requirements.txt pyinstaller
echo Gerando executavel...
pyinstaller --clean --name MonitoramentoCameras --onefile --windowed --add-data "cameras_ip_wifi_mundial.json;." --add-data "cameras_db.json;." main.py
echo Pronto! Veja em dist\
pause
## 4) Script para Linux/macOS
