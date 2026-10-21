#!/usr/bin/env bash
set -e
echo "Instalando dependências..."
pip3 install -r requirements.txt pyinstaller
echo "Gerando executável..."
pyinstaller --clean --name MonitoramentoCameras --onefile --windowed \
  --add-data "cameras_ip_wifi_mundial.json:." \
  --add-data "cameras_db.json:." \
  main.py
echo "Pronto! Veja em dist/"
