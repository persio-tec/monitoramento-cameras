# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('cameras_ip_wifi_mundial.json', '.'),
        ('cameras_db.json', '.'),
        ('README.md', '.'),
    ],
    hiddenimports=[
        'cv2',
        'PIL',
        'PIL._tkinter_finder',
        'qrcode',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='MonitoramentoCameras',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.zipped_data,
    datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='MonitoramentoCameras',
)

app = BUNDLE(
    coll,
    name='MonitoramentoCameras.app',
    icon=None,
    bundle_identifier='com.persio.monitoramentocameras',
)
