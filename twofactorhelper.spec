# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['twofactor.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'objc',
        'AppKit',
        'Foundation',
        'PyObjCTools',
        'PyObjCTools.AppHelper',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='TwoFactorHelper',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    target_arch=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name='TwoFactorHelper',
)

app = BUNDLE(
    coll,
    name='TwoFactorHelper.app',
    icon='AppIcon.icns',
    bundle_identifier='com.sunflower.twofactorhelper',
    info_plist={
        'CFBundleName': 'TwoFactorHelper',
        'CFBundleDisplayName': '2FA Helper',
        'CFBundleVersion': '1.0',
        'CFBundleShortVersionString': '1.0',
        'LSMinimumSystemVersion': '13.0',
        'LSUIElement': True,
        'NSUserNotificationAlertStyle': 'alert',
    },
)
