# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['nitropy.py'],
             pathex=['C:\\build\\cache\\Nitrokey\\pynitrokey.git'],
             binaries=[],
             datas=[("pynitrokey\\VERSION", "pynitrokey"), 
                    ("C:\\python3.7.7\\lib\\site-packages\\fido2\\public_suffix_list.dat", "fido2"),
										("C:\\python3.7.7\\lib\\site-packages\\libusb\\_platform\\_windows\\x86\\libusb-1.0.dll", ".")
						 ],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='nitropy-0.4.1',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True )
