# -*- mode: python ; coding: utf-8 -*-
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import argparse
import importlib.metadata

from PyInstaller.utils.hooks import copy_metadata


def find_file(package: str, file: str) -> str:
    all_files = importlib.metadata.files(package)
    matching_files = [f for f in all_files if str(f) == file]
    if not matching_files:
        raise Exception(f"No '{file}' file found in package {package}")
    if len(matching_files) > 1:
        raise Exception(f"Multiple '{file}' files found in package {package}: {matching_files}")
    return str(matching_files[0].locate())


parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=["onedir", "onefile"], required=True)
parser.add_argument("--platform", choices=["linux", "windows"], required=True)
args = parser.parse_args()

datas = [
    (find_file('fido2', 'fido2/public_suffix_list.dat'), 'fido2'),
    ('../pynitrokey/VERSION', 'pynitrokey'),
    ('../LICENSES', '.'),
]
datas += copy_metadata('pynitrokey')
datas += copy_metadata('ecdsa')
datas += copy_metadata('fido2')
datas += copy_metadata('pyusb')

block_cipher = None

binaries = []
if args.platform == "windows":
    binaries = [
        (find_file("libusb1", "usb1/libusb-1.0.dll"), "."),
    ]

a = Analysis(
    ['nitropy.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe_args = [pyz, a.scripts]
exe_kwargs = {
    "name": 'nitropy',
    "debug": False,
    "bootloader_ignore_signals": False,
    "strip": False,
    "upx": True,
    "console": True,
    "disable_windowed_traceback": False,
    "argv_emulation": False,
    "target_arch": None,
    "codesign_identity": None,
    "entitlements_file": None,
}

if args.mode == "onefile":
    exe_args += [a.binaries, a.zipfiles, a.datas]
    exe_kwargs["upx_exclude"] = []
    exe_kwargs["runtime_tmpdir"] = None
if args.mode == "onedir":
    exe_kwargs["exclude_binaries"] = True
if args.platform == "windows":
    exe_kwargs["icon"] = None
    exe_kwargs["version"] = "windows/pyinstaller/file_version_info.txt"
    exe_kwargs["uac_admin"] = False

exe_args.append([])

exe = EXE(*exe_args, **exe_kwargs)

if args.mode == "onedir":
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=True,
        upx_exclude=[],
        name='nitropy',
    )
