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
    ('../LICENSES', '.'),
]
datas += copy_metadata('pynitrokey')
datas += copy_metadata('ecdsa')
datas += copy_metadata('fido2')
datas += copy_metadata('pyusb')

binaries = []
if args.platform == "windows":
    binaries.append((find_file("libusb1", "usb1/libusb-1.0.dll"), "."))

a = Analysis(['nitropy.py'], binaries=binaries, datas=datas, excludes=['tkinter'])
pyz = PYZ(a.pure, a.zipped_data)

exe_args = [pyz, a.scripts]
is_onedir = args.mode == "onedir"
version = None

if args.mode == "onefile":
    exe_args += [a.binaries, a.zipfiles, a.datas]

if args.platform == "windows":
    version = "windows/pyinstaller/file_version_info.txt"

exe = EXE(*exe_args, name="nitropy", upx=True, exclude_binaries=is_onedir, version=version)

if is_onedir:
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        upx=True,
        name='nitropy',
    )
