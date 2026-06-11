# -*- mode: python ; coding: utf-8 -*-
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import argparse
import importlib.metadata
import semver

from PyInstaller.utils.hooks import copy_metadata
from PyInstaller.utils.win32.versionfile import VSVersionInfo


def find_file(package: str, file: str) -> str:
    all_files = importlib.metadata.files(package)
    matching_files = [f for f in all_files if str(f) == file]
    if not matching_files:
        raise Exception(f"No '{file}' file found in package {package}")
    if len(matching_files) > 1:
        raise Exception(f"Multiple '{file}' files found in package {package}: {matching_files}")
    return str(matching_files[0].locate())

def create_versioninfo() -> VSVersionInfo:
    try:
        version_string = metadata.version('pynitrokey')
    except importlib.metadata.PackageNotFoundError:
        raise Exception("Pynitrokey was not found. Make sure it is installed.")
    try:
        version_parsed = semver.parse(version_string)
    except ValueError:
        raise Exception("Could not parse version from pyproject.toml file.")
    
    major = version_parsed.major
    minor = version_parsed.minor
    patch = version_parse.patch
    build = version_parsed.build if version_parsed.build is not None and version_parsed.build.isdigit() else 0

    flags = 0x2 if version_parsed.prerelease is not None else 0x0

    versioninfo = VSVersionInfo(
        ffi=FixedFileInfo(
            filevers = (0, 0, 0, 0),
            prodvers = (major, minor, patch, build),
            mask = 0x3f,
            flags = flags,
            OS = 0x40004,
            fileType = 0x1,
            subtype = 0x0,
            date = (0,0)
            ),
        kids=[
            StringFileInfo([
                StringTable(
                    u'040904B0',
                    [
                        StringStruct('CompanyName', 'Nitrokey GmbH'),
                        StringStruct('FileDescription', 'Commandline application to manage Nitrokey devices'),
                        StringStruct('FileVersion', '0.0.0.0'),
                        StringStruct('InternalName', 'Nitropy'),
                        StringStruct('LegalCopyright', 'Nitrokey GmbH and contributors'),
                        StringStruct('OriginalFilename', 'nitropy.exe'),
                        StringStruct('ProductName', 'Nitropy'),
                        StringStruct('ProductVersion', f"{major}.{minor}.{patch}.{build}")
                    ]
                )
            ]),
            VarFileInfo([VarStruct(u'Translation', [1033, 4608])])
        ]
    )

    return versioninfo

parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=["onedir", "onefile"], required=True)
parser.add_argument("--platform", choices=["linux", "windows"], required=True)
args = parser.parse_args()

datas = [
    (find_file('fido2', 'fido2/public_suffix_list.dat'), 'fido2'),
    ('../LICENSES', '.'),
]
datas += copy_metadata('pynitrokey')
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
    version = create_versioninfo()

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
