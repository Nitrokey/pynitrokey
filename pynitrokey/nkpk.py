# -*- coding: utf-8 -*-
#
# Copyright 2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional

from fido2.hid import CtapHidDevice

from pynitrokey.trussed import VID_NITROKEY
from pynitrokey.trussed.base import NitrokeyTrussedBase
from pynitrokey.trussed.bootloader.nrf52 import NitrokeyTrussedBootloaderNrf52
from pynitrokey.trussed.device import NitrokeyTrussedDevice
from pynitrokey.trussed.utils import Fido2Certs, Version

PID_NITROKEY_PASSKEY_DEVICE = 0x42F3
PID_NITROKEY_PASSKEY_BOOTLOADER = 0x42F4

FIDO2_CERTS = [
    Fido2Certs(
        start=Version(0, 1, 0),
        hashes=[
            "c7512dfcd15ffc5a7b4000e4898e5956ee858027794c5086cc137a02cd15d123",
        ],
    ),
]


class NitrokeyPasskeyDevice(NitrokeyTrussedDevice):
    def __init__(self, device: CtapHidDevice) -> None:
        super().__init__(device, FIDO2_CERTS)

    @property
    def pid(self) -> int:
        return PID_NITROKEY_PASSKEY_DEVICE

    @property
    def name(self) -> str:
        return "Nitrokey Passkey"

    @classmethod
    def from_device(cls, device: CtapHidDevice) -> "NitrokeyPasskeyDevice":
        return cls(device)


class NitrokeyPasskeyBootloader(NitrokeyTrussedBootloaderNrf52):
    @property
    def name(self) -> str:
        return "Nitrokey Passkey Bootloader"

    @property
    def pid(self) -> int:
        return PID_NITROKEY_PASSKEY_BOOTLOADER

    @classmethod
    def list(cls) -> List["NitrokeyPasskeyBootloader"]:
        return cls.list_vid_pid(VID_NITROKEY, PID_NITROKEY_PASSKEY_BOOTLOADER)

    @classmethod
    def open(cls, path: str) -> Optional["NitrokeyPasskeyBootloader"]:
        return cls.open_vid_pid(VID_NITROKEY, PID_NITROKEY_PASSKEY_BOOTLOADER, path)


def list() -> List[NitrokeyTrussedBase]:
    devices: List[NitrokeyTrussedBase] = []
    devices.extend(NitrokeyPasskeyBootloader.list())
    devices.extend(NitrokeyPasskeyDevice.list())
    return devices


def open(path: str) -> Optional[NitrokeyTrussedBase]:
    device = NitrokeyPasskeyDevice.open(path)
    bootloader_device = NitrokeyPasskeyBootloader.open(path)
    if device and bootloader_device:
        raise Exception(f"Found multiple devices at path {path}")
    if device:
        return device
    if bootloader_device:
        return bootloader_device
    return None
