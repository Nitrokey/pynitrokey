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

PID_NITROKEY_PASSKEY_DEVICE = 0x42F3
PID_NITROKEY_PASSKEY_BOOTLOADER = 0x42F4


class NitrokeyPasskeyDevice(NitrokeyTrussedDevice):
    def __init__(self, device: CtapHidDevice) -> None:
        super().__init__(device)

    @property
    def pid(self) -> int:
        return PID_NITROKEY_PASSKEY_DEVICE

    @property
    def name(self) -> str:
        return "Nitrokey Passkey"


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
