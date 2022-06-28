# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional

from . import bootloader
from .base import Nitrokey3Base
from .device import Nitrokey3Device

VID_NITROKEY = 0x20A0
PID_NITROKEY3_DEVICE = 0x42B2
PID_NITROKEY3_LPC55_BOOTLOADER = 0x42DD
PID_NITROKEY3_NRF52_BOOTLOADER = 0x42E8


def list() -> List[Nitrokey3Base]:
    devices: List[Nitrokey3Base] = []
    devices.extend(bootloader.list())
    devices.extend(Nitrokey3Device.list())
    return devices


def open(path: str) -> Optional[Nitrokey3Base]:
    device = Nitrokey3Device.open(path)
    bootloader_device = bootloader.open(path)
    if device and bootloader_device:
        raise Exception(f"Found multiple devices at path {path}")
    if device:
        return device
    if bootloader_device:
        return bootloader_device
    return None
