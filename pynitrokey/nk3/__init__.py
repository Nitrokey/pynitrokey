# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional

from .base import Nitrokey3Base
from .bootloader import Nitrokey3Bootloader
from .device import Nitrokey3Device

VID_NITROKEY = 0x20A0
PID_NITROKEY3_DEVICE = 0x42B2
PID_NITROKEY3_BOOTLOADER = 0x42DD


def list() -> List[Nitrokey3Base]:
    devices: List[Nitrokey3Base] = []
    devices.extend(Nitrokey3Bootloader.list())
    devices.extend(Nitrokey3Device.list())
    return devices


def open(path: str) -> Optional[Nitrokey3Base]:
    device = Nitrokey3Device.open(path)
    bootloader = Nitrokey3Bootloader.open(path)
    if device and bootloader:
        raise Exception(f"Found multiple devices at path {path}")
    if device:
        return device
    if bootloader:
        return bootloader
    return None
