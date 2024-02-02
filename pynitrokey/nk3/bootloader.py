# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional, Sequence

from pynitrokey.trussed import VID_NITROKEY
from pynitrokey.trussed.bootloader import NitrokeyTrussedBootloader
from pynitrokey.trussed.bootloader.lpc55 import NitrokeyTrussedBootloaderLpc55
from pynitrokey.trussed.bootloader.nrf52 import (
    NitrokeyTrussedBootloaderNrf52,
    SignatureKey,
)

from . import NK3_DATA


class Nitrokey3Bootloader(NitrokeyTrussedBootloader):
    pass


class Nitrokey3BootloaderLpc55(NitrokeyTrussedBootloaderLpc55, Nitrokey3Bootloader):
    @property
    def name(self) -> str:
        return "Nitrokey 3 Bootloader (LPC55)"

    @property
    def pid(self) -> int:
        from . import PID_NITROKEY3_LPC55_BOOTLOADER

        return PID_NITROKEY3_LPC55_BOOTLOADER

    @classmethod
    def list(cls) -> List["Nitrokey3BootloaderLpc55"]:
        from . import PID_NITROKEY3_LPC55_BOOTLOADER

        return cls.list_vid_pid(VID_NITROKEY, PID_NITROKEY3_LPC55_BOOTLOADER)


class Nitrokey3BootloaderNrf52(NitrokeyTrussedBootloaderNrf52, Nitrokey3Bootloader):
    @property
    def name(self) -> str:
        return "Nitrokey 3 Bootloader (NRF52)"

    @property
    def pid(self) -> int:
        from . import PID_NITROKEY3_NRF52_BOOTLOADER

        return PID_NITROKEY3_NRF52_BOOTLOADER

    @classmethod
    def list(cls) -> List["Nitrokey3BootloaderNrf52"]:
        from . import PID_NITROKEY3_NRF52_BOOTLOADER

        return cls.list_vid_pid(VID_NITROKEY, PID_NITROKEY3_NRF52_BOOTLOADER)

    @classmethod
    def open(cls, path: str) -> Optional["Nitrokey3BootloaderNrf52"]:
        from . import PID_NITROKEY3_NRF52_BOOTLOADER

        return cls.open_vid_pid(VID_NITROKEY, PID_NITROKEY3_NRF52_BOOTLOADER, path)

    @property
    def signature_keys(self) -> Sequence[SignatureKey]:
        return NK3_DATA.nrf52_signature_keys


def list() -> List[Nitrokey3Bootloader]:
    devices: List[Nitrokey3Bootloader] = []
    devices.extend(Nitrokey3BootloaderLpc55.list())
    devices.extend(Nitrokey3BootloaderNrf52.list())
    return devices


def open(path: str) -> Optional[Nitrokey3Bootloader]:
    lpc55 = Nitrokey3BootloaderLpc55.open(path)
    if lpc55:
        return lpc55

    nrf52 = Nitrokey3BootloaderNrf52.open(path)
    if nrf52:
        return nrf52

    return None
