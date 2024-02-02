# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from fido2.hid import CtapHidDevice

from pynitrokey.trussed.device import NitrokeyTrussedDevice
from pynitrokey.trussed.utils import Fido2Certs, Version

FIDO2_CERTS = [
    Fido2Certs(
        start=Version(0, 1, 0),
        hashes=[
            "ad8fd1d16f59104b9e06ef323cc03f777ed5303cd421a101c9cb00bb3fdf722d",
        ],
    ),
    Fido2Certs(
        start=Version(1, 0, 3),
        hashes=[
            "aa1cb760c2879530e7d7fed3da75345d25774be9cfdbbcbd36fdee767025f34b",  # NK3xN/lpc55
            "4c331d7af869fd1d8217198b917a33d1fa503e9778da7638504a64a438661ae0",  # NK3AM/nrf52
            "f1ed1aba24b16e8e3fabcda72b10cbfa54488d3b778bda552162d60c6dd7b4fa",  # NK3AM/nrf52 test
        ],
    ),
]


class Nitrokey3Device(NitrokeyTrussedDevice):
    """A Nitrokey 3 device running the firmware."""

    def __init__(self, device: CtapHidDevice) -> None:
        super().__init__(device, FIDO2_CERTS)

    @property
    def pid(self) -> int:
        from . import PID_NITROKEY3_DEVICE

        return PID_NITROKEY3_DEVICE

    @property
    def name(self) -> str:
        return "Nitrokey 3"

    @classmethod
    def from_device(cls, device: CtapHidDevice) -> "Nitrokey3Device":
        return cls(device)
