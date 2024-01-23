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


class Nitrokey3Device(NitrokeyTrussedDevice):
    """A Nitrokey 3 device running the firmware."""

    def __init__(self, device: CtapHidDevice) -> None:
        super().__init__(device)

    @property
    def pid(self) -> int:
        from . import PID_NITROKEY3_DEVICE

        return PID_NITROKEY3_DEVICE

    @property
    def name(self) -> str:
        return "Nitrokey 3"
