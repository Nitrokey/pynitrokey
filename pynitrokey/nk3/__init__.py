# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List

from .base import Nitrokey3Base

VID_NITROKEY = 0x20A0
PID_NITROKEY3_DEVICE = 0x42B2
PID_NITROKEY3_BOOTLOADER = 0x42DD


def list() -> List[Nitrokey3Base]:
    from .device import Nitrokey3Device

    return [device for device in Nitrokey3Device.list()]
