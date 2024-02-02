# -*- coding: utf-8 -*-
#
# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import re
from dataclasses import dataclass
from re import Pattern
from typing import TYPE_CHECKING

from pynitrokey.updates import Repository

if TYPE_CHECKING:
    from .bootloader.nrf52 import SignatureKey

VID_NITROKEY = 0x20A0


@dataclass
class DeviceData:
    name: str
    firmware_repository_name: str
    firmware_pattern_string: str
    nrf52_signature_keys: list["SignatureKey"]

    @property
    def firmware_repository(self) -> Repository:
        return Repository(owner="Nitrokey", name=self.firmware_repository_name)

    @property
    def firmware_pattern(self) -> Pattern[str]:
        return re.compile(self.firmware_pattern_string)
