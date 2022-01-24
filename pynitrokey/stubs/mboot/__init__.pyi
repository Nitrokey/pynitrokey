# -*- coding: utf-8 -*-
#
# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from enum import Enum
from typing import Optional, Tuple

from .connection import DevConnBase

class PropertyTag(Enum):
    UNIQUE_DEVICE_IDENT: Tuple[int, str, str]

class McuBoot:
    def __init__(self, device: DevConnBase) -> None: ...
    def open(self) -> None: ...
    def close(self) -> None: ...
    def reset(self, reopen: bool = True) -> bool: ...
    def get_property(self, prop_tag: PropertyTag) -> Optional[list]: ...
    def receive_sb_file(self, data: bytes) -> bool: ...
    @property
    def status_code(self) -> Tuple[int, str, str]: ...
