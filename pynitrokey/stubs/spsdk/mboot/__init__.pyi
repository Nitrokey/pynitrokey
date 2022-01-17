# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from enum import Enum
from typing import List, Optional

from .interfaces import Interface
from .properties import PropertyTag

class StatusCode(int):
    @classmethod
    def desc(cls, key: int) -> str: ...

class McuBoot:
    def __init__(self, device: Interface) -> None: ...
    @property
    def status_code(self) -> StatusCode: ...
    def open(self) -> None: ...
    def close(self) -> None: ...
    def receive_sb_file(self, data: bytes) -> bool: ...
    def reset(self, reopen: bool) -> bool: ...
    def get_property(self, prop_tag: PropertyTag) -> Optional[List[int]]: ...
