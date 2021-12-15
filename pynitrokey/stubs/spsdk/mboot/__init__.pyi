# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional

from .interfaces import Interface
from .properties import PropertyTag

class McuBoot:
    def __init__(self, device: Interface) -> None: ...
    def open(self) -> None: ...
    def close(self) -> None: ...
    def reset(self, reopen: bool) -> bool: ...
    def get_property(self, prop_tag: PropertyTag) -> Optional[List[int]]: ...
