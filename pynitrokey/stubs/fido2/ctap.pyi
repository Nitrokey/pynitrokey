# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from enum import IntEnum, unique
from typing import Union

class CtapDevice: ...

class CtapError(Exception):
    class UNKNOWN_ERR(int): ...

    @unique
    class ERR(IntEnum):
        INVALID_LENGTH: int
    code: Union[UNKNOWN_ERR, ERR]
