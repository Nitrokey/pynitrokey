# -*- coding: utf-8 -*-
#
# Copyright 2022-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.


class NitrokeyTrussedException(Exception):
    pass


class TimeoutException(NitrokeyTrussedException):
    def __init__(self) -> None:
        super().__init__("The user confirmation request timed out")
