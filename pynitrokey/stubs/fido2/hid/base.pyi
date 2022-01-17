# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import NamedTuple, Optional, Union

class HidDescriptor(NamedTuple):
    path: Union[str, bytes]
    vid: int
    pid: int
    report_size_in: Optional[int]
    report_size_out: Optional[int]
    product_name: bytearray
    serial_number: bytearray
