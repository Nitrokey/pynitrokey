# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from collections import namedtuple

class HidDescriptor(
    namedtuple(
        "HidDescriptor",
        [
            "path",
            "vid",
            "pid",
            "report_size_in",
            "report_size_out",
            "product_name",
            "serial_number",
        ],
    )
): ...
