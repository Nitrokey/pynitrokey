# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import Optional

from ..utils.crypto import CertBlockV2
from .headers import ImageHeaderV2

class BootImageV21:
    cert_block: Optional[CertBlockV2]
    @property
    def header(self) -> ImageHeaderV2: ...
    @classmethod
    def parse(cls, data: bytes, kek: bytes = bytes()) -> "BootImageV21": ...
