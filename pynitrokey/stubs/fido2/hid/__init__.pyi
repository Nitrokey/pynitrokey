# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from enum import IntEnum, unique
from typing import Iterator, List

from ..ctap import CtapDevice
from .base import HidDescriptor

@unique
class CTAPHID(IntEnum):
    PING: int
    MSG: int
    LOCK: int
    INIT: int
    WINK: int
    CBOR: int
    CANCEL: int
    ERROR: int
    KEEPALIVE: int
    VENDOR_FIRST: int

class CtapHidDevice(CtapDevice):
    descriptor: HidDescriptor
    def call(self, command: int, data: bytes = b"") -> bytes: ...
    def wink(self) -> None: ...
    def close(self) -> None: ...
    @classmethod
    def list_devices(cls) -> Iterator["CtapHidDevice"]: ...

def list_devices() -> List[CtapHidDevice]: ...
def open_device(path) -> CtapHidDevice: ...
