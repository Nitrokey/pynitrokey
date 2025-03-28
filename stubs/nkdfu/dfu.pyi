# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from array import array
from typing import Literal

from usb1 import USBDeviceHandle

class DFUBadSate(Exception): ...

class DFU:
    def __init__(self, handle: USBDeviceHandle) -> None: ...
    def download(self, data: array[int]) -> Literal["Finished"]: ...
