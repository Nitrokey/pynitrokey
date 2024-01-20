# -*- coding: utf-8 -*-
#
# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from abc import ABC, abstractmethod
from typing import Optional, TypeVar

from . import VID_NITROKEY
from .utils import Uuid

T = TypeVar("T", bound="NitrokeyTrussedBase")


class NitrokeyTrussedBase(ABC):
    """
    Base class for Nitrokey devices using the Trussed framework and running
    the firmware or the bootloader.
    """

    def __enter__(self: T) -> T:
        return self

    def __exit__(self, exc_type: None, exc_val: None, exc_tb: None) -> None:
        self.close()

    def validate_vid_pid(self, vid: int, pid: int) -> None:
        if (vid, pid) != (self.vid, self.pid):
            raise ValueError(
                f"Not a {self.name} device: expected VID:PID "
                f"{self.vid:x}:{self.pid:x}, got {vid:x}:{pid:x}"
            )

    @property
    def vid(self) -> int:
        return VID_NITROKEY

    @property
    @abstractmethod
    def pid(self) -> int:
        ...

    @property
    @abstractmethod
    def path(self) -> str:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

    @abstractmethod
    def reboot(self) -> bool:
        ...

    @abstractmethod
    def uuid(self) -> Optional[Uuid]:
        ...
