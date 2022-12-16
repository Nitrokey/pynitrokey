# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from abc import ABC, abstractmethod
from typing import Optional, TypeVar

from .utils import Uuid

T = TypeVar("T", bound="Nitrokey3Base")


class Nitrokey3Base(ABC):
    """Base class for Nitrokey 3 devices, running the firmware or the bootloader."""

    def __enter__(self: T) -> T:
        return self

    def __exit__(self, exc_type: None, exc_val: None, exc_tb: None) -> None:
        self.close()

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
