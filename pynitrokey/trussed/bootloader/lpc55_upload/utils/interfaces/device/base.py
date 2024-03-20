#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Low level device base class."""
import logging
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Optional, Type

from typing_extensions import Self

logger = logging.getLogger(__name__)


class DeviceBase(ABC):
    """Device base class."""

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        self.close()

    @property
    @abstractmethod
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""

    @abstractmethod
    def open(self) -> None:
        """Open the interface."""

    @abstractmethod
    def close(self) -> None:
        """Close the interface."""

    @abstractmethod
    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data from the device.

        :param length: Length of data to be read
        :param timeout: Read timeout to be applied
        """

    @abstractmethod
    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write data to the device.

        :param data: Data to be written
        :param timeout: Read timeout to be applied
        """

    @property
    @abstractmethod
    def timeout(self) -> int:
        """Timeout property."""

    @timeout.setter
    @abstractmethod
    def timeout(self, value: int) -> None:
        """Timeout property setter."""

    @abstractmethod
    def __str__(self) -> str:
        """Return string containing information about the interface."""
