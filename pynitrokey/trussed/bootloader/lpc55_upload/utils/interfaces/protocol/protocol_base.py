#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Protocol base."""
from abc import ABC, abstractmethod
from types import ModuleType, TracebackType
from typing import Dict, List, Optional, Type, Union

from typing_extensions import Self

from ....exceptions import SPSDKError
from ....utils.interfaces.commands import CmdPacketBase, CmdResponseBase
from ....utils.interfaces.device.base import DeviceBase
from ....utils.plugins import PluginsManager, PluginType


class ProtocolBase(ABC):
    """Protocol base class."""

    device: DeviceBase
    identifier: str

    def __init__(self, device: DeviceBase) -> None:
        """Initialize the MbootSerialProtocol object.

        :param device: The device instance
        """
        self.device = device

    def __str__(self) -> str:
        return f"identifier='{self.identifier}', device={self.device}"

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

    @abstractmethod
    def open(self) -> None:
        """Open the interface."""

    @abstractmethod
    def close(self) -> None:
        """Close the interface."""

    @property
    @abstractmethod
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""

    @classmethod
    @abstractmethod
    def scan_from_args(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> List[Self]:
        """Scan method."""

    @abstractmethod
    def write_command(self, packet: CmdPacketBase) -> None:
        """Write command to the device.

        :param packet: Command packet to be sent
        """

    @abstractmethod
    def write_data(self, data: bytes) -> None:
        """Write data to the device.

        :param data: Data to be send
        """

    @abstractmethod
    def read(self, length: Optional[int] = None) -> Union[CmdResponseBase, bytes]:
        """Read data from device.

        :return: read data
        """

    @classmethod
    def _get_interfaces(cls) -> List[Type[Self]]:
        """Get list of all available interfaces."""
        cls._load_plugins()
        return [
            sub_class
            for sub_class in cls._get_subclasses(cls)
            if getattr(sub_class, "identifier", None)
        ]

    @classmethod
    def get_interface(cls, identifier: str) -> Type[Self]:
        """Get list of all available interfaces."""
        interface = next(
            (
                iface
                for iface in cls._get_interfaces()
                if iface.identifier == identifier
            ),
            None,
        )
        if not interface:
            raise SPSDKError(f"Interface with identifier {identifier} does not exist.")
        return interface

    @staticmethod
    def _load_plugins() -> Dict[str, ModuleType]:
        """Load all installed interface plugins."""
        plugins_manager = PluginsManager()
        plugins_manager.load_from_entrypoints(PluginType.DEVICE_INTERFACE.label)
        return plugins_manager.plugins

    @classmethod
    def _get_subclasses(
        cls,
        base_class: Type,
    ) -> List[Type[Self]]:
        """Recursively find all subclasses."""
        subclasses = []
        for subclass in base_class.__subclasses__():
            subclasses.append(subclass)
            subclasses.extend(cls._get_subclasses(subclass))
        return subclasses
