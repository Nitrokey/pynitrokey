#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""UART Mboot interface implementation."""
import logging
from dataclasses import dataclass
from typing import List, Optional

from typing_extensions import Self

from spsdk.mboot.protocol.serial_protocol import MbootSerialProtocol
from spsdk.utils.interfaces.device.serial_device import SerialDevice

logger = logging.getLogger(__name__)


@dataclass
class ScanArgs:
    """Scan arguments dataclass."""

    port: Optional[str]
    baudrate: Optional[int]

    @classmethod
    def parse(cls, params: str) -> Self:
        """Parse given scanning parameters into ScanArgs class.

        :param params: Parameters as a string
        """
        port_parts = params.split(",")
        return cls(
            port=port_parts.pop(0), baudrate=int(port_parts.pop(), 0) if port_parts else None
        )


class MbootUARTInterface(MbootSerialProtocol):
    """UART interface."""

    default_baudrate = 57600
    device: SerialDevice
    identifier = "uart"

    def __init__(self, device: SerialDevice):
        """Initialize the MbootUARTInterface object.

        :param device: The device instance
        """
        assert isinstance(device, SerialDevice)
        super().__init__(device=device)

    @classmethod
    def scan_from_args(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> List[Self]:
        """Scan connected UART devices.

        :param params: Params as a configuration string
        :param extra_params: Extra params configuration string
        :param timeout: Timeout for the scan
        :return: list of matching RawHid devices
        """
        scan_args = ScanArgs.parse(params=params)
        interfaces = cls.scan(
            port=scan_args.port,
            baudrate=scan_args.baudrate or cls.default_baudrate,
            timeout=timeout,
        )
        return interfaces

    @classmethod
    def scan(
        cls,
        port: Optional[str] = None,
        baudrate: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> List[Self]:
        """Scan connected UART devices.

        Returns list of serial ports with devices that respond to PING command.
        If 'port' is specified, only that serial port is checked
        If no devices are found, return an empty list.

        :param port: name of preferred serial port, defaults to None
        :param baudrate: speed of the UART interface, defaults to 56700
        :param timeout: timeout in milliseconds, defaults to 5000
        :return: list of interfaces responding to the PING command
        """
        devices = SerialDevice.scan(
            port=port, baudrate=baudrate or cls.default_baudrate, timeout=timeout
        )
        interfaces = []
        for device in devices:
            try:
                interface = cls(device)
                interface.open()
                interface._ping()
                interface.close()
                interfaces.append(interface)
            except Exception:
                interface.close()
        return interfaces
