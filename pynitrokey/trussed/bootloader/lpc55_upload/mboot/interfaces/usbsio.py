#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""USBSIO Mboot interface implementation."""
from typing import List, Optional

from typing_extensions import Self

from spsdk.mboot.protocol.serial_protocol import MbootSerialProtocol
from spsdk.utils.interfaces.device.usbsio_device import ScanArgs, UsbSioI2CDevice, UsbSioSPIDevice


class MbootUsbSioI2CInterface(MbootSerialProtocol):
    """USBSIO I2C interface."""

    device: UsbSioI2CDevice
    identifier = "usbsio_i2c"

    def __init__(self, device: UsbSioI2CDevice):
        """Initialize the UsbSioI2CDevice object.

        :param device: The device instance
        """
        super().__init__(device=device)

    @classmethod
    def scan_from_args(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> List[Self]:
        """Scan connected USBSIO devices.

        :param params: Params as a configuration string
        :param extra_params: Extra params configuration string
        :param timeout: Timeout for the scan
        :return: list of matching RawHid devices
        """
        scan_args = ScanArgs.parse(params=params)
        interfaces = cls.scan(config=scan_args.config, timeout=timeout)
        return interfaces

    @classmethod
    def scan(cls, config: Optional[str] = None, timeout: int = 5000) -> List[Self]:
        """Scan connected USB-SIO bridge devices.

        :param config: Configuration string identifying spi or i2c SIO interface
                        and could filter out USB devices
        :param timeout: Read timeout in milliseconds, defaults to 5000
        :return: List of interfaces
        """
        devices = UsbSioI2CDevice.scan(config, timeout)
        spi_devices = [x for x in devices if isinstance(x, UsbSioI2CDevice)]
        return [cls(device) for device in spi_devices]


class MbootUsbSioSPIInterface(MbootSerialProtocol):
    """USBSIO I2C interface."""

    # START_NOT_READY may be 0x00 or 0xFF depending on the implementation
    FRAME_START_NOT_READY_LIST = [0x00, 0xFF]
    device: UsbSioSPIDevice
    identifier = "usbsio_spi"

    def __init__(self, device: UsbSioSPIDevice) -> None:
        """Initialize the UsbSioSPIDevice object.

        :param device: The device instance
        """
        super().__init__(device)

    @classmethod
    def scan_from_args(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> List[Self]:
        """Scan connected USBSIO devices.

        :param params: Params as a configuration string
        :param extra_params: Extra params configuration string
        :param timeout: Timeout for the scan
        :return: list of matching RawHid devices
        """
        scan_args = ScanArgs.parse(params=params)
        interfaces = cls.scan(config=scan_args.config, timeout=timeout)
        return interfaces

    @classmethod
    def scan(cls, config: Optional[str] = None, timeout: int = 5000) -> List[Self]:
        """Scan connected USB-SIO bridge devices.

        :param config: Configuration string identifying spi or i2c SIO interface
                        and could filter out USB devices
        :param timeout: Read timeout in milliseconds, defaults to 5000
        :return: List of interfaces
        """
        devices = UsbSioSPIDevice.scan(config, timeout)
        spi_devices = [x for x in devices if isinstance(x, UsbSioSPIDevice)]
        return [cls(device) for device in spi_devices]
