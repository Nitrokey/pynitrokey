#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Low level usbsio device."""
import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Union

import libusbsio
from libusbsio.libusbsio import LIBUSBSIO
from typing_extensions import Self

from ....exceptions import SPSDKConnectionError, SPSDKError, SPSDKValueError
from ....utils.exceptions import SPSDKTimeoutError
from ....utils.interfaces.device.base import DeviceBase
from ....utils.misc import value_to_int
from ....utils.usbfilter import USBDeviceFilter

logger = logging.getLogger(__name__)


@dataclass
class ScanArgs:
    """Scan arguments dataclass."""

    config: str

    @classmethod
    def parse(cls, params: str) -> Self:
        """Parse given scanning parameters into ScanArgs class.

        :param params: Parameters as a string
        """
        return cls(config=params)


class UsbSioDevice(DeviceBase):
    """USBSIO device class."""

    def __init__(self, dev: int = 0, config: Optional[str] = None, timeout: int = 5000) -> None:
        """Initialize the Interface object.

        :param dev: device index to be used, default is set to 0
        :param config: configuration string identifying spi or i2c SIO interface
        :param timeout: read timeout in milliseconds, defaults to 5000
        :raises SPSDKError: When LIBUSBSIO device is not opened.
        """
        # device is the LIBUSBSIO.PORT instance (LIBUSBSIO.SPI or LIBUSBSIO.I2C class)
        self.port: Optional[Union[LIBUSBSIO.SPI, LIBUSBSIO.I2C]] = None

        # work with the global LIBUSBSIO instance
        self.dev_ix = dev
        self.sio = self._get_usbsio()
        self._timeout = timeout

        # store USBSIO configuration and version
        self.config = config

    @property
    def timeout(self) -> int:
        """Timeout property."""
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Timeout property setter."""
        self._timeout = value

    @property
    def is_opened(self) -> bool:
        """Indicates whether device is open.

        :return: True if device is open, False othervise.
        """
        return bool(self.port)

    def close(self) -> None:
        """Close the interface."""
        if self.port:
            self.port.Close()
            self.port = None
            self.sio.Close()
            # re-init the libusb to prepare it for next open
            self.sio.GetNumPorts()

    def __str__(self) -> str:
        """Return string containing information about the interface."""
        class_name = self.__class__.__name__
        config = f":'{self.config}'" if self.config else ""
        return f"libusbsio interface ({class_name}){config}"

    @staticmethod
    def get_interface_cfg(config: str, interface: str) -> str:
        """Return part of interface config.

        :param config: Full config of LIBUSBSIO
        :param interface: Name of interface to find.
        :return: Part with interface config.
        """
        i = config.rfind(interface)
        if i < 0:
            return ""
        return config[i:]

    @staticmethod
    def _get_usbsio() -> LIBUSBSIO:
        """Wraps getting USBSIO library to raise SPSDK errors in case of problem.

        :return: LIBUSBSIO object
        :raises SPSDKError: When libusbsio library error or if no bridge device found
        """
        try:
            # get the global singleton instance of LIBUSBSIO library
            libusbsio_logger = logging.getLogger("libusbsio")
            return libusbsio.usbsio(loglevel=libusbsio_logger.getEffectiveLevel())
        except libusbsio.LIBUSBSIO_Exception as e:
            raise SPSDKError(f"Error in libusbsio interface: {e}") from e
        except Exception as e:
            raise SPSDKError(str(e)) from e

    @classmethod
    def scan(
        cls, config: Optional[str] = None, timeout: int = 5000
    ) -> List[Union["UsbSioSPIDevice", "UsbSioI2CDevice"]]:
        """Scan connected USB-SIO bridge devices.

        :param config: Configuration string identifying spi or i2c SIO interface
                        and could filter out USB devices
        :param timeout: Read timeout in milliseconds, defaults to 5000
        :return: List of matching UsbSio devices
        :raises SPSDKError: When libusbsio library error or if no bridge device found
        :raises SPSDKValueError: Invalid configuration detected.
        """
        cfg = config.split(",") if config else []
        re_spi = re.compile(r"^spi(?P<index>\d*)")
        re_i2c = re.compile(r"^i2c(?P<index>\d*)")
        spi = None
        i2c = None
        for cfg_part in cfg:
            match_i2c = re_i2c.match(cfg_part.lower())
            if match_i2c:
                i2c = value_to_int(match_i2c.group("index"), 0)
            match_spi = re_spi.match(cfg_part.lower())
            if match_spi:
                spi = value_to_int(match_spi.group("index"), 0)
        if i2c is not None and spi is not None:
            raise SPSDKValueError(
                f"Cannot be specified spi and i2c together in configuration: {cfg}"
            )
        intf_specified = i2c is not None or spi is not None

        port_indexes = cls.get_usbsio_devices(config)
        sio = cls._get_usbsio()
        devices: List[Union["UsbSioSPIDevice", "UsbSioI2CDevice"]] = []
        for port in port_indexes:
            if not sio.Open(port):
                raise SPSDKError(f"Cannot open libusbsio bridge {port}.")
            i2c_ports = sio.GetNumI2CPorts()
            if i2c_ports:
                if i2c is not None:
                    devices.append(
                        UsbSioI2CDevice(dev=port, port=i2c, config=config, timeout=timeout)
                    )
                elif not intf_specified:
                    devices.extend(
                        [
                            UsbSioI2CDevice(dev=port, port=p, timeout=timeout)
                            for p in range(i2c_ports)
                        ]
                    )
            spi_ports = sio.GetNumSPIPorts()
            if spi_ports:
                if spi is not None:
                    devices.append(
                        UsbSioSPIDevice(dev=port, port=spi, config=config, timeout=timeout)
                    )
                elif not intf_specified:
                    devices.extend(
                        [
                            UsbSioSPIDevice(dev=port, port=p, timeout=timeout)
                            for p in range(spi_ports)
                        ]
                    )
            if sio.Close() < 0:
                raise SPSDKError(f"Cannot close libusbsio bridge {port}.")
            # re-init the libusb to prepare it for next open
            sio.GetNumPorts()
        return devices

    @classmethod
    def get_usbsio_devices(cls, config: Optional[str] = None) -> List[int]:
        """Returns list of ports indexes of USBSIO devices.

        It could be filtered by standard SPSDK USB filters.

        :param config: Could contain USB filter configuration, defaults to None
        :return: List of port indexes of founded USBSIO device
        """

        def _filter_usb(sio: LIBUSBSIO, ports: List[int], flt: str) -> List[int]:
            """Filter the  LIBUSBSIO device.

            :param sio: LIBUSBSIO instance.
            :param ports: Input list of LIBUSBSIO available ports.
            :param flt: Filter string (PATH, PID/VID, SERIAL_NUMBER)
            :raises SPSDKError: When libusbsio library error or if no bridge device found
            :return: List with selected device, empty list otherwise.
            """
            usb_filter = USBDeviceFilter(flt.casefold())
            port_indexes = []
            for port in ports:
                info = sio.GetDeviceInfo(port)
                if not info:
                    raise SPSDKError(f"Cannot retrive information from LIBUSBSIO device {port}.")
                dev_info = {
                    "vendor_id": info.vendor_id,
                    "product_id": info.product_id,
                    "serial_number": info.serial_number,
                    "path": info.path,
                }
                if usb_filter.compare(dev_info):
                    port_indexes.append(port)
                    break
            return port_indexes

        cfg = config.split(",") if config else []
        port_indexes = []

        sio = UsbSioDevice._get_usbsio()
        # it may already be open (?), in that case, just close it - We are scan function!
        if sio.IsOpen():
            sio.Close()

        port_indexes.extend(list(range(sio.GetNumPorts())))

        # filter out the USB devices
        if cfg and cfg[0] == "usb":
            port_indexes = _filter_usb(sio, port_indexes, cfg[1])

        return port_indexes


class UsbSioSPIDevice(UsbSioDevice):
    """USBSIO SPI interface."""

    def __init__(
        self,
        config: Optional[str] = None,
        dev: int = 0,
        port: int = 0,
        ssel_port: int = 0,
        ssel_pin: int = 15,
        speed_khz: int = 1000,
        cpol: int = 1,
        cpha: int = 1,
        timeout: int = 5000,
    ) -> None:
        """Initialize the UsbSioSPI Interface object.

        :param config: configuration string passed from command line
        :param dev: device index to be used, default is set to 0
        :param port: default SPI port to be used, typically 0 as only one port is supported by LPCLink2/MCULink
        :param ssel_port: bridge GPIO port used to drive SPI SSEL signal
        :param ssel_pin: bridge GPIO pin used to drive SPI SSEL signal
        :param speed_khz: SPI clock speed in kHz
        :param cpol: SPI clock polarity mode
        :param cpha: SPI clock phase mode
        :param timeout: read timeout in milliseconds, defaults to 5000
        :raises SPSDKError: When port configuration cannot be parsed
        """
        super().__init__(dev=dev, config=config, timeout=timeout)

        # default configuration taken from parameters (and their default values)
        self.spi_port = port
        self.spi_sselport = ssel_port
        self.spi_sselpin = ssel_pin
        self.spi_speed_khz = speed_khz
        self.spi_cpol = cpol
        self.spi_cpha = cpha

        # values can be also overridden by a configuration string
        if config:
            # config format: spi[,<port>,<pin>,<speed>,<cpol>,<cpha>]
            cfg = self.get_interface_cfg(config, "spi").split(",")
            try:
                self.spi_sselport = int(cfg[1], 0)
                self.spi_sselpin = int(cfg[2], 0)
                self.spi_speed_khz = int(cfg[3], 0)
                self.spi_cpol = int(cfg[4], 0)
                self.spi_cpha = int(cfg[5], 0)
            except IndexError:
                pass
            except Exception as e:
                raise SPSDKError(
                    "Cannot parse lpcusbsio SPI parameters.\n"
                    "Expected: spi[,<port>,<pin>,<speed_kHz>,<cpol>,<cpha>]\n"
                    f"Given:    {config}"
                ) from e

    def open(self) -> None:
        """Open the interface."""
        if not self.sio.IsOpen():
            self.sio.Open(self.dev_ix)

        self.port: LIBUSBSIO.SPI = self.sio.SPI_Open(
            portNum=self.spi_port,
            busSpeed=self.spi_speed_khz * 1000,
            cpol=self.spi_cpol,
            cpha=self.spi_cpha,
        )
        if not self.port:
            raise SPSDKError("Cannot open lpcusbsio SPI interface.\n")

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :param timeout: Read timeout
        :return: Data read from the device
        :raises SPSDKConnectionError: When reading data from device fails
        :raises TimeoutError: When no data received
        """
        try:
            (data, result) = self.port.Transfer(
                devSelectPort=self.spi_sselport,
                devSelectPin=self.spi_sselpin,
                txData=None,
                size=length,
            )
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if result < 0 or not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        :param data: Data to send
        :param timeout: Write timeout
        :raises SPSDKConnectionError: When sending the data fails
        :raises SPSDKTimeoutError: When data could not be written
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            (dummy, result) = self.port.Transfer(
                devSelectPort=self.spi_sselport, devSelectPin=self.spi_sselpin, txData=data
            )
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if result < 0:
            raise SPSDKTimeoutError()


class UsbSioI2CDevice(UsbSioDevice):
    """USBSIO I2C interface."""

    def __init__(
        self,
        config: Optional[str] = None,
        dev: int = 0,
        port: int = 0,
        address: int = 0x10,
        speed_khz: int = 100,
        timeout: int = 5000,
    ) -> None:
        """Initialize the UsbSioI2C Interface object.

        :param config: configuration string passed from command line
        :param dev: device index to be used, default is set to 0
        :param port: default I2C port to be used, typically 0 as only one port is supported by LPCLink2/MCULink
        :param address: I2C target device address
        :param speed_khz: I2C clock speed in kHz
        :param timeout: read timeout in milliseconds, defaults to 5000
        :raises SPSDKError: When port configuration cannot be parsed
        """
        super().__init__(dev=dev, config=config, timeout=timeout)

        # default configuration taken from parameters (and their default values)
        self.i2c_port = port
        self.i2c_address = address
        self.i2c_speed_khz = speed_khz

        # values can be also overridden by a configuration string
        if config:
            # config format: i2c[,<address>,<speed>]
            cfg = self.get_interface_cfg(config, "i2c").split(",")
            try:
                self.i2c_address = int(cfg[1], 0)
                self.i2c_speed_khz = int(cfg[2], 0)
            except IndexError:
                pass
            except Exception as e:
                raise SPSDKError(
                    "Cannot parse lpcusbsio I2C parameters.\n"
                    "Expected: i2c[,<address>,<speed_kHz>]\n"
                    f"Given:    {config}"
                ) from e

    def open(self) -> None:
        """Open the interface."""
        if not self.sio.IsOpen():
            self.sio.Open(self.dev_ix)
        self.port: LIBUSBSIO.I2C = self.sio.I2C_Open(
            clockRate=self.i2c_speed_khz * 1000, portNum=self.i2c_port
        )
        if not self.port:
            raise SPSDKError("Cannot open lpcusbsio I2C interface.\n")

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :param timeout: Read timeout
        :return: Data read from the device
        :raises SPSDKConnectionError: When reading data from device fails
        :raises SPSDKTimeoutError: When no data received
        """
        try:
            (data, result) = self.port.DeviceRead(devAddr=self.i2c_address, rxSize=length)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if result < 0 or not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        :param data: Data to send
        :param timeout: Write timeout
        :raises SPSDKConnectionError: When sending the data fails
        :raises TimeoutError: When data NAKed or could not be written
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            result = self.port.DeviceWrite(devAddr=self.i2c_address, txData=data)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if result < 0:
            raise SPSDKTimeoutError()
