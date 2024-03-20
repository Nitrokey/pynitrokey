#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Low level serial device."""
import logging
from typing import List, Optional

from serial import Serial, SerialException, SerialTimeoutException
from serial.tools.list_ports import comports
from typing_extensions import Self

from spsdk.exceptions import SPSDKConnectionError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.device.base import DeviceBase

logger = logging.getLogger(__name__)


class SerialDevice(DeviceBase):
    """Serial device class."""

    default_baudrate = 115200
    default_timeout = 5000

    def __init__(
        self,
        port: Optional[str] = None,
        timeout: int = default_timeout,
        baudrate: int = default_baudrate,
    ):
        """Initialize the UART interface.

        :param port: name of the serial port, defaults to None
        :param baudrate: speed of the UART interface, defaults to 115200
        :param timeout: read/write timeout in milliseconds, defaults to 1000
        :raises SPSDKConnectionError: when there is no port available
        """
        super().__init__()
        self._timeout = timeout
        try:
            timeout_s = timeout / 1000
            self._device = Serial(
                port=port, timeout=timeout_s, write_timeout=timeout_s, baudrate=baudrate
            )
            self.expect_status = True
        except SerialException as se:
            logger.debug(f"Exception occurred during device opening: {se}")
            self.expect_status = False
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e

    @property
    def timeout(self) -> int:
        """Timeout property."""
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Timeout property setter."""
        self._timeout = value
        self._device.timeout = value / 1000
        self._device.write_timeout = value / 1000

    @property
    def is_opened(self) -> bool:
        """Indicates whether device is open.

        :return: True if device is open, False otherwise.
        """
        if self.expect_status == False:
            return False
        else:
            return self._device.is_open

    def open(self) -> None:
        """Open the UART interface.

        :raises SPSDKConnectionError: when opening device fails
        """
        if not self.is_opened:
            try:
                self._device.open()
            except Exception as e:
                self.close()
                raise SPSDKConnectionError(str(e)) from e

    def close(self) -> None:
        """Close the UART interface.

        :raises SPSDKConnectionError: when closing device fails
        """
        if self.is_opened:
            try:
                self._device.reset_input_buffer()
                self._device.reset_output_buffer()
                self._device.close()
            except Exception as e:
                raise SPSDKConnectionError(str(e)) from e

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :param timeout: Read timeout
        :return: Data read from the device
        :raises SPSDKTimeoutError: Time-out
        :raises SPSDKConnectionError: When reading data from device fails
        """
        if not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for reading")
        try:
            data = self._device.read(length)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        :param data: Data to send
        :param timeout: Write timeout
        :raises SPSDKTimeoutError: when sending of data times-out
        :raises SPSDKConnectionError: when send data to device fails
        """
        if not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for reading")
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            self._device.reset_input_buffer()
            self._device.reset_output_buffer()
            self._device.write(data)
            self._device.flush()
        except SerialTimeoutException as e:
            raise SPSDKTimeoutError(
                f"Write timeout error. The timeout is set to {self._device.write_timeout} s. Consider increasing it."
            ) from e
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e

    def __str__(self) -> str:
        """Return information about the UART interface.

        :return: information about the UART interface
        :raises SPSDKConnectionError: when information can not be collected from device
        """
        try:
            return self._device.port
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e

    @classmethod
    def scan(
        cls,
        port: Optional[str] = None,
        baudrate: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> List[Self]:
        """Scan connected serial ports.

        Returns list of serial ports with devices that respond to PING command.
        If 'port' is specified, only that serial port is checked
        If no devices are found, return an empty list.

        :param port: name of preferred serial port, defaults to None
        :param baudrate: speed of the UART interface, defaults to 56700
        :param timeout: timeout in milliseconds, defaults to 5000
        :return: list of interfaces responding to the PING command
        """
        baudrate = baudrate or cls.default_baudrate
        timeout = timeout or 5000
        if port:
            device = cls._check_port(port, baudrate, timeout)
            devices = [device] if device else []
        else:
            all_ports = [
                cls._check_port(comport.device, baudrate, timeout)
                for comport in comports(include_links=True)
            ]
            devices = list(filter(None, all_ports))
        return devices

    @classmethod
    def _check_port(cls, port: str, baudrate: int, timeout: int) -> Optional[Self]:
        """Check if device on comport 'port' responds to PING command.

        :param port: name of port to check
        :param baudrate: speed of the UART interface, defaults to 56700
        :param timeout: timeout in milliseconds
        :return: None if device doesn't respond to PING, instance of Interface if it does
        """
        try:
            logger.debug(f"Checking port: {port}, baudrate: {baudrate}, timeout: {timeout}")
            device = cls(port=port, baudrate=baudrate, timeout=timeout)
            device.open()
            device.close()
            return device
        except Exception as e:  # pylint: disable=broad-except
            logger.debug(f"{type(e).__name__}: {e}")
            return None
