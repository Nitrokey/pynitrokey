#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Low level sdio device."""
import os
import time
from io import FileIO
from typing import List, Optional

from typing_extensions import Self

from ....exceptions import SPSDKConnectionError, SPSDKError
from ....utils.exceptions import SPSDKTimeoutError
from ....utils.interfaces.device.base import DeviceBase, logger
from ....utils.misc import Timeout


class SdioDevice(DeviceBase):
    """SDIO device class."""

    DEFAULT_TIMEOUT = 2000

    def __init__(
        self,
        path: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the SDIO interface object.

        :raises McuBootConnectionError: when the path is empty
        """
        self._opened = False
        # Temporarily use hard code until there is a way to retrive VID/PID
        self.vid = 0x0471
        self.pid = 0x0209
        self._timeout = timeout
        if path is None:
            raise SPSDKConnectionError("No SDIO device path")
        self.path = path
        self.is_blocking = False
        self.device: Optional[FileIO] = None

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
        return self.device is not None and self._opened

    def open(self) -> None:
        """Open the interface with non-blocking mode.

        :raises McuBootError: if non-blocking mode is not available
        :raises SPSDKError: if trying to open in non-blocking mode on non-linux os
        :raises SPSDKConnectionError: if no device is available
        :raises SPSDKConnectionError: if the device can not be opened
        """
        logger.debug("Opening the sdio device.")
        if not self._opened:
            try:
                self.device = open(self.path, "rb+", buffering=0)
                if self.device is None:
                    raise SPSDKConnectionError("No device available")
                if not self.is_blocking:
                    if not hasattr(os, "set_blocking"):
                        raise SPSDKError("Opening in non-blocking mode is available only on Linux")
                    # pylint: disable=no-member     # this is available only on Unix
                    os.set_blocking(self.device.fileno(), False)
                self._opened = True
            except Exception as error:
                raise SPSDKConnectionError(
                    f"Unable to open device '{self.path}' VID={self.vid} PID={self.pid}"
                ) from error

    def close(self) -> None:
        """Close the interface.

        :raises SPSDKConnectionError: if no device is available
        :raises SPSDKConnectionError: if the device can not be opened
        """
        logger.debug("Closing the sdio Interface.")
        if not self.device:
            raise SPSDKConnectionError("No device available")
        if self._opened:
            try:
                self.device.close()
                self._opened = False
            except Exception as error:
                raise SPSDKConnectionError(
                    f"Unable to close device '{self.path}' VID={self.vid} PID={self.pid}"
                ) from error

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :param timeout: Read timeout
        :return: Data read from the device
        :raises SPSDKTimeoutError: Time-out
        :raises SPSDKConnectionError: When device was not open for reading
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for reading")
        _read = self._read_blocking if self.is_blocking else self._read_non_blocking
        data = _read(length=length, timeout=timeout)
        if not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _read_blocking(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount for bytes from device in blocking mode.

        :param length: Number of bytes to read
        :param timeout: Read timeout
        :return: Data read from the device
        :raises SPSDKConnectionError: When reading data from device fails
        :raises SPSDKConnectionError: Raises if device is not opened for reading
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing")
        logger.debug("Reading with blocking mode.")
        try:
            return self.device.read(length)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e

    def _read_non_blocking(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount for bytes from device in non-blocking mode.

        :param length: Number of bytes to read
        :param timeout: Read timeout
        :return: Data read from the device
        :raises TimeoutError: When timeout occurs
        :raises SPSDKConnectionError: When reading data from device fails
        :raises SPSDKConnectionError: Raises if device is not opened for reading
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for reading")
        logger.debug("Reading with non-blocking mode.")
        has_data = 0
        no_data_continuous = 0

        data = bytearray()
        _timeout = Timeout(timeout or self.timeout, "ms")
        while len(data) < length:
            try:
                buf = self.device.read(length)
            except Exception as e:
                raise SPSDKConnectionError(str(e)) from e

            if buf is None:
                time.sleep(0.05)  # delay for access device
                if has_data != 0:
                    no_data_continuous = no_data_continuous + 1
            else:
                data.extend(buf)
                logger.debug("expend buf")
                has_data = has_data + 1
                no_data_continuous = 0

            if no_data_continuous > 5:
                break
            if _timeout.overflow():
                logger.debug("SDIO interface : read timeout")
                break
        return bytes(data)

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device with non-blocking mode.

        :param data: Data to send
        :param timeout: Write timeout
        :raises SPSDKConnectionError: Raises an error if device is not available
        :raises SPSDKConnectionError: When sending the data fails
        :raises TimeoutError: When timeout occurs
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing.")
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        _write = self._write_blocking if self.is_blocking else self._write_non_blocking
        _write(data=data, timeout=timeout)

    def _write_blocking(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write data to device in blocking mode.

        :param data: Data to be written
        :param timeout: Write timeout

        :raises SPSDKConnectionError: When writing data to device fails
        :raises SPSDKConnectionError: Raises if device is not opened for writing
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing")
        logger.debug("Writing in blocking mode")
        try:
            self.device.write(data)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e

    def _write_non_blocking(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write data to device in non-blocking mode.

        :param data: Data to be written
        :param timeout: Write timeout

        :raises SPSDKConnectionError: When writing data to device fails
        :raises SPSDKConnectionError: Raises if device is not opened for writing
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing")
        logger.debug("Writing in non-blocking mode")
        tx_len = len(data)
        _timeout = Timeout(timeout or self.timeout, "ms")
        while tx_len > 0:
            try:
                wr_count = self.device.write(data)
                time.sleep(0.05)
                data = data[wr_count:]
                tx_len -= wr_count
            except Exception as e:
                raise SPSDKConnectionError(str(e)) from e
            if _timeout.overflow():
                raise SPSDKTimeoutError()

    def __str__(self) -> str:
        """Return information about the SDIO interface."""
        return f"(0x{self.vid:04X}, 0x{self.pid:04X})"

    @classmethod
    def scan(
        cls,
        device_path: str,
        timeout: Optional[int] = None,
    ) -> List[Self]:
        """Scan connected SDIO devices.

        :param device_path: device path string
        :param timeout: default read/write timeout
        :return: matched SDIO device
        """
        if device_path is None:
            logger.debug("No sdio path has been defined.")
            devices = []
        try:
            logger.debug(f"Checking path: {device_path}")
            device = cls(path=device_path, timeout=timeout or cls.DEFAULT_TIMEOUT)
            device.open()
            device.close()
            devices = [device] if device else []
        except Exception as e:  # pylint: disable=broad-except
            logger.debug(f"{type(e).__name__}: {e}")
            devices = []
        return devices
