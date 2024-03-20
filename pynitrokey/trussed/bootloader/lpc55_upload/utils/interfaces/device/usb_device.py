#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Low level Hid device."""
import logging
from typing import Dict, List, Optional

import libusbsio
from typing_extensions import Self

from ....exceptions import SPSDKConnectionError, SPSDKError
from ....utils.exceptions import SPSDKTimeoutError
from ....utils.interfaces.device.base import DeviceBase
from ....utils.misc import get_hash
from ....utils.usbfilter import NXPUSBDeviceFilter, USBDeviceFilter

logger = logging.getLogger(__name__)


class UsbDevice(DeviceBase):
    """USB device class."""

    def __init__(
        self,
        vid: Optional[int] = None,
        pid: Optional[int] = None,
        path: Optional[bytes] = None,
        serial_number: Optional[str] = None,
        vendor_name: Optional[str] = None,
        product_name: Optional[str] = None,
        interface_number: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Initialize the USB interface object."""
        self._opened = False
        self.vid = vid or 0
        self.pid = pid or 0
        self.path = path or b""
        self.serial_number = serial_number or ""
        self.vendor_name = vendor_name or ""
        self.product_name = product_name or ""
        self.interface_number = interface_number or 0
        self._timeout = timeout or 2000
        libusbsio_logger = logging.getLogger("libusbsio")
        self._device: libusbsio.LIBUSBSIO.HID_DEVICE = libusbsio.usbsio(
            loglevel=libusbsio_logger.getEffectiveLevel()
        ).HIDAPI_DeviceCreate()

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
        return self._opened

    def open(self) -> None:
        """Open the interface.

        :raises SPSDKError: if device is already opened
        :raises SPSDKConnectionError: if the device can not be opened
        """
        logger.debug(f"Opening the Interface: {str(self)}")
        if self.is_opened:
            # This would get HID_DEVICE into broken state
            raise SPSDKError("Can't open already opened device")
        try:
            self._device.Open(self.path)
            self._opened = True
        except Exception as error:
            raise SPSDKConnectionError(f"Unable to open device '{str(self)}'") from error

    def close(self) -> None:
        """Close the interface.

        :raises SPSDKConnectionError: if no device is available
        :raises SPSDKConnectionError: if the device can not be opened
        """
        logger.debug(f"Closing the Interface: {str(self)}")
        if self.is_opened:
            try:
                self._device.Close()
                self._opened = False
            except Exception as error:
                raise SPSDKConnectionError(f"Unable to close device '{str(self)}'") from error

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data on the IN endpoint associated to the HID interface.

        :return: Return CmdResponse object.
        :raises SPSDKConnectionError: Raises an error if device is not opened for reading
        :raises SPSDKConnectionError: Raises if device is not available
        :raises SPSDKConnectionError: Raises if reading fails
        :raises SPSDKTimeoutError: Time-out
        """
        timeout = timeout or self.timeout
        if not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for reading")
        try:
            (data, result) = self._device.Read(length, timeout_ms=timeout)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if not data:
            logger.error(f"Cannot read from HID device, error={result}")
            raise SPSDKTimeoutError()
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        :param data: Data to send
        :param timeout: Timeout to be used
        :raises SPSDKConnectionError: Sending data to device failure
        """
        timeout = timeout or self.timeout
        if not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing")
        try:
            bytes_written = self._device.Write(data, timeout_ms=timeout)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if bytes_written < 0 or bytes_written < len(data):
            raise SPSDKConnectionError(
                f"Invalid size of written bytes has been detected: {bytes_written} != {len(data)}"
            )

    def __str__(self) -> str:
        """Return information about the USB interface."""
        return (
            f"{self.product_name:s} (0x{self.vid:04X}, 0x{self.pid:04X})"
            f"path={self.path!r} sn='{self.serial_number}'"
        )

    @property
    def path_str(self) -> str:
        """BLHost-friendly string representation of USB path."""
        return NXPUSBDeviceFilter.convert_usb_path(self.path)

    @property
    def path_hash(self) -> str:
        """BLHost-friendly hash of the USB path."""
        return get_hash(self.path)

    def __hash__(self) -> int:
        return hash(self.path)

    @classmethod
    def scan(
        cls,
        device_id: Optional[str] = None,
        usb_devices_filter: Optional[Dict] = None,
        timeout: Optional[int] = None,
    ) -> List[Self]:
        """Scan connected USB devices.

        :param device_id: Device identifier <vid>, <vid:pid>, device/instance path, device name are supported
        :param usb_devices_filter: Dictionary holding NXP device vid/pid {"device_name": [vid(int), pid(int)]}.
        If set, only devices included in the dictionary will be scanned
        :param timeout: Read/write timeout
        :return: list of matching RawHid devices
        """
        usb_filter = NXPUSBDeviceFilter(usb_id=device_id, nxp_device_names=usb_devices_filter)
        devices = cls.enumerate(usb_filter, timeout=timeout)
        return devices

    @classmethod
    def enumerate(
        cls, usb_device_filter: USBDeviceFilter, timeout: Optional[int] = None
    ) -> List[Self]:
        """Get list of all connected devices which matches device_id.

        :param usb_device_filter: USBDeviceFilter object
        :param timeout: Default timeout to be set
        :return: List of interfaces found
        """
        devices = []
        libusbsio_logger = logging.getLogger("libusbsio")
        sio = libusbsio.usbsio(loglevel=libusbsio_logger.getEffectiveLevel())
        all_hid_devices = sio.HIDAPI_Enumerate()

        # iterate on all devices found
        for dev in all_hid_devices:
            if usb_device_filter.compare(vars(dev)) is True:
                new_device = cls(
                    vid=dev["vendor_id"],
                    pid=dev["product_id"],
                    path=dev["path"],
                    vendor_name=dev["manufacturer_string"],
                    product_name=dev["product_string"],
                    interface_number=dev["interface_number"],
                    timeout=timeout,
                )
                devices.append(new_device)
        return devices
