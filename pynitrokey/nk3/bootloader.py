# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import sys
from typing import List, Optional

from spsdk.mboot import McuBoot
from spsdk.mboot.interfaces import RawHid
from spsdk.mboot.properties import PropertyTag
from spsdk.utils.usbfilter import USBDeviceFilter

from .base import Nitrokey3Base

UUID_LEN = 4

logger = logging.getLogger(__name__)


class Nitrokey3Bootloader(Nitrokey3Base):
    """A Nitrokey 3 device running the bootloader."""

    def __init__(self, device: RawHid):
        from . import PID_NITROKEY3_BOOTLOADER, VID_NITROKEY

        if (device.vid, device.pid) != (VID_NITROKEY, PID_NITROKEY3_BOOTLOADER):
            raise ValueError(
                "Not a Nitrokey 3 device: expected VID:PID "
                f"{VID_NITROKEY:x}:{PID_NITROKEY3_BOOTLOADER:x}, "
                f"got {device.vid:x}:{device.pid:x}"
            )
        self._path = device.path
        self.device = McuBoot(device)

    def __enter__(self) -> "Nitrokey3Bootloader":
        self.device.open()
        return self

    @property
    def path(self) -> str:
        if isinstance(self._path, bytes):
            return self._path.decode("UTF-8")
        return self._path

    @property
    def name(self) -> str:
        return "Nitrokey 3 Bootloader"

    def close(self) -> None:
        self.device.close()

    def reboot(self) -> None:
        if not self.device.reset(reopen=False):
            raise Exception("Failed to reboot Nitrokey 3 bootloader")

    def uuid(self) -> Optional[int]:
        uuid = self.device.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)
        if not uuid:
            raise ValueError("Missing response for UUID property query")
        if len(uuid) != UUID_LEN:
            raise ValueError(f"UUID response has invalid length {len(uuid)}")

        # See GetProperties::device_uuid in the lpc55 crate:
        # https://github.com/lpc55/lpc55-host/blob/main/src/bootloader/property.rs#L222
        wrong_endian = (uuid[3] << 96) + (uuid[2] << 64) + (uuid[1] << 32) + uuid[0]
        right_endian = wrong_endian.to_bytes(16, byteorder="little")
        return int.from_bytes(right_endian, byteorder="big")

    @staticmethod
    def list() -> List["Nitrokey3Bootloader"]:
        from . import PID_NITROKEY3_BOOTLOADER, VID_NITROKEY

        device_filter = USBDeviceFilter(
            f"0x{VID_NITROKEY:x}:0x{PID_NITROKEY3_BOOTLOADER:x}"
        )
        devices = []
        for device in RawHid.enumerate(device_filter):
            try:
                devices.append(Nitrokey3Bootloader(device))
            except ValueError:
                logger.warn(
                    f"Invalid Nitrokey 3 bootloader returned by enumeration: {device}"
                )
        return devices

    @staticmethod
    def open(path: str) -> Optional["Nitrokey3Bootloader"]:
        device_filter = USBDeviceFilter(path)
        devices = RawHid.enumerate(device_filter)
        if len(devices) == 0:
            logger.warn(f"No HID device at {path}")
            return None
        if len(devices) > 1:
            logger.warn(f"Multiple HID devices at {path}: {devices}")
            return None

        try:
            return Nitrokey3Bootloader(devices[0])
        except ValueError:
            logger.warn(
                f"No Nitrokey 3 bootloader at path {path}", exc_info=sys.exc_info()
            )
            return None
