# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import platform
import sys
from typing import Callable, List, Optional, Tuple

from spsdk.mboot import McuBoot, StatusCode
from spsdk.mboot.interfaces import RawHid
from spsdk.mboot.properties import PropertyTag
from spsdk.sbfile.sb2.images import BootImageV21
from spsdk.utils.usbfilter import USBDeviceFilter

from .base import Nitrokey3Base
from .utils import Version

RKHT = bytes.fromhex("050aad3e77791a81e59c5b2ba5a158937e9460ee325d8ccba09734b8fdebb171")
KEK = bytes([0xAA] * 32)
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

    @property
    def status(self) -> Tuple[int, str]:
        code = self.device.status_code
        message = StatusCode.desc(code)
        return (code, message)

    def close(self) -> None:
        self.device.close()

    def reboot(self) -> None:
        if not self.device.reset(reopen=False):
            # On Windows, this function returns false even if the reset was successful
            if platform.system() == "Windows":
                logger.warning("Failed to reboot Nitrokey 3 bootloader")
            else:
                raise Exception("Failed to reboot Nitrokey 3 bootloader")

    def uuid(self) -> Optional[int]:
        uuid = self.device.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)  # type: ignore[arg-type]
        if not uuid:
            raise ValueError("Missing response for UUID property query")
        if len(uuid) != UUID_LEN:
            raise ValueError(f"UUID response has invalid length {len(uuid)}")

        # See GetProperties::device_uuid in the lpc55 crate:
        # https://github.com/lpc55/lpc55-host/blob/main/src/bootloader/property.rs#L222
        wrong_endian = (uuid[3] << 96) + (uuid[2] << 64) + (uuid[1] << 32) + uuid[0]
        right_endian = wrong_endian.to_bytes(16, byteorder="little")
        return int.from_bytes(right_endian, byteorder="big")

    def update(
        self,
        image: bytes,
        callback: Optional[Callable[[int, int], None]] = None,
        check_errors: bool = False,
    ) -> bool:
        return self.device.receive_sb_file(
            image,
            progress_callback=callback,
            check_errors=check_errors,
        )

    @staticmethod
    def list() -> List["Nitrokey3Bootloader"]:
        from . import PID_NITROKEY3_BOOTLOADER, VID_NITROKEY

        device_filter = USBDeviceFilter(
            f"0x{VID_NITROKEY:x}:0x{PID_NITROKEY3_BOOTLOADER:x}"
        )
        devices = []
        for device in RawHid.enumerate(device_filter):
            # TODO: remove assert if https://github.com/NXPmicro/spsdk/issues/32 is fixed
            assert isinstance(device, RawHid)
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
            # TODO: remove assert if https://github.com/NXPmicro/spsdk/issues/32 is fixed
            assert isinstance(devices[0], RawHid)
            return Nitrokey3Bootloader(devices[0])
        except ValueError:
            logger.warn(
                f"No Nitrokey 3 bootloader at path {path}", exc_info=sys.exc_info()
            )
            return None


class FirmwareMetadata:
    def __init__(self, version: Version, rkht: Optional[bytes]) -> None:
        self.version = version
        self.rkht = rkht

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FirmwareMetadata):
            return NotImplemented
        return self.version == other.version and self.rkht == other.rkht

    def __repr__(self) -> str:
        rkht = self.rkht.hex() if self.rkht else None
        return f"FirmwareMetadata(version={self.version}, rkht={rkht})"

    @classmethod
    def from_image(cls, image: BootImageV21) -> "FirmwareMetadata":
        return cls(
            version=Version.from_bcd_version(image.header.product_version),
            rkht=image.cert_block.rkht if image.cert_block else None,
        )

    @classmethod
    def from_image_data(cls, data: bytes) -> "FirmwareMetadata":
        return FirmwareMetadata.from_image(BootImageV21.parse(data, kek=KEK))


def check_firmware_image(data: bytes) -> FirmwareMetadata:
    try:
        metadata = FirmwareMetadata.from_image_data(data)
    except Exception:
        logger.exception("Failed to parse firmware image", exc_info=sys.exc_info())
        raise Exception("Failed to parse firmware image")

    if not metadata.rkht:
        raise Exception("Firmware image is not signed")

    if metadata.rkht != RKHT:
        raise Exception(
            f"Firmware image is not signed by Nitrokey (RKHT: {metadata.rkht.hex()})"
        )

    return metadata
