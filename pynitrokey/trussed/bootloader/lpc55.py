# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import platform
import re
import sys
from typing import List, Optional, Tuple, TypeVar

from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.mboot.mcuboot import McuBoot
from spsdk.mboot.properties import PropertyTag
from spsdk.sbfile.sb2.images import BootImageV21
from spsdk.utils.interfaces.device.usb_device import UsbDevice
from spsdk.utils.usbfilter import USBDeviceFilter

from pynitrokey.trussed.utils import Uuid, Version

from . import FirmwareMetadata, NitrokeyTrussedBootloader, ProgressCallback, Variant

RKTH = bytes.fromhex("050aad3e77791a81e59c5b2ba5a158937e9460ee325d8ccba09734b8fdebb171")
KEK = bytes([0xAA] * 32)
UUID_LEN = 4
FILENAME_PATTERN = re.compile("(firmware|alpha)-nk3..-lpc55-(?P<version>.*)\\.sb2$")

T = TypeVar("T", bound="NitrokeyTrussedBootloaderLpc55")

logger = logging.getLogger(__name__)


class NitrokeyTrussedBootloaderLpc55(NitrokeyTrussedBootloader):
    """A Nitrokey 3 device running the LPC55 bootloader."""

    def __init__(self, device: UsbDevice):
        self.validate_vid_pid(device.vid, device.pid)
        self._path = device.path
        self.device = McuBoot(MbootUSBInterface(device))

    def __enter__(self: T) -> T:
        self.device.open()
        return self

    @property
    def variant(self) -> Variant:
        return Variant.LPC55

    @property
    def path(self) -> str:
        if isinstance(self._path, bytes):
            return self._path.decode("UTF-8")
        return self._path

    @property
    def status(self) -> Tuple[int, str]:
        code = self.device.status_code
        message = StatusCode.desc(code)
        return (code, message)

    def close(self) -> None:
        self.device.close()

    def reboot(self) -> bool:
        if not self.device.reset(reopen=False):
            # On Windows, this function returns false even if the reset was successful
            if platform.system() == "Windows":
                logger.warning("Failed to reboot Nitrokey 3 bootloader")
            else:
                raise Exception("Failed to reboot Nitrokey 3 bootloader")
        return True

    def uuid(self) -> Optional[Uuid]:
        uuid = self.device.get_property(PropertyTag.UNIQUE_DEVICE_IDENT)
        if not uuid:
            raise ValueError("Missing response for UUID property query")
        if len(uuid) != UUID_LEN:
            raise ValueError(f"UUID response has invalid length {len(uuid)}")

        # See GetProperties::device_uuid in the lpc55 crate:
        # https://github.com/lpc55/lpc55-host/blob/main/src/bootloader/property.rs#L222
        wrong_endian = (uuid[3] << 96) + (uuid[2] << 64) + (uuid[1] << 32) + uuid[0]
        right_endian = wrong_endian.to_bytes(16, byteorder="little")
        return Uuid(int.from_bytes(right_endian, byteorder="big"))

    def update(
        self,
        image: bytes,
        callback: Optional[ProgressCallback] = None,
        check_errors: bool = False,
    ) -> None:
        success = self.device.receive_sb_file(
            image,
            progress_callback=callback,
            check_errors=check_errors,
        )
        logger.debug(f"Firmware update finished with status {self.status}")
        if success:
            self.reboot()
        else:
            (code, message) = self.status
            raise Exception(
                f"Firmware update failed with status code {code}: {message}"
            )

    @classmethod
    def list_vid_pid(cls: type[T], vid: int, pid: int) -> list[T]:
        device_filter = USBDeviceFilter(f"0x{vid:x}:0x{pid:x}")
        devices = []
        for device in UsbDevice.enumerate(device_filter):
            try:
                devices.append(cls(device))
            except ValueError:
                logger.warn(
                    f"Invalid Nitrokey 3 LPC55 bootloader returned by enumeration: {device}"
                )
        return devices

    @classmethod
    def open(cls: type[T], path: str) -> Optional[T]:
        device_filter = USBDeviceFilter(path)
        devices = UsbDevice.enumerate(device_filter)
        if len(devices) == 0:
            logger.warn(f"No HID device at {path}")
            return None
        if len(devices) > 1:
            logger.warn(f"Multiple HID devices at {path}: {devices}")
            return None

        try:
            return cls(devices[0])
        except ValueError:
            logger.warn(
                f"No Nitrokey 3 bootloader at path {path}", exc_info=sys.exc_info()
            )
            return None


def parse_firmware_image(data: bytes) -> FirmwareMetadata:
    image = BootImageV21.parse(data, kek=KEK)
    version = Version.from_bcd_version(image.header.product_version)
    metadata = FirmwareMetadata(version=version)
    if image.cert_block:
        if image.cert_block.rkth == RKTH:
            metadata.signed_by = "Nitrokey"
            metadata.signed_by_nitrokey = True
        else:
            metadata.signed_by = f"unknown issuer (RKTH: {image.cert_block.rkth.hex()})"
    return metadata
