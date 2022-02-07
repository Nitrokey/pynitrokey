# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import enum
import logging
import sys
from enum import Enum
from typing import List, Optional

from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice, open_device

from pynitrokey.fido2 import device_path_to_str

from .base import Nitrokey3Base
from .exceptions import TimeoutException
from .utils import Version

RNG_LEN = 57
UUID_LEN = 16
VERSION_LEN = 4

logger = logging.getLogger(__name__)


@enum.unique
class Command(Enum):
    """Vendor-specific CTAPHID commands for the Nitrokey 3."""

    UPDATE = 0x51
    REBOOT = 0x53
    RNG = 0x60
    VERSION = 0x61
    UUID = 0x62


@enum.unique
class BootMode(Enum):
    FIRMWARE = enum.auto()
    BOOTROM = enum.auto()


class Nitrokey3Device(Nitrokey3Base):
    """A Nitrokey 3 device running the firmware."""

    def __init__(self, device: CtapHidDevice) -> None:
        from . import PID_NITROKEY3_DEVICE, VID_NITROKEY

        (vid, pid) = (device.descriptor.vid, device.descriptor.pid)
        if (vid, pid) != (VID_NITROKEY, PID_NITROKEY3_DEVICE):
            raise ValueError(
                "Not a Nitrokey 3 device: expected VID:PID "
                f"{VID_NITROKEY:x}:{PID_NITROKEY3_DEVICE:x}, got {vid:x}:{pid:x}"
            )

        self.device = device
        self._path = device_path_to_str(device.descriptor.path)
        self.logger = logger.getChild(self._path)

    @property
    def path(self) -> str:
        return self._path

    @property
    def name(self) -> str:
        return "Nitrokey 3"

    def close(self) -> None:
        self.device.close()

    def reboot(self, mode: BootMode = BootMode.FIRMWARE) -> None:
        try:
            if mode == BootMode.FIRMWARE:
                self._call(Command.REBOOT)
            elif mode == BootMode.BOOTROM:
                try:
                    self._call(Command.UPDATE)
                except CtapError as e:
                    # The admin app returns an Invalid Length error if the user confirmation
                    # request times out
                    if e.code == CtapError.ERR.INVALID_LENGTH:
                        raise TimeoutException()
                    else:
                        raise e
        except OSError as e:
            # OS error is expected as the device does not respond during the reboot
            self.logger.debug("ignoring OSError after reboot", exc_info=e)

    def uuid(self) -> Optional[int]:
        uuid = self._call(Command.UUID)
        if len(uuid) == 0:
            # Firmware version 1.0.0 does not support querying the UUID
            return None
        if len(uuid) != UUID_LEN:
            raise ValueError(f"UUID response has invalid length {len(uuid)}")
        return int.from_bytes(uuid, "big")

    def version(self) -> Version:
        version_bytes = self._call(Command.VERSION, response_len=VERSION_LEN)
        version = int.from_bytes(version_bytes, "big")
        return Version.from_int(version)

    def wink(self) -> None:
        self.device.wink()

    def rng(self) -> bytes:
        return self._call(Command.RNG, response_len=RNG_LEN)

    def _call(self, command: Command, response_len: Optional[int] = None) -> bytes:
        response = self.device.call(command.value)
        if response_len is not None and response_len != len(response):
            raise ValueError(
                f"The response for the CTAPHID {command.name} command has an unexpected length "
                f"(expected: {response_len}, actual: {len(response)})"
            )
        return response

    @staticmethod
    def list() -> List["Nitrokey3Device"]:
        devices = []
        for device in CtapHidDevice.list_devices():
            try:
                devices.append(Nitrokey3Device(device))
            except ValueError:
                # not a Nitrokey 3 device, skip
                pass
        return devices

    @staticmethod
    def open(path: str) -> Optional["Nitrokey3Device"]:
        try:
            device = open_device(path)
        except Exception:
            logger.warn(f"No CTAPHID device at path {path}", exc_info=sys.exc_info())
            return None
        try:
            return Nitrokey3Device(device)
        except ValueError:
            logger.warn(f"No Nitrokey 3 device at path {path}", exc_info=sys.exc_info())
            return None
