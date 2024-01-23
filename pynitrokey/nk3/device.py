# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import enum
from enum import Enum
from typing import Optional

from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice

from pynitrokey.trussed.device import NitrokeyTrussedDevice
from pynitrokey.trussed.utils import Uuid, Version

from .exceptions import TimeoutException

RNG_LEN = 57
UUID_LEN = 16
VERSION_LEN = 4


@enum.unique
class Command(Enum):
    """Vendor-specific CTAPHID commands for the Nitrokey 3."""

    UPDATE = 0x51
    REBOOT = 0x53
    RNG = 0x60
    VERSION = 0x61
    UUID = 0x62
    LOCKED = 0x63
    OTP = 0x70
    PROVISIONER = 0x71
    ADMIN = 0x72


@enum.unique
class BootMode(Enum):
    FIRMWARE = enum.auto()
    BOOTROM = enum.auto()


class Nitrokey3Device(NitrokeyTrussedDevice):
    """A Nitrokey 3 device running the firmware."""

    def __init__(self, device: CtapHidDevice) -> None:
        super().__init__(device)

    @property
    def pid(self) -> int:
        from . import PID_NITROKEY3_DEVICE

        return PID_NITROKEY3_DEVICE

    @property
    def name(self) -> str:
        return "Nitrokey 3"

    def reboot(self, mode: BootMode = BootMode.FIRMWARE) -> bool:
        try:
            if mode == BootMode.FIRMWARE:
                self._call_nk3(Command.REBOOT)
            elif mode == BootMode.BOOTROM:
                try:
                    self._call_nk3(Command.UPDATE)
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
        return True

    def uuid(self) -> Optional[Uuid]:
        uuid = self._call_nk3(Command.UUID)
        if len(uuid) == 0:
            # Firmware version 1.0.0 does not support querying the UUID
            return None
        if len(uuid) != UUID_LEN:
            raise ValueError(f"UUID response has invalid length {len(uuid)}")
        return Uuid(int.from_bytes(uuid, byteorder="big"))

    def version(self) -> Version:
        return self.admin.version()

    def factory_reset(self) -> None:
        self.admin.factory_reset()

    def factory_reset_app(self, app: str) -> None:
        self.admin.factory_reset_app(app)

    def rng(self) -> bytes:
        return self._call_nk3(Command.RNG, response_len=RNG_LEN)

    def otp(self, data: bytes = b"") -> bytes:
        return self._call_nk3(Command.OTP, data=data)

    def is_locked(self) -> bool:
        response = self._call_nk3(Command.LOCKED, response_len=1)
        return response[0] == 1

    def _call_nk3(
        self, command: Command, response_len: Optional[int] = None, data: bytes = b""
    ) -> bytes:
        return super()._call(command.value, command.name, response_len, data)
