import enum
import sys
from dataclasses import dataclass
from enum import Enum, IntFlag
from typing import Optional

from fido2 import cbor
from fido2.ctap import CtapError

from pynitrokey.helpers import local_critical, local_print
from pynitrokey.nk3.device import Command, Nitrokey3Device

from .device import VERSION_LEN
from .utils import Version


@enum.unique
class AdminCommand(Enum):
    STATUS = 0x80
    TEST_SE050 = 0x81
    GET_CONFIG = 0x82
    SET_CONFIG = 0x83
    FACTORY_RESET = 0x84
    FACTORY_RESET_APP = 0x85


@enum.unique
class InitStatus(IntFlag):
    NFC_ERROR = 0b0001
    INTERNAL_FLASH_ERROR = 0b0010
    EXTERNAL_FLASH_ERROR = 0b0100
    MIGRATION_ERROR = 0b1000
    SE050_ERROR = 0b00010000

    def is_error(self) -> bool:
        return self.value != 0

    def __str__(self) -> str:
        if self == 0:
            return "ok"
        errors = [error for error in InitStatus if error in self if error.name]
        value = sum(errors)
        messages = [error.name for error in errors if error.name]
        if self.value != value:
            messages.append("UNKNOWN")
        return ", ".join(messages) + " (" + hex(self.value) + ")"


@enum.unique
class Variant(Enum):
    USBIP = 0
    LPC55 = 1
    NRF52 = 2


@dataclass
class Status:
    init_status: Optional[InitStatus] = None
    ifs_blocks: Optional[int] = None
    efs_blocks: Optional[int] = None
    variant: Optional[Variant] = None


@enum.unique
class FactoryResetStatus(Enum):
    SUCCESS = 0
    NOT_CONFIRMED = 0x01
    APP_NOT_ALLOWED = 0x02
    APP_FAILED_PARSE = 0x03

    @classmethod
    def from_int(cls, i: int) -> Optional["FactoryResetStatus"]:
        for status in FactoryResetStatus:
            if status.value == i:
                return status
        return None

    @classmethod
    def check(cls, i: int, msg: str) -> None:
        status = FactoryResetStatus.from_int(i)
        if status != FactoryResetStatus.SUCCESS:
            if status is None:
                raise Exception(f"Unknown error {i:x}")
            if status == FactoryResetStatus.NOT_CONFIRMED:
                error = "Operation was not confirmed with touch"
            elif status == FactoryResetStatus.APP_NOT_ALLOWED:
                error = "The application does not support factory reset through nitropy"
            elif status == FactoryResetStatus.APP_FAILED_PARSE:
                error = "The application name must be utf-8"
            local_critical(f"{msg}: {error}", support_hint=False)


@enum.unique
class ConfigStatus(Enum):
    SUCCESS = 0
    READ_FAILED = 1
    WRITE_FAILED = 2
    DESERIALIZATION_FAILED = 3
    SERIALIZATION_FAILED = 4
    INVALID_KEY = 5
    INVALID_VALUE = 6
    DATA_TOO_LONG = 7

    @classmethod
    def from_int(cls, i: int) -> Optional["ConfigStatus"]:
        for status in ConfigStatus:
            if status.value == i:
                return status
        return None

    @classmethod
    def check(cls, i: int, msg: str) -> None:
        status = ConfigStatus.from_int(i)
        if status != ConfigStatus.SUCCESS:
            if status:
                error = str(status)
            else:
                error = f"unknown error {i:x}"
            raise Exception(f"{msg}: {error}")


class AdminApp:
    def __init__(self, device: Nitrokey3Device) -> None:
        self.device = device

    def _call(
        self,
        command: AdminCommand,
        response_len: Optional[int] = None,
        data: bytes = b"",
    ) -> Optional[bytes]:
        try:
            return self.device._call(
                Command.ADMIN,
                response_len=response_len,
                data=command.value.to_bytes(1, "big") + data,
            )
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                return None
            else:
                raise

    def status(self) -> Status:
        status = Status()
        reply = self._call(AdminCommand.STATUS)
        if reply is not None:
            if not reply:
                raise ValueError("The device returned an empty status")
            status.init_status = InitStatus(reply[0])
            if len(reply) >= 4:
                status.ifs_blocks = reply[1]
                status.efs_blocks = int.from_bytes(reply[2:4], "big")
            if len(reply) >= 5:
                try:
                    status.variant = Variant(reply[4])
                except ValueError:
                    pass
        return status

    def version(self) -> Version:
        reply = self.device._call(Command.VERSION, data=bytes([0x01]))
        if len(reply) == VERSION_LEN:
            version = int.from_bytes(reply, "big")
            return Version.from_int(version)
        else:
            return Version.from_str(reply.decode("utf-8"))

    def se050_tests(self) -> Optional[bytes]:
        return self._call(AdminCommand.TEST_SE050)

    def has_config(self, key: str) -> bool:
        reply = self._call(AdminCommand.GET_CONFIG, data=key.encode())
        if not reply or len(reply) < 1:
            return False
        return ConfigStatus.from_int(reply[0]) == ConfigStatus.SUCCESS

    def get_config(self, key: str) -> str:
        reply = self._call(AdminCommand.GET_CONFIG, data=key.encode())
        if not reply or len(reply) < 1:
            raise ValueError("The device returned an empty response")
        ConfigStatus.check(reply[0], "Failed to get config value")
        return reply[1:].decode()

    def set_config(self, key: str, value: str) -> None:
        request = cbor.encode({"key": key, "value": value})
        reply = self._call(AdminCommand.SET_CONFIG, data=request, response_len=1)
        assert reply
        ConfigStatus.check(reply[0], "Failed to set config value")

    def factory_reset(self) -> None:
        try:
            local_print(
                "Please touch the device to confirm the operation", file=sys.stderr
            )
            reply = self._call(AdminCommand.FACTORY_RESET, response_len=1)
            if reply is None:
                local_critical(
                    "Factory reset is not supported by the firmware version on the device",
                    support_hint=False,
                )
                return
        except OSError as e:
            if e.errno == 5:
                self.device.logger.debug("ignoring OSError after reboot", exc_info=e)
                return
            else:
                raise e
        FactoryResetStatus.check(reply[0], "Failed to factory reset the device")

    def factory_reset_app(self, application: str) -> None:
        local_print("Please touch the device to confirm the operation", file=sys.stderr)
        reply = self._call(
            AdminCommand.FACTORY_RESET_APP,
            data=application.encode("ascii"),
            response_len=1,
        )
        if reply is None:
            local_critical(
                "Application Factory reset is not supported by the firmware version on the device",
                support_hint=False,
            )
            return
        FactoryResetStatus.check(reply[0], "Failed to factory reset the device")
