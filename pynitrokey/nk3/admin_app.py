import enum
from dataclasses import dataclass
from enum import Enum, IntFlag
from typing import Optional

from fido2.ctap import CtapError

from pynitrokey.nk3.device import Command, Nitrokey3Device

from .device import VERSION_LEN
from .utils import Version


@enum.unique
class AdminCommand(Enum):
    STATUS = 0x80


@enum.unique
class InitStatus(IntFlag):
    NFC_ERROR = 0b0001
    INTERNAL_FLASH_ERROR = 0b0010
    EXTERNAL_FLASH_ERROR = 0b0100
    MIGRATION_ERROR = 0b1000

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


@dataclass
class Status:
    init_status: Optional[InitStatus] = None
    ifs_blocks: Optional[int] = None
    efs_blocks: Optional[int] = None


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
        return status

    def version(self) -> Version:
        reply = self.device._call(Command.VERSION, data=bytes([0x01]))
        if len(reply) == VERSION_LEN:
            version = int.from_bytes(reply, "big")
            return Version.from_int(version)
        else:
            return Version.from_str(reply.decode("utf-8"))
