import enum
from enum import Enum
from typing import Optional

from fido2.ctap import CtapError

from pynitrokey.nk3.device import Command, Nitrokey3Device


@enum.unique
class DebugCommand(Enum):
    GET_SIZE = 0x00
    READ = 0x01


class DebugApp:
    def __init__(self, device: Nitrokey3Device) -> None:
        self.device = device

    def _call(
        self,
        command: DebugCommand,
        response_len: Optional[int] = None,
        data: bytes = b"",
    ) -> Optional[bytes]:
        try:
            return self.device._call(
                Command.DEBUG,
                response_len=response_len,
                data=command.value.to_bytes(1, "big") + data,
            )
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                return None
            else:
                raise

    def size(self) -> int:
        reply = self._call(DebugCommand.GET_SIZE, response_len=4)
        assert reply
        return int.from_bytes(reply, "big")

    def read(self, offset: int) -> bytes:
        reply = self._call(DebugCommand.READ, data=offset.to_bytes(4, "big"))
        assert reply
        return reply
