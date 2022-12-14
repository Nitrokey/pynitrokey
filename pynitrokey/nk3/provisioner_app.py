import enum
from enum import Enum
from typing import Optional

from pynitrokey.nk3.device import Command, Nitrokey3Device


@enum.unique
class Buffer(Enum):
    FILENAME = bytes([0xE1, 0x01])
    FILE = bytes([0xE1, 0x02])


@enum.unique
class ProvisionerCommand(Enum):
    SELECT = 0xA4
    WRITE_BINARY = 0xD0
    WRITE_FILE = 0xBF
    GET_UUID = 0x62


class ProvisionerApp:
    def __init__(self, device: Nitrokey3Device) -> None:
        self.device = device

        try:
            self._call(ProvisionerCommand.GET_UUID)
        except Exception:
            raise RuntimeError("Provisioner application not available")

    def _call(
        self,
        command: ProvisionerCommand,
        response_len: Optional[int] = None,
        data: bytes = b"",
    ) -> bytes:
        return self.device._call(
            Command.PROVISIONER,
            response_len=response_len,
            data=command.value.to_bytes(1, "big") + data,
        )

    def _select(self, buffer: Buffer) -> None:
        self._call(ProvisionerCommand.SELECT, data=buffer.value, response_len=0)

    def _write_binary(self, data: bytes) -> None:
        self._call(ProvisionerCommand.WRITE_BINARY, data=data, response_len=0)

    def _write_file(self) -> None:
        self._call(ProvisionerCommand.WRITE_FILE, response_len=0)

    def write_file(self, filename: bytes, data: bytes) -> None:
        self._select(Buffer.FILENAME)
        self._write_binary(filename)
        self._select(Buffer.FILE)
        self._write_binary(data)
        self._write_file()
