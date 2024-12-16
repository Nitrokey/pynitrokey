from typing import Any, Iterable, Sequence

from .core import USBError as USBError

class Interface:
    interfaceClass: Any
    interfaceSubClass: Any
    interfaceNumber: Any
    interfaceProtocol: Any
    alternateSetting: Any

class Configuration:
    value: Any
    interfaces: Sequence[Sequence[Interface]]

class Device:
    filename: str
    idVendor: int
    idProduct: int
    configurations: Sequence[Configuration]

    def open(self) -> "DeviceHandle": ...

class DeviceHandle:
    def getString(self, index: int, length: int) -> bytes: ...
    def claimInterface(self, interface: Interface) -> None: ...
    def setAltInterface(self, alternate: Interface) -> None: ...
    def reset(self) -> None: ...
    def releaseInterface(self) -> None: ...
    def bulkRead(
        self, endpoint: int, size: int, timeout: int = 100
    ) -> Sequence[int]: ...
    def bulkWrite(
        self, endpoint: int, buffer: Sequence[int], timeout: int = 100
    ) -> int: ...

class Bus:
    devices: Sequence[Device]

def busses() -> Iterable[Bus]: ...
