from .core import USBError as USBError

class Device:
    filename: str

    def open(self) -> "DeviceHandle": ...

class DeviceHandle:
    def getString(self, index: int, length: int) -> bytes: ...
