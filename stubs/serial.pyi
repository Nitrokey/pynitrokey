# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from typing import Optional

class SerialException(IOError): ...

class Serial:
    def __init__(
        self,
        port: Optional[str] = None,
        baudrate: int = 9600,
        timeout: Optional[float] = None,
    ) -> None: ...
    def read(self, size: int) -> bytes: ...
    def close(self) -> None: ...
