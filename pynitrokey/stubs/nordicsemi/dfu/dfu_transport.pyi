# -*- coding: utf-8 -*-
#
# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import Callable

class DfuEvent:
    PROGRESS_EVENT: int

class DfuTransport:
    def open(self) -> None: ...
    def close(self) -> None: ...
    def send_init_packet(self, data: bytes) -> None: ...
    def send_firmware(self, data: bytes) -> None: ...
    def register_events_callback(
        self, event_type: int, callback: Callable[[int], None]
    ) -> None: ...
