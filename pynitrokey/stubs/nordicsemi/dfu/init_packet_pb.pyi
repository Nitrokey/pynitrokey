# -*- coding: utf-8 -*-
#
# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import Optional

class Hash:
    hash: bytes

class Command:
    fw_version: int
    app_size: int
    hash: Hash

class SignedCommand:
    command: Command
    signature_type: str
    signature: str

class Packet:
    signed_command: Optional[SignedCommand]
    command: Optional[Command]

class InitPacketPB:
    packet: Packet
    init_command: Command
    def __init__(self, from_bytes: Optional[bytes]) -> None: ...
    def get_init_command_bytes(self) -> str: ...
