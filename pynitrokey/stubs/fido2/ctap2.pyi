# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import Any, Dict

from fido2.hid import CtapHidDevice

class CTAP2:
    def __init__(self, device: CtapHidDevice, strict_cbor: bool = True): ...

class PinProtocolV1: ...

class AttestationObject(bytes):
    auth_data: AuthenticatorData
    att_statement: Dict[str, Any]

class AttestedCredentialData(bytes): ...

class AuthenticatorData(bytes):
    credential_data: AttestedCredentialData
