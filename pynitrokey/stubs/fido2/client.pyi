# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import Optional

from .ctap import CtapDevice
from .webauthn import AuthenticatorAssertionResponse, AuthenticatorAttestationResponse

class Fido2Client:
    def __init__(self, device: CtapDevice, origin: str) -> None: ...
    def make_credential(
        self, options: dict, pin: Optional[str] = None
    ) -> AuthenticatorAttestationResponse: ...
    def get_assertion(
        self, options: dict, pin: Optional[str] = None
    ) -> Fido2ClientAssertionSelection: ...

class ClientData(bytes): ...
class ClientError(Exception): ...
class PinRequiredError(ClientError): ...

class Fido2ClientAssertionSelection:
    def get_response(self, idx: int) -> AuthenticatorAssertionResponse: ...
