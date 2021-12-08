# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import Any

from .client import ClientData
from .ctap2 import AttestationObject, AuthenticatorData

class AttestationConveyancePreference:
    NONE: str
    INDIRECT: str
    DIRECT: str

class AuthenticatorAttestationResponse:
    client_data: ClientData
    attestation_object: AttestationObject

class AuthenticatorAssertionResponse:
    client_data: ClientData
    authenticator_data: AuthenticatorData
    signature: bytes
    credential_id: int
