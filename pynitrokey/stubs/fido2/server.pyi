# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional, Tuple

from .client import ClientData
from .ctap2 import AttestationObject, AttestedCredentialData, AuthenticatorData

class Fido2Server:
    def __init__(self, rp: dict, attestation: Optional[str] = None) -> None: ...
    def register_begin(
        self,
        user: dict,
        user_verification: Optional[str] = None,
        authenticator_attachment: Optional[str] = None,
    ) -> Tuple[dict, dict]: ...
    def register_complete(
        self,
        state: dict,
        client_data: ClientData,
        attestation_object: AttestationObject,
    ) -> AuthenticatorData: ...
    def authenticate_begin(
        self,
        credentials: List[AttestedCredentialData],
        user_verification: Optional[str] = None,
    ) -> Tuple[dict, dict]: ...
    def authenticate_complete(
        self,
        state: dict,
        credentials: List[AttestedCredentialData],
        credential_id: int,
        client_data: ClientData,
        auth_data: AuthenticatorData,
        signature: bytes,
    ) -> AttestedCredentialData: ...
