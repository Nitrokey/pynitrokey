#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Support for OSCCA SM2/SM3."""


from ..utils.misc import Endianness
from .. import SPSDK_DATA_FOLDER_COMMON

try:
    # this import is to find out whether OSCCA support is installed or not
    # pylint: disable=unused-import
    import gmssl

    IS_OSCCA_SUPPORTED = True
except ImportError:
    IS_OSCCA_SUPPORTED = False


if IS_OSCCA_SUPPORTED:
    import base64
    import os
    from typing import Any, NamedTuple, Optional, Type, TypeVar

    from ..exceptions import SPSDKError

    OSCCA_ASN_DEFINITION_FILE = os.path.join(SPSDK_DATA_FOLDER_COMMON, "crypto", "oscca.asn")
    SM2_OID = "1.2.156.10197.1.301"

    class SM2KeySet(NamedTuple):
        """Bare-bone representation of a SM2 Key."""

        private: str
        public: Optional[str]

    class SM2PublicKey(NamedTuple):
        """Bare-bone representation of a SM2 Public Key."""

        public: str

    _T = TypeVar("_T")

    def singleton(class_: Type[_T]) -> Type[_T]:
        """Decorator providing Singleton functionality for classes."""
        instances = {}

        def getinstance(*args: Any, **kwargs: Any) -> _T:
            # args/kwargs should be part of cache key
            if class_ not in instances:
                instances[class_] = class_(*args, **kwargs)
            return instances[class_]

        return getinstance  # type: ignore  # why are we even using Mypy?!

    @singleton
    class SM2Encoder:
        """ASN1 Encoder/Decoder for SM2 keys and signature."""

        def __init__(self, asn_file: str = OSCCA_ASN_DEFINITION_FILE) -> None:
            """Create ASN encoder/decoder based on provided ASN file."""
            try:
                import asn1tools
            except ImportError as import_error:
                raise SPSDKError(
                    "asn1tools package is missing, "
                    "please install it with pip install 'spsdk[oscca]' in order to use OSCCA"
                ) from import_error

            self.parser = asn1tools.compile_files(asn_file)

        def decode_private_key(self, data: bytes) -> SM2KeySet:
            """Parse private SM2 key set from binary data."""
            result = self.parser.decode("Private", data)
            key_set = self.parser.decode("KeySet", result["keyset"])
            return SM2KeySet(private=key_set["prk"].hex(), public=key_set["puk"][0][1:].hex())

        def decode_public_key(self, data: bytes) -> SM2PublicKey:
            """Parse public SM2 key set from binary data."""
            result = self.parser.decode("Public", data)
            return SM2PublicKey(public=result["puk"][0][1:].hex())

        def encode_private_key(self, keys: SM2KeySet) -> bytes:
            """Encode private SM2 key set from keyset."""
            assert isinstance(keys.public, str)
            puk_array = bytearray(bytes.fromhex(keys.public))
            puk_array[0:0] = b"\x04"  # 0x4 must be prepended
            puk = (puk_array, 520)  # tuple contains 520
            keyset = self.parser.encode(
                "KeySet",
                data={
                    "number": 1,
                    "prk": bytes.fromhex(keys.private),
                    "puk": puk,
                },
            )
            private_key = {"number": 0, "ids": [SM2_OID, SM2_OID], "keyset": keyset}
            return self.parser.encode("Private", data=private_key)

        def encode_public_key(self, key: SM2PublicKey) -> bytes:
            """Encode public SM2 key from SM2PublicKey."""
            puk_array = bytearray(bytes.fromhex(key.public))
            puk_array[0:0] = b"\x04"  # 0x4 must be prepended
            puk = (puk_array, 520)  # tuple contains 520
            data = {"ids": [SM2_OID, SM2_OID], "puk": puk}
            return self.parser.encode("Public", data=data)

        def decode_signature(self, data: bytes) -> bytes:
            """Decode BER signature into r||s coordinates."""
            result = self.parser.decode("Signature", data)
            r = int.to_bytes(result["r"], length=32, byteorder=Endianness.BIG.value)
            s = int.to_bytes(result["s"], length=32, byteorder=Endianness.BIG.value)
            return r + s

        def encode_signature(self, data: bytes) -> bytes:
            """Encode raw r||s signature into BER format."""
            if len(data) != 64:
                raise SPSDKError("SM2 signature must be 64B long.")
            r = int.from_bytes(data[:32], byteorder=Endianness.BIG.value)
            s = int.from_bytes(data[32:], byteorder=Endianness.BIG.value)
            ber_signature = self.parser.encode("Signature", data={"r": r, "s": s})
            return ber_signature

    def sanitize_pem(data: bytes) -> bytes:
        """Covert PEM data into DER."""
        if b"---" not in data:
            return data

        capture_data = False
        base64_data = b""
        for line in data.splitlines(keepends=False):
            if capture_data:
                base64_data += line
            # PEM data may contain EC PARAMS, thus capture trigger should be the word KEY
            if b"KEY" in line:
                capture_data = not capture_data
        # in the end the `capture_data` flag should be false singaling propper END * KEY
        # and we should have some data
        if capture_data is False and len(base64_data) > 0:
            der_data = base64.b64decode(base64_data)
            return der_data
        raise SPSDKError("PEM data are corrupted")
