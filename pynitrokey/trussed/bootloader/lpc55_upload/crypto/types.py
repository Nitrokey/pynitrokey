#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Based crypto classes."""
from typing import Dict

from cryptography import utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.base import Version
from cryptography.x509.extensions import ExtensionOID, Extensions, KeyUsage
from cryptography.x509.name import Name, NameOID, ObjectIdentifier

from spsdk.exceptions import SPSDKError


class SPSDKEncoding(utils.Enum):
    """Extension of cryptography Encoders class."""

    NXP = "NXP"
    PEM = "PEM"
    DER = "DER"

    @staticmethod
    def get_cryptography_encodings(encoding: "SPSDKEncoding") -> Encoding:
        """Get Encoding in cryptography class."""
        cryptography_encoding = {
            SPSDKEncoding.PEM: Encoding.PEM,
            SPSDKEncoding.DER: Encoding.DER,
        }.get(encoding)
        if cryptography_encoding is None:
            raise SPSDKError(f"{encoding} format is not supported by cryptography.")
        return cryptography_encoding

    @staticmethod
    def get_file_encodings(data: bytes) -> "SPSDKEncoding":
        """Get the encoding type out of given item from the data.

        :param data: Already loaded data file to determine the encoding style
        :return: encoding type (Encoding.PEM, Encoding.DER)
        """
        encoding = SPSDKEncoding.PEM
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            encoding = SPSDKEncoding.DER
        else:
            if decoded.find("----") == -1:
                encoding = SPSDKEncoding.DER
        return encoding

    @staticmethod
    def all() -> Dict[str, "SPSDKEncoding"]:
        """Get all supported encodings."""
        return {"NXP": SPSDKEncoding.NXP, "PEM": SPSDKEncoding.PEM, "DER": SPSDKEncoding.DER}


SPSDKExtensions = Extensions
SPSDKExtensionOID = ExtensionOID
SPSDKNameOID = NameOID
SPSDKKeyUsage = KeyUsage
SPSDKName = Name
SPSDKVersion = Version
SPSDKObjectIdentifier = ObjectIdentifier
