#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""ASN1Crypto implementation for CMS signature container."""


# Used security modules
from datetime import datetime
from typing import Optional

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import ECDSASignature, PrivateKey, PrivateKeyEcc, PrivateKeyRsa
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.crypto.types import SPSDKEncoding
from spsdk.exceptions import SPSDKError, SPSDKTypeError, SPSDKValueError


def cms_sign(
    zulu: datetime,
    data: bytes,
    certificate: Certificate,
    signing_key: Optional[PrivateKey],
    signature_provider: Optional[SignatureProvider],
) -> bytes:
    """Sign provided data and return CMS signature.

    :param zulu: current UTC time+date
    :param data: to be signed
    :param certificate: Certificate with issuer information
    :param signing_key: Signing key, is mutually exclusive with signature_provider parameter
    :param signature_provider: Signature provider, is mutually exclusive with signing_key parameter
    :return: CMS signature (binary)
    :raises SPSDKError: If certificate is not present
    :raises SPSDKError: If private key is not present
    :raises SPSDKError: If incorrect time-zone"
    """
    # Lazy imports are used here to save some time during SPSDK startup
    from asn1crypto import cms, util, x509

    if certificate is None:
        raise SPSDKValueError("Certificate is not present")
    if not (signing_key or signature_provider):
        raise SPSDKValueError("Private key or signature provider is not present")
    if signing_key and signature_provider:
        raise SPSDKValueError("Only one of private key and signature provider must be specified")
    if signing_key and not isinstance(signing_key, (PrivateKeyEcc, PrivateKeyRsa)):
        raise SPSDKTypeError(f"Unsupported private key type {type(signing_key)}.")

    # signed data (main section)
    signed_data = cms.SignedData()
    signed_data["version"] = "v1"
    signed_data["encap_content_info"] = util.OrderedDict([("content_type", "data")])
    signed_data["digest_algorithms"] = [
        util.OrderedDict([("algorithm", "sha256"), ("parameters", None)])
    ]

    # signer info sub-section
    signer_info = cms.SignerInfo()
    signer_info["version"] = "v1"
    signer_info["digest_algorithm"] = util.OrderedDict(
        [("algorithm", "sha256"), ("parameters", None)]
    )
    signer_info["signature_algorithm"] = (
        util.OrderedDict([("algorithm", "rsassa_pkcs1v15"), ("parameters", b"")])
        if (signing_key and isinstance(signing_key, PrivateKeyRsa))
        or (signature_provider and signature_provider.signature_length >= 256)
        else util.OrderedDict([("algorithm", "sha256_ecdsa")])
    )
    # signed identifier: issuer amd serial number

    asn1_cert = x509.Certificate.load(certificate.export(SPSDKEncoding.DER))
    signer_info["sid"] = cms.SignerIdentifier(
        {
            "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                {
                    "issuer": asn1_cert.issuer,
                    "serial_number": asn1_cert.serial_number,
                }
            )
        }
    )
    # signed attributes
    signed_attrs = cms.CMSAttributes()
    signed_attrs.append(
        cms.CMSAttribute(
            {
                "type": "content_type",
                "values": [cms.ContentType("data")],
            }
        )
    )

    # check time-zone is assigned (expected UTC+0)
    if not zulu.tzinfo:
        raise SPSDKError("Incorrect time-zone")
    signed_attrs.append(
        cms.CMSAttribute(
            {
                "type": "signing_time",
                "values": [cms.Time(name="utc_time", value=zulu.strftime("%y%m%d%H%M%SZ"))],
            }
        )
    )
    signed_attrs.append(
        cms.CMSAttribute(
            {
                "type": "message_digest",
                "values": [cms.OctetString(get_hash(data))],  # digest
            }
        )
    )
    signer_info["signed_attrs"] = signed_attrs

    # create signature
    data_to_sign = signed_attrs.dump()
    signature = sign_data(data_to_sign, signing_key, signature_provider)

    signer_info["signature"] = signature
    # Adding SignerInfo object to SignedData object
    signed_data["signer_infos"] = [signer_info]

    # content info
    content_info = cms.ContentInfo()
    content_info["content_type"] = "signed_data"
    content_info["content"] = signed_data

    return content_info.dump()


def sign_data(
    data_to_sign: bytes,
    signing_key: Optional[PrivateKey],
    signature_provider: Optional[SignatureProvider],
) -> bytes:
    """Sign the data.

    :param data_to_sign: Data to be signed
    :param signing_key: Signing key, is mutually exclusive with signature_provider parameter
    :param signature_provider: Signature provider, is mutually exclusive with signing_key parameter
    """
    assert signing_key or signature_provider
    if signing_key and signature_provider:
        raise SPSDKValueError("Only one of private key and signature provider must be specified")
    if signing_key:
        return (
            signing_key.sign(data_to_sign, algorithm=EnumHashAlgorithm.SHA256, der_format=True)
            if isinstance(signing_key, PrivateKeyEcc)
            else signing_key.sign(data_to_sign)
        )
    assert signature_provider
    signature = signature_provider.get_signature(data_to_sign)
    # convert to DER format
    if signature_provider.signature_length < 256:
        ecdsa_signature = ECDSASignature.parse(signature)
        signature = ecdsa_signature.export(encoding=SPSDKEncoding.DER)
    return signature
