#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for certificate management (generating certificate, validating certificate, chains)."""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.extensions import ExtensionNotFound
from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import PrivateKey, PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.crypto.types import (
    SPSDKEncoding,
    SPSDKExtensionOID,
    SPSDKExtensions,
    SPSDKName,
    SPSDKNameOID,
    SPSDKObjectIdentifier,
    SPSDKVersion,
)
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import align_block, load_binary, write_file


class SPSDKExtensionNotFoundError(SPSDKError, ExtensionNotFound):
    """Extension not found error."""


class Certificate(BaseClass):
    """SPSDK Certificate representation."""

    def __init__(self, certificate: x509.Certificate) -> None:
        """Constructor of SPSDK Certificate.

        :param certificate: Cryptography Certificate representation.
        """
        assert isinstance(certificate, x509.Certificate)
        self.cert = certificate

    @staticmethod
    def generate_certificate(
        subject: x509.Name,
        issuer: x509.Name,
        subject_public_key: PublicKey,
        issuer_private_key: PrivateKey,
        serial_number: Optional[int] = None,
        duration: Optional[int] = None,
        extensions: Optional[List[x509.ExtensionType]] = None,
    ) -> "Certificate":
        """Generate certificate.

        :param subject: subject name that the CA issues the certificate to
        :param issuer: issuer name that issued the certificate
        :param subject_public_key: Public key of subject
        :param issuer_private_key: Private key of issuer
        :param serial_number: certificate serial number, if not specified, random serial number will be set
        :param duration: how long the certificate will be valid (in days)
        :param extensions: List of extensions to include in the certificate
        :return: certificate
        """
        before = datetime.utcnow() if duration else datetime(2000, 1, 1)
        after = datetime.utcnow() + timedelta(days=duration) if duration else datetime(9999, 12, 31)
        crt = x509.CertificateBuilder(
            subject_name=subject,
            issuer_name=issuer,
            not_valid_before=before,
            not_valid_after=after,
            public_key=subject_public_key.key,
            # we don't pass extensions directly, need to handle the "critical" flag
            extensions=[],
            serial_number=serial_number or x509.random_serial_number(),
        )

        if extensions:
            for ext in extensions:
                crt = crt.add_extension(ext, critical=True)

        return Certificate(crt.sign(issuer_private_key.key, hashes.SHA256()))

    def save(
        self,
        file_path: str,
        encoding_type: SPSDKEncoding = SPSDKEncoding.PEM,
    ) -> None:
        """Save the certificate/CSR into file.

        :param file_path: path to the file where item will be stored
        :param encoding_type: encoding type (PEM or DER)
        """
        write_file(self.export(encoding_type), file_path, mode="wb")

    @classmethod
    def load(cls, file_path: str) -> Self:
        """Load the Certificate from the given file.

        :param file_path: path to the file, where the key is stored
        """
        data = load_binary(file_path)
        return cls.parse(data=data)

    def export(self, encoding: SPSDKEncoding = SPSDKEncoding.NXP) -> bytes:
        """Convert certificates into bytes.

        :param encoding: encoding type
        :return: certificate in bytes form
        """
        if encoding == SPSDKEncoding.NXP:
            return align_block(self.export(SPSDKEncoding.DER), 4, "zeros")

        return self.cert.public_bytes(SPSDKEncoding.get_cryptography_encodings(encoding))

    def get_public_key(self) -> PublicKey:
        """Get public keys from certificate.

        :return: RSA public key
        """
        pub_key = self.cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            return PublicKeyRsa(pub_key)
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            return PublicKeyEcc(pub_key)

        raise SPSDKError(f"Unsupported Certificate public key: {type(pub_key)}")

    @property
    def version(self) -> SPSDKVersion:
        """Returns the certificate version."""
        return self.cert.version

    @property
    def signature(self) -> bytes:
        """Returns the signature bytes."""
        return self.cert.signature

    @property
    def tbs_certificate_bytes(self) -> bytes:
        """Returns the tbsCertificate payload bytes as defined in RFC 5280."""
        return self.cert.tbs_certificate_bytes

    @property
    def signature_hash_algorithm(
        self,
    ) -> Optional[hashes.HashAlgorithm]:
        """Returns a HashAlgorithm corresponding to the type of the digest signed in the certificate."""
        return self.cert.signature_hash_algorithm

    @property
    def extensions(self) -> SPSDKExtensions:
        """Returns an Extensions object."""
        return self.cert.extensions

    @property
    def issuer(self) -> SPSDKName:
        """Returns the issuer name object."""
        return self.cert.issuer

    @property
    def serial_number(self) -> int:
        """Returns certificate serial number."""
        return self.cert.serial_number

    @property
    def subject(self) -> SPSDKName:
        """Returns the subject name object."""
        return self.cert.subject

    @property
    def signature_algorithm_oid(self) -> SPSDKObjectIdentifier:
        """Returns the ObjectIdentifier of the signature algorithm."""
        return self.cert.signature_algorithm_oid

    def validate_subject(self, subject_certificate: "Certificate") -> bool:
        """Validate certificate.

        :param subject_certificate: Subject's certificate
        :raises SPSDKError: Unsupported key type in Certificate
        :return: true/false whether certificate is valid or not
        """
        assert subject_certificate.signature_hash_algorithm
        return self.get_public_key().verify_signature(
            subject_certificate.signature,
            subject_certificate.tbs_certificate_bytes,
            EnumHashAlgorithm.from_label(subject_certificate.signature_hash_algorithm.name),
        )

    def validate(self, issuer_certificate: "Certificate") -> bool:
        """Validate certificate.

        :param issuer_certificate: Issuer's certificate
        :raises SPSDKError: Unsupported key type in Certificate
        :return: true/false whether certificate is valid or not
        """
        assert self.signature_hash_algorithm
        return issuer_certificate.get_public_key().verify_signature(
            self.signature,
            self.tbs_certificate_bytes,
            EnumHashAlgorithm.from_label(self.signature_hash_algorithm.name),
        )

    @property
    def ca(self) -> bool:
        """Check if CA flag is set in certificate.

        :return: true/false depending whether ca flag is set or not
        """
        extension = self.extensions.get_extension_for_oid(SPSDKExtensionOID.BASIC_CONSTRAINTS)
        return extension.value.ca  # type: ignore # mypy can not handle property definition in cryptography

    @property
    def self_signed(self) -> bool:
        """Indication whether the Certificate is self-signed."""
        return self.validate(self)

    @property
    def raw_size(self) -> int:
        """Raw size of the certificate."""
        return len(self.export())

    def public_key_hash(self, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256) -> bytes:
        """Get key hash.

        :param algorithm: Used hash algorithm, defaults to sha256
        :return: Key Hash
        """
        return self.get_public_key().key_hash(algorithm)

    def __repr__(self) -> str:
        """Text short representation about the Certificate."""
        return f"Certificate, SN:{hex(self.cert.serial_number)}"

    def __str__(self) -> str:
        """Text information about the Certificate."""
        not_valid_before = self.cert.not_valid_before.strftime("%d.%m.%Y (%H:%M:%S)")
        not_valid_after = self.cert.not_valid_after.strftime("%d.%m.%Y (%H:%M:%S)")
        nfo = ""
        nfo += f"  Certification Authority:    {'YES' if self.ca else 'NO'}\n"
        nfo += f"  Serial Number:              {hex(self.cert.serial_number)}\n"
        nfo += f"  Validity Range:             {not_valid_before} - {not_valid_after}\n"
        if self.signature_hash_algorithm:
            nfo += f"  Signature Algorithm:        {self.signature_hash_algorithm.name}\n"
        nfo += f"  Self Issued:                {'YES' if self.self_signed else 'NO'}\n"

        return nfo

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialize object from bytes array.

        :param data: Data to be parsed
        :returns: Recreated certificate
        """

        def load_der_certificate(data: bytes) -> x509.Certificate:
            """Load the DER certificate from bytes.

            This function is designed to eliminate cryptography exception
            when the padded data is provided.

            :param data: Data with DER certificate
            :return: Certificate (from cryptography library)
            :raises SPSDKError: Unsupported certificate to load
            """
            while True:
                try:
                    return x509.load_der_x509_certificate(data)
                except ValueError as exc:
                    if len(exc.args) and "kind: ExtraData" in exc.args[0] and data[-1:] == b"\00":
                        data = data[:-1]
                    else:
                        raise SPSDKValueError(str(exc)) from exc

        try:
            cert = {
                SPSDKEncoding.PEM: x509.load_pem_x509_certificate,
                SPSDKEncoding.DER: load_der_certificate,
            }[SPSDKEncoding.get_file_encodings(data)](
                data
            )  # type: ignore
            return Certificate(cert)  # type: ignore
        except ValueError as exc:
            raise SPSDKError(f"Cannot load certificate: ({str(exc)})") from exc


def validate_certificate_chain(chain_list: List[Certificate]) -> List[bool]:
    """Validate chain of certificates.

    :param chain_list: list of certificates in chain
    :return: list of boolean values, which corresponds to the certificate validation in chain
    :raises SPSDKError: When chain has less than two certificates
    """
    if len(chain_list) <= 1:
        raise SPSDKError("The chain must have at least two certificates")
    result = []
    for i in range(len(chain_list) - 1):
        result.append(chain_list[i].validate(chain_list[i + 1]))
    return result


def validate_ca_flag_in_cert_chain(chain_list: List[Certificate]) -> bool:
    """Validate CA flag in certification chain.

    :param chain_list: list of certificates in the chain
    :return: true/false depending whether ca flag is set or not
    """
    return chain_list[0].ca


X509NameConfig = Union[List[Dict[str, str]], Dict[str, Union[str, List[str]]]]


def generate_name(config: X509NameConfig) -> x509.Name:
    """Generate x509 Name.

    :param config: subject/issuer description
    :return: x509.Name
    """
    attributes: List[x509.NameAttribute] = []

    def _get_name_oid(name: str) -> x509.ObjectIdentifier:
        try:
            return getattr(SPSDKNameOID, name)
        except Exception as exc:
            raise SPSDKError(f"Invalid value of certificate attribute: {name}") from exc

    if isinstance(config, list):
        for item in config:
            for key, value in item.items():
                name_oid = _get_name_oid(key)
                attributes.append(x509.NameAttribute(name_oid, str(value)))

    if isinstance(config, dict):
        for key_second, value_second in config.items():
            name_oid = _get_name_oid(key_second)
            if isinstance(value_second, list):
                for value in value_second:
                    attributes.append(x509.NameAttribute(name_oid, str(value)))
            else:
                attributes.append(x509.NameAttribute(name_oid, str(value_second)))

    return x509.Name(attributes)


def generate_extensions(config: dict) -> List[x509.ExtensionType]:
    """Get x509 extensions out of config data."""
    extensions: List[x509.ExtensionType] = []

    for key, val in config.items():
        if key == "BASIC_CONSTRAINTS":
            ca = bool(val["ca"])
            extensions.append(
                x509.BasicConstraints(ca=ca, path_length=val.get("path_length") if ca else None)
            )
        if key == "WPC_QIAUTH_POLICY":
            extensions.append(WPCQiAuthPolicy(value=val["value"]))
        if key == "WPC_QIAUTH_RSID":
            extensions.append(WPCQiAuthRSID(value=val["value"]))
    return extensions


class WPCQiAuthPolicy(x509.UnrecognizedExtension):
    """WPC Qi Auth Policy x509 extension."""

    oid = x509.ObjectIdentifier("2.23.148.1.1")

    def __init__(self, value: int) -> None:
        """Initialize the extension with given policy number."""
        super().__init__(
            oid=self.oid,
            value=b"\x04\x04" + value.to_bytes(length=4, byteorder="big"),
        )


class WPCQiAuthRSID(x509.UnrecognizedExtension):
    """WPC Qi Auth RSID x509 extension."""

    oid = x509.ObjectIdentifier("2.23.148.1.2")

    def __init__(self, value: str) -> None:
        """Initialize the extension with given RSID in form of a hex-string."""
        super().__init__(
            oid=self.oid,
            value=b"\x04\x09" + bytes.fromhex(value).zfill(9),
        )
