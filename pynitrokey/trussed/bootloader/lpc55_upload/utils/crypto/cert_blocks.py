#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for handling Certificate block."""

import datetime
import logging
import os
import re
from abc import abstractmethod
from struct import calcsize, pack, unpack_from
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Type, Union

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.crypto.certificate import Certificate
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PrivateKeyRsa, PublicKeyEcc
from spsdk.crypto.signature_provider import SignatureProvider, get_signature_provider
from spsdk.crypto.types import SPSDKEncoding
from spsdk.crypto.utils import extract_public_key, extract_public_key_from_data, get_matching_key_id
from spsdk.exceptions import (
    SPSDKError,
    SPSDKNotImplementedError,
    SPSDKTypeError,
    SPSDKUnsupportedOperation,
    SPSDKValueError,
)
from spsdk.utils.abstract import BaseClass
from spsdk.utils.crypto.rkht import RKHTv1, RKHTv21
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import (
    Endianness,
    align,
    align_block,
    change_endianness,
    find_file,
    load_binary,
    load_configuration,
    split_data,
    value_to_int,
    write_file,
)
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)


class CertBlock(BaseClass):
    """Common general class for various CertBlocks."""

    @classmethod
    @abstractmethod
    def get_supported_families(cls) -> List[str]:
        """Get supported families for certification block."""

    @classmethod
    @abstractmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
        """

    @staticmethod
    @abstractmethod
    def generate_config_template(family: Optional[str] = None) -> str:
        """Generate configuration for certification block."""

    @classmethod
    @abstractmethod
    def from_config(
        cls,
        config: Dict[str, Any],
        search_paths: Optional[List[str]] = None,
    ) -> Self:
        """Creates an instance of cert block from configuration."""

    @abstractmethod
    def create_config(self, data_path: str) -> str:
        """Create configuration of the Certification block Image."""

    @classmethod
    def get_cert_block_class(cls, family: str) -> Type["CertBlock"]:
        """Get certification block class by family name.

        :param family: Chip family
        :raises SPSDKError: No certification block class found for given family
        """
        for cert_block_class in cls.get_cert_block_classes():
            if family in cert_block_class.get_supported_families():
                return cert_block_class
        raise SPSDKError(f"Family '{family}' is not supported in any certification block.")

    @classmethod
    def get_all_supported_families(cls) -> List[str]:
        """Get supported families for all certification blocks except for SRK."""
        families = get_families(DatabaseManager.CERT_BLOCK)

        return [
            family
            for family in families
            if "srk" not in get_db(family, "latest").get_str(DatabaseManager.CERT_BLOCK, "rot_type")
        ]

    @classmethod
    def get_cert_block_classes(cls) -> List[Type["CertBlock"]]:
        """Get list of all cert block classes."""
        return CertBlock.__subclasses__()

    @property
    def rkth(self) -> bytes:
        """Root Key Table Hash 32-byte hash (SHA-256) of SHA-256 hashes of up to four root public keys."""
        return bytes()

    @classmethod
    def _get_supported_families(cls, cert_block_type: str) -> List[str]:
        """Get list of supported families.

        :param cert_block_type: Type of certification block to look for
        :return: List of devices that supports this cert block
        """
        families = cls.get_all_supported_families()

        return [
            family
            for family in families
            if get_db(family, "latest").get_str(DatabaseManager.CERT_BLOCK, "rot_type")
            == cert_block_type
        ]

    @classmethod
    def get_root_private_key_file(cls, config: Dict[str, Any]) -> Optional[str]:
        """Get main root private key file from config.

        :param config: Configuration to be searched.
        :return: Root private key file path.
        """
        private_key_file = config.get("signPrivateKey", config.get("mainRootCertPrivateKeyFile"))
        if private_key_file and not isinstance(private_key_file, str):
            raise SPSDKTypeError("Root private key file must be a string type")
        return private_key_file

    @classmethod
    def find_main_cert_index(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> Optional[int]:
        """Go through all certificates and find the index matching to private key.

        :param config: Configuration to be searched.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: List of root certificates.
        """
        try:
            signature_provider = get_signature_provider(
                sp_cfg=config.get("signProvider"),
                local_file_key=cls.get_root_private_key_file(config),
                search_paths=search_paths,
            )
        except SPSDKError as exc:
            logger.debug(f"A signature provider could not be created: {exc}")
            return None
        root_certificates = find_root_certificates(config)
        public_keys = []
        for root_crt_file in root_certificates:
            try:
                public_key = extract_public_key(root_crt_file, search_paths=search_paths)
                public_keys.append(public_key)
            except SPSDKError:
                continue
        try:
            idx = get_matching_key_id(public_keys, signature_provider)
            return idx
        except (SPSDKValueError, SPSDKUnsupportedOperation) as exc:
            logger.debug(f"Main cert index could not be found: {exc}")
            return None

    @classmethod
    def get_main_cert_index(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> int:
        """Gets main certificate index from configuration.

        :param config: Input standard configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Certificate index
        :raises SPSDKError: If invalid configuration is provided.
        :raises SPSDKError: If correct certificate could not be identified.
        :raises SPSDKValueError: If certificate is not of correct type.
        """
        root_cert_id = config.get("mainRootCertId")
        cert_chain_id = config.get("mainCertChainId")
        if root_cert_id is not None and cert_chain_id is not None and root_cert_id != cert_chain_id:
            raise SPSDKError(
                "The mainRootCertId and mainRootCertId are specified and have different values."
            )
        found_cert_id = cls.find_main_cert_index(config=config, search_paths=search_paths)
        if root_cert_id is None and cert_chain_id is None:
            if found_cert_id is not None:
                return found_cert_id
            raise SPSDKError("Certificate could not be found")
        # root_cert_id may be 0 which is falsy value, therefore 'or' cannot be used
        cert_id = root_cert_id if root_cert_id is not None else cert_chain_id
        try:
            cert_id = int(cert_id)
        except ValueError as exc:
            raise SPSDKValueError(f"A certificate index is not a number: {cert_id}") from exc
        if found_cert_id is not None and found_cert_id != cert_id:
            logger.warning("Defined certificate does not match the private key.")
        return cert_id


########################################################################################################################
# Certificate Block Header Class
########################################################################################################################
class CertBlockHeader(BaseClass):
    """Certificate block header."""

    FORMAT = "<4s2H6I"
    SIZE = calcsize(FORMAT)
    SIGNATURE = b"cert"

    def __init__(self, version: str = "1.0", flags: int = 0, build_number: int = 0) -> None:
        """Constructor.

        :param version: Version of the certificate in format n.n
        :param flags: Flags for the Certificate Header
        :param build_number: of the certificate
        :raises SPSDKError: When there is invalid version
        """
        if not re.match(r"[0-9]+\.[0-9]+", version):  # check format of the version: N.N
            raise SPSDKError("Invalid version")
        self.version = version
        self.flags = flags
        self.build_number = build_number
        self.image_length = 0
        self.cert_count = 0
        self.cert_table_length = 0

    def __repr__(self) -> str:
        nfo = f"CertBlockHeader: V={self.version}, F={self.flags}, BN={self.build_number}, IL={self.image_length}, "
        nfo += f"CC={self.cert_count}, CTL={self.cert_table_length}"
        return nfo

    def __str__(self) -> str:
        """Info of the certificate header in text form."""
        nfo = str()
        nfo += f" CB Version:           {self.version}\n"
        nfo += f" CB Flags:             {self.flags}\n"
        nfo += f" CB Build Number:      {self.build_number}\n"
        nfo += f" CB Image Length:      {self.image_length}\n"
        nfo += f" CB Cert. Count:       {self.cert_count}\n"
        nfo += f" CB Cert. Length:      {self.cert_table_length}\n"
        return nfo

    def export(self) -> bytes:
        """Certificate block in binary form."""
        major_version, minor_version = [int(v) for v in self.version.split(".")]
        return pack(
            self.FORMAT,
            self.SIGNATURE,
            major_version,
            minor_version,
            self.SIZE,
            self.flags,
            self.build_number,
            self.image_length,
            self.cert_count,
            self.cert_table_length,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialize object from bytes array.

        :param data: Input data as bytes
        :return: Certificate Header instance
        :raises SPSDKError: Unexpected size or signature of data
        """
        if cls.SIZE > len(data):
            raise SPSDKError("Incorrect size")
        (
            signature,
            major_version,
            minor_version,
            length,
            flags,
            build_number,
            image_length,
            cert_count,
            cert_table_length,
        ) = unpack_from(cls.FORMAT, data)
        if signature != cls.SIGNATURE:
            raise SPSDKError("Incorrect signature")
        if length != cls.SIZE:
            raise SPSDKError("Incorrect length")
        obj = cls(
            version=f"{major_version}.{minor_version}",
            flags=flags,
            build_number=build_number,
        )
        obj.image_length = image_length
        obj.cert_count = cert_count
        obj.cert_table_length = cert_table_length
        return obj


########################################################################################################################
# Certificate Block Class
########################################################################################################################
class CertBlockV1(CertBlock):
    """Certificate block.

    Shared for SB file 2.1 and for MasterBootImage using RSA keys.
    """

    # default size alignment
    DEFAULT_ALIGNMENT = 16

    @property
    def header(self) -> CertBlockHeader:
        """Certificate block header."""
        return self._header

    @property
    def rkh(self) -> List[bytes]:
        """List of root keys hashes (SHA-256), each hash as 32 bytes."""
        return self._rkht.rkh_list

    @property
    def rkth(self) -> bytes:
        """Root Key Table Hash 32-byte hash (SHA-256) of SHA-256 hashes of up to four root public keys."""
        return self._rkht.rkth()

    @property
    def rkth_fuses(self) -> List[int]:
        """List of RKHT fuses, ordered from highest bit to lowest.

        Note: Returned values are in format that should be passed for blhost
        """
        result = []
        rkht = self.rkth
        while rkht:
            fuse = int.from_bytes(rkht[:4], byteorder=Endianness.LITTLE.value)
            result.append(fuse)
            rkht = rkht[4:]
        return result

    @property
    def certificates(self) -> List[Certificate]:
        """List of certificates in header.

        First certificate is root certificate and followed by optional chain certificates
        """
        return self._cert

    @property
    def signature_size(self) -> int:
        """Size of the signature in bytes."""
        return len(
            self.certificates[0].signature
        )  # The certificate is self signed, return size of its signature

    @property
    def rkh_index(self) -> Optional[int]:
        """Index of the Root Key Hash that matches the certificate; None if does not match."""
        if self._cert:
            rkh = self._cert[0].public_key_hash()
            for index, value in enumerate(self.rkh):
                if rkh == value:
                    return index
        return None

    @property
    def alignment(self) -> int:
        """Alignment of the binary output, by default it is DEFAULT_ALIGNMENT but can be customized."""
        return self._alignment

    @alignment.setter
    def alignment(self, value: int) -> None:
        """Setter.

        :param value: new alignment
        :raises SPSDKError: When there is invalid alignment
        """
        if value <= 0:
            raise SPSDKError("Invalid alignment")
        self._alignment = value

    @property
    def raw_size(self) -> int:
        """Aligned size of the certificate block."""
        size = CertBlockHeader.SIZE
        size += self._header.cert_table_length
        size += self._rkht.RKH_SIZE * self._rkht.RKHT_SIZE
        return align(size, self.alignment)

    @property
    def expected_size(self) -> int:
        """Expected size of binary block."""
        return self.raw_size

    @property
    def image_length(self) -> int:
        """Image length in bytes."""
        return self._header.image_length

    @image_length.setter
    def image_length(self, value: int) -> None:
        """Setter.

        :param value: new image length
        :raises SPSDKError: When there is invalid image length
        """
        if value <= 0:
            raise SPSDKError("Invalid image length")
        self._header.image_length = value

    def __init__(self, version: str = "1.0", flags: int = 0, build_number: int = 0) -> None:
        """Constructor.

        :param version: of the certificate in format n.n
        :param flags: Flags for the Certificate Block Header
        :param build_number: of the certificate
        """
        self._header = CertBlockHeader(version, flags, build_number)
        self._rkht: RKHTv1 = RKHTv1([])
        self._cert: List[Certificate] = []
        self._alignment = self.DEFAULT_ALIGNMENT

    def __len__(self) -> int:
        return len(self._cert)

    def set_root_key_hash(self, index: int, key_hash: Union[bytes, bytearray, Certificate]) -> None:
        """Add Root Key Hash into RKHT.

        Note: Multiple root public keys are supported to allow for key revocation.

        :param index: The index of Root Key Hash in the table
        :param key_hash: The Root Key Hash value (32 bytes, SHA-256);
                        or Certificate where the hash can be created from public key
        :raises SPSDKError: When there is invalid index of root key hash in the table
        :raises SPSDKError: When there is invalid length of key hash
        """
        if isinstance(key_hash, Certificate):
            key_hash = get_hash(key_hash.get_public_key().export())
        assert isinstance(key_hash, (bytes, bytearray))
        if len(key_hash) != self._rkht.RKH_SIZE:
            raise SPSDKError("Invalid length of key hash")
        self._rkht.set_rkh(index, bytes(key_hash))

    def add_certificate(self, cert: Union[bytes, Certificate]) -> None:
        """Add certificate.

        First call adds root certificate. Additional calls add chain certificates.

        :param cert: The certificate itself in DER format
        :raises SPSDKError: If certificate cannot be added
        """
        if isinstance(cert, bytes):
            cert_obj = Certificate.parse(cert)
        elif isinstance(cert, Certificate):
            cert_obj = cert
        else:
            raise SPSDKError("Invalid parameter type (cert)")
        if cert_obj.version.name != "v3":
            raise SPSDKError("Expected certificate v3 but received: " + cert_obj.version.name)
        if self._cert:  # chain certificate?
            last_cert = self._cert[-1]  # verify that it is signed by parent key
            if not cert_obj.validate(last_cert):
                raise SPSDKError("Chain certificate cannot be verified using parent public key")
        else:  # root certificate
            if not cert_obj.self_signed:
                raise SPSDKError(f"Root certificate must be self-signed.\n{str(cert_obj)}")
        self._cert.append(cert_obj)
        self._header.cert_count += 1
        self._header.cert_table_length += cert_obj.raw_size + 4

    def __repr__(self) -> str:
        return str(self._header)

    def __str__(self) -> str:
        """Text info about certificate block."""
        nfo = str(self.header)
        nfo += " Public Root Keys Hash e.g. RKH (SHA256):\n"
        rkh_index = self.rkh_index
        for index, root_key in enumerate(self._rkht.rkh_list):
            nfo += (
                f"  {index}) {root_key.hex().upper()} {'<- Used' if index == rkh_index else ''}\n"
            )
        rkth = self.rkth
        nfo += f" RKTH (SHA256): {rkth.hex().upper()}\n"
        for index, fuse in enumerate(self.rkth_fuses):
            bit_ofs = (len(rkth) - 4 * index) * 8
            nfo += f"  - RKTH fuse [{bit_ofs:03}:{bit_ofs - 31:03}]: {fuse:08X}\n"
        for index, cert in enumerate(self._cert):
            nfo += " Root Certificate:\n" if index == 0 else f" Certificate {index}:\n"
            nfo += str(cert)
        return nfo

    def verify_data(self, signature: bytes, data: bytes) -> bool:
        """Signature verification.

        :param signature: to be verified
        :param data: that has been signed
        :return: True if the data signature can be confirmed using the certificate; False otherwise
        """
        cert = self._cert[-1]
        pub_key = cert.get_public_key()
        return pub_key.verify_signature(signature=signature, data=data)

    def verify_private_key(self, private_key: PrivateKeyRsa) -> bool:
        """Verify that given private key matches the public certificate.

        :param private_key: to be tested
        :return: True if yes; False otherwise
        """
        cert = self.certificates[-1]  # last certificate
        pub_key = cert.get_public_key()
        return private_key.verify_public_key(pub_key)

    def export(self) -> bytes:
        """Serialize Certificate Block V1 object."""
        # At least one certificate must be used
        if not self._cert:
            raise SPSDKError("At least one certificate must be used")
        # The hast of root key certificate must be in RKHT
        if self.rkh_index is None:
            raise SPSDKError("The HASH of used Root Key must be in RKHT")
        # CA: Using a single certificate is allowed. In this case, the sole certificate must be self-signed and must not
        # be a CA. If multiple certificates are used, the root must be self-signed and all but the last must be CAs.
        if self._cert[-1].ca:
            raise SPSDKError("The last chain certificate must not be CA.")
        if not all(cert.ca for cert in self._cert[:-1]):
            raise SPSDKError("All certificates except the last chain certificate must be CA")
        # Export
        data = self.header.export()
        for cert in self._cert:
            data += pack("<I", cert.raw_size)
            data += cert.export()
        data += self._rkht.export()
        data = align_block(data, self.alignment)
        if len(data) != self.raw_size:
            raise SPSDKError("Invalid length of data")
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialize CertBlockV1 from binary file.

        :param data: Binary data
        :return: Certificate Block instance
        :raises SPSDKError: Length of the data doesn't match Certificate Block length
        """
        header = CertBlockHeader.parse(data)
        offset = CertBlockHeader.SIZE
        if len(data) < (header.cert_table_length + (RKHTv1.RKHT_SIZE * RKHTv1.RKH_SIZE)):
            raise SPSDKError("Length of the data doesn't match Certificate Block length")
        obj = cls(version=header.version, flags=header.flags, build_number=header.build_number)
        for _ in range(header.cert_count):
            cert_len = unpack_from("<I", data, offset)[0]
            offset += 4
            cert_obj = Certificate.parse(data[offset : offset + cert_len])
            obj.add_certificate(cert_obj)
            offset += cert_len
        obj._rkht = RKHTv1.parse(data[offset : offset + (RKHTv1.RKH_SIZE * RKHTv1.RKHT_SIZE)])
        return obj

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.CERT_BLOCK)
        return [
            sch_cfg["certificate_v1"],
            sch_cfg["certificate_root_keys"],
        ]

    @staticmethod
    def generate_config_template(_family: Optional[str] = None) -> str:
        """Generate configuration for certification block v1."""
        val_schemas = CertBlockV1.get_validation_schemas()
        val_schemas.append(
            DatabaseManager().db.get_schema_file(DatabaseManager.CERT_BLOCK)["cert_block_output"]
        )
        return CommentedConfig("Certification Block V1 template", val_schemas).get_template()

    def create_config(self, data_path: str) -> str:
        """Create configuration of the Certification block Image."""
        cfg = self.get_config(data_path)
        val_schemas = CertBlockV1.get_validation_schemas()

        return CommentedConfig(
            main_title=(
                "Certification block v1 recreated configuration from :"
                f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}."
            ),
            schemas=val_schemas,
        ).get_config(cfg)

    @classmethod
    def get_root_private_key_file(cls, config: Dict[str, Any]) -> Optional[str]:
        """Get main root private key file from config.

        :param config: Configuration to be searched.
        :return: Root private key file path.
        """
        private_key_file = config.get("mainCertPrivateKeyFile")
        if private_key_file and not isinstance(private_key_file, str):
            raise SPSDKTypeError("Root private key file must be a string type")
        return private_key_file

    @classmethod
    def from_config(
        cls,
        config: Dict[str, Any],
        search_paths: Optional[List[str]] = None,
    ) -> "CertBlockV1":
        """Creates an instance of CertBlockV1 from configuration.

        :param config: Input standard configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of CertBlockV1
        :raises SPSDKError: Invalid certificates detected, Invalid configuration.
        """
        if not isinstance(config, Dict):
            raise SPSDKError("Configuration cannot be parsed")
        cert_block = config.get("certBlock")
        if cert_block:
            try:
                return cls.parse(load_binary(cert_block, search_paths))
            except (SPSDKError, TypeError):
                if search_paths:  # append path to cert block
                    search_paths.append(os.path.dirname(cert_block))
                else:
                    search_paths = [os.path.dirname(cert_block)]
                return cls.from_config(load_configuration(cert_block, search_paths), search_paths)

        image_build_number = value_to_int(config.get("imageBuildNumber", 0))
        root_certificates: List[List[str]] = [[] for _ in range(4)]
        # TODO we need to read the whole chain from the dict for a given
        # selection based on mainCertPrivateKeyFile!!!
        root_certificates[0].append(config.get("rootCertificate0File", None))
        root_certificates[1].append(config.get("rootCertificate1File", None))
        root_certificates[2].append(config.get("rootCertificate2File", None))
        root_certificates[3].append(config.get("rootCertificate3File", None))
        main_cert_chain_id = cls.get_main_cert_index(config, search_paths=search_paths)
        if root_certificates[main_cert_chain_id][0] is None:
            raise SPSDKError(f"A key rootCertificate{main_cert_chain_id}File must be defined")

        # get all certificate chain related keys from config
        pattern = f"chainCertificate{main_cert_chain_id}File[0-3]"
        keys = [key for key in config.keys() if re.fullmatch(pattern, key)]
        # just in case, sort the chain certificate keys in order
        keys.sort()
        for key in keys:
            root_certificates[main_cert_chain_id].append(config[key])

        cert_block = CertBlockV1(build_number=image_build_number)

        # add whole certificate chain used for image signing
        for cert_path in root_certificates[main_cert_chain_id]:
            cert_data = Certificate.load(
                find_file(str(cert_path), search_paths=search_paths)
            ).export(SPSDKEncoding.DER)
            cert_block.add_certificate(cert_data)
        # set root key hash of each root certificate
        empty_rec = False
        for cert_idx, cert_path_list in enumerate(root_certificates):
            if cert_path_list[0]:
                if empty_rec:
                    raise SPSDKError("There are gaps in rootCertificateXFile definition")
                cert_data = Certificate.load(
                    find_file(str(cert_path_list[0]), search_paths=search_paths)
                ).export(SPSDKEncoding.DER)
                cert_block.set_root_key_hash(cert_idx, Certificate.parse(cert_data))
            else:
                empty_rec = True

        return cert_block

    def get_config(self, output_folder: str) -> Dict[str, Any]:
        """Create configuration of Certificate V2 from object.

        :param output_folder: Output folder to store possible files.
        :return: Configuration dictionary.
        """

        def create_certificate_cfg(root_id: int, chain_id: int) -> Optional[str]:
            if len(self._cert) <= chain_id:
                return None

            file_name = f"certificate{root_id}_depth{chain_id}.der"
            self._cert[chain_id].save(os.path.join(output_folder, file_name))
            return file_name

        cfg: Dict[str, Optional[Union[str, int]]] = {}
        cfg["imageBuildNumber"] = self.header.build_number
        used_cert_id = self.rkh_index
        assert used_cert_id is not None
        cfg["mainRootCertId"] = used_cert_id

        cfg[f"rootCertificate{used_cert_id}File"] = create_certificate_cfg(used_cert_id, 0)
        for chain_ix in range(4):
            cfg[f"chainCertificate{used_cert_id}File{chain_ix}"] = create_certificate_cfg(
                used_cert_id, chain_ix + 1
            )

        return cfg

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Get list of supported families."""
        return super()._get_supported_families("cert_block_1")


########################################################################################################################
# Certificate Block Class for SB 3.1
########################################################################################################################


def convert_to_ecc_key(key: Union[PublicKeyEcc, bytes]) -> PublicKeyEcc:
    """Convert key into EccKey instance."""
    if isinstance(key, PublicKeyEcc):
        return key
    try:
        pub_key = extract_public_key_from_data(key)
        if not isinstance(pub_key, PublicKeyEcc):
            raise SPSDKError("Not ECC key")
        return pub_key
    except Exception:
        pass
    # Just recreate public key from the parsed data
    return PublicKeyEcc.parse(key)


class CertificateBlockHeader(BaseClass):
    """Create Certificate block header."""

    FORMAT = "<4s2HL"
    SIZE = calcsize(FORMAT)
    MAGIC = b"chdr"

    def __init__(self, format_version: str = "2.1") -> None:
        """Constructor for Certificate block header version 2.1.

        :param format_version: Major = 2, minor = 1
        """
        self.format_version = format_version
        self.cert_block_size = 0

    def export(self) -> bytes:
        """Export Certificate block header as bytes array."""
        major_format_version, minor_format_version = [
            int(v) for v in self.format_version.split(".")
        ]

        return pack(
            self.FORMAT,
            self.MAGIC,
            minor_format_version,
            major_format_version,
            self.cert_block_size,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Certificate block header from bytes array.

        :param data: Input data as bytes
        :raises SPSDKError: Raised when SIZE is bigger than length of the data without offset
        :raises SPSDKError: Raised when magic is not equal MAGIC
        :return: CertificateBlockHeader
        """
        if cls.SIZE > len(data):
            raise SPSDKError("SIZE is bigger than length of the data without offset")
        (
            magic,
            minor_format_version,
            major_format_version,
            cert_block_size,
        ) = unpack_from(cls.FORMAT, data)

        if magic != cls.MAGIC:
            raise SPSDKError("Magic is not same!")

        obj = cls(format_version=f"{major_format_version}.{minor_format_version}")
        obj.cert_block_size = cert_block_size
        return obj

    def __len__(self) -> int:
        """Length of the Certificate block header."""
        return calcsize(self.FORMAT)

    def __repr__(self) -> str:
        return f"Cert block header {self.format_version}"

    def __str__(self) -> str:
        """Get info of Certificate block header."""
        info = f"Format version:              {self.format_version}\n"
        info += f"Certificate block size:      {self.cert_block_size}\n"
        return info


class RootKeyRecord(BaseClass):
    """Create Root key record."""

    # P-256

    def __init__(
        self,
        ca_flag: bool,
        root_certs: Optional[Union[Sequence[PublicKeyEcc], Sequence[bytes]]] = None,
        used_root_cert: int = 0,
    ) -> None:
        """Constructor for Root key record.

        :param ca_flag: CA flag
        :param root_certs: Root cert used to ISK/image signature
        :param used_root_cert: Used root cert number 0-3
        """
        self.ca_flag = ca_flag
        self.root_certs_input = root_certs
        self.root_certs: List[PublicKeyEcc] = []
        self.used_root_cert = used_root_cert
        self.flags = 0
        self._rkht = RKHTv21([])
        self.root_public_key = b""

    @property
    def number_of_certificates(self) -> int:
        """Get number of included certificates."""
        return (self.flags & 0xF0) >> 4

    @property
    def expected_size(self) -> int:
        """Get expected binary block size."""
        # the '4' means 4 bytes for flags
        return 4 + len(self._rkht.export()) + len(self.root_public_key)

    def __repr__(self) -> str:
        cert_type = {0x1: "secp256r1", 0x2: "secp384r1"}[self.flags & 0xF]
        return f"Cert Block: Root Key Record - ({cert_type})"

    def __str__(self) -> str:
        """Get info of Root key record."""
        cert_type = {0x1: "secp256r1", 0x2: "secp384r1"}[self.flags & 0xF]
        info = ""
        info += f"Flags:           {hex(self.flags)}\n"
        info += f"  - CA:          {bool(self.ca_flag)}, ISK Certificate is {'not ' if self.ca_flag else ''}mandatory\n"
        info += f"  - Used Root c.:{self.used_root_cert}\n"
        info += f"  - Number of c.:{self.number_of_certificates}\n"
        info += f"  - Cert. type:  {cert_type}\n"
        if self.root_certs:
            info += f"Root certs:      {self.root_certs}\n"
        if self._rkht.rkh_list:
            info += f"CTRK Hash table: {self._rkht.export().hex()}\n"
        if self.root_public_key:
            info += f"Root public key: {str(convert_to_ecc_key(self.root_public_key))}\n"

        return info

    def _calculate_flags(self) -> int:
        """Function to calculate parameter flags."""
        flags = 0
        if self.ca_flag is True:
            flags |= 1 << 31
        if self.used_root_cert:
            flags |= self.used_root_cert << 8
        flags |= len(self.root_certs) << 4
        if self.root_certs[0].curve in ["NIST P-256", "p256", "secp256r1"]:
            flags |= 1 << 0
        if self.root_certs[0].curve in ["NIST P-384", "p384", "secp384r1"]:
            flags |= 1 << 1
        return flags

    def _create_root_public_key(self) -> bytes:
        """Function to create root public key."""
        root_key = self.root_certs[self.used_root_cert]
        root_key_data = root_key.export()
        return root_key_data

    def calculate(self) -> None:
        """Calculate all internal members.

        :raises SPSDKError: The RKHT certificates inputs are missing.
        """
        # pylint: disable=invalid-name
        if not self.root_certs_input:
            raise SPSDKError("Root Key Record: The root of trust certificates are not specified.")
        self.root_certs = [convert_to_ecc_key(cert) for cert in self.root_certs_input]
        self.flags = self._calculate_flags()
        self._rkht = RKHTv21.from_keys(keys=self.root_certs)
        if self._rkht.hash_algorithm != self.get_hash_algorithm(self.flags):
            raise SPSDKError("Hash algorithm does not match the key size.")
        self.root_public_key = self._create_root_public_key()

    def export(self) -> bytes:
        """Export Root key record as bytes array."""
        data = bytes()
        data += pack("<L", self.flags)
        data += self._rkht.export()
        data += self.root_public_key
        assert len(data) == self.expected_size
        return data

    @staticmethod
    def get_hash_algorithm(flags: int) -> EnumHashAlgorithm:
        """Get CTRK table hash algorithm.

        :param flags: Root Key Record flags
        :return: Name of hash algorithm
        """
        return {1: EnumHashAlgorithm.SHA256, 2: EnumHashAlgorithm.SHA384}[flags & 0xF]

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Root key record from bytes array.

        :param data:  Input data as bytes array
        :return: Root key record object
        """
        (flags,) = unpack_from("<L", data)
        ca_flag = flags & 0x80000000
        used_rot_ix = (flags & 0xF00) >> 8
        number_of_hashes = (flags & 0xF0) >> 4
        rotkh_len = {0x0: 32, 0x1: 32, 0x2: 48}[flags & 0xF]
        root_key_record = cls(ca_flag=ca_flag, root_certs=[], used_root_cert=used_rot_ix)
        root_key_record.flags = flags
        offset = 4  # move offset just after FLAGS
        if number_of_hashes > 1:
            rkht_len = rotkh_len * number_of_hashes
            rkht = data[offset : offset + rkht_len]
            offset += rkht_len
        root_key_record.root_public_key = data[offset : offset + rotkh_len * 2]
        root_key_record._rkht = (
            RKHTv21.parse(rkht, cls.get_hash_algorithm(flags))
            if number_of_hashes > 1
            else RKHTv21([get_hash(root_key_record.root_public_key, cls.get_hash_algorithm(flags))])
        )
        return root_key_record


class IskCertificate(BaseClass):
    """Create ISK certificate."""

    def __init__(
        self,
        constraints: int = 0,
        signature_provider: Optional[SignatureProvider] = None,
        isk_cert: Optional[Union[PublicKeyEcc, bytes]] = None,
        user_data: Optional[bytes] = None,
        offset_present: bool = True,
        family: Optional[str] = None,
    ) -> None:
        """Constructor for ISK certificate.

        :param constraints: Certificate version
        :param signature_provider: ISK Signature Provider
        :param isk_cert: ISK certificate
        :param user_data: User data
        """
        self.flags = 0
        self.offset_present = offset_present
        self.constraints = constraints
        self.signature_provider = signature_provider
        self.isk_cert = convert_to_ecc_key(isk_cert) if isk_cert else None
        self.user_data = user_data or bytes()
        if family:
            db = get_db(device=family)
            isk_data_limit = db.get_int(DatabaseManager.CERT_BLOCK, "isk_data_limit")
            if len(self.user_data) > isk_data_limit:
                raise SPSDKError(
                    f"ISK user data is too big ({len(self.user_data)} B). Max size is: {isk_data_limit} B."
                )
            isk_data_alignment = db.get_int(DatabaseManager.CERT_BLOCK, "isk_data_alignment")
            if len(self.user_data) % isk_data_alignment:
                raise SPSDKError(f"ISK user data is not aligned to {isk_data_alignment} B.")
        self.signature = bytes()
        self.coordinate_length = (
            self.signature_provider.signature_length // 2 if self.signature_provider else 0
        )
        self.isk_public_key_data = self.isk_cert.export() if self.isk_cert else bytes()

        self._calculate_flags()

    @property
    def signature_offset(self) -> int:
        """Signature offset inside the ISK Certificate."""
        offset = calcsize("<3L") if self.offset_present else calcsize("<2L")
        signature_offset = offset + len(self.user_data)
        if self.isk_cert:
            signature_offset += 2 * self.isk_cert.coordinate_size

        return signature_offset

    @property
    def expected_size(self) -> int:
        """Binary block expected size."""
        sign_len = len(self.signature) or (
            self.signature_provider.signature_length if self.signature_provider else 0
        )
        pub_key_len = (
            self.isk_cert.coordinate_size * 2 if self.isk_cert else len(self.isk_public_key_data)
        )

        offset = 4 if self.offset_present else 0
        return (
            offset  #  signature offset
            + 4  # constraints
            + 4  # flags
            + pub_key_len  # isk public key coordinates
            + len(self.user_data)  # user data
            + sign_len  # isk blob signature
        )

    def __repr__(self) -> str:
        isk_type = {0: "secp256r1", 1: "secp256r1", 2: "secp384r1"}[self.flags & 0xF]
        return f"ISK Certificate, {isk_type}"

    def __str__(self) -> str:
        """Get info about ISK certificate."""
        isk_type = {0: "secp256r1", 1: "secp256r1", 2: "secp384r1"}[self.flags & 0xF]
        info = ""
        info += f"Constraints:     {self.constraints}\n"
        info += f"Flags: {self.flags}\n"
        if self.user_data:
            info += f"User data:       {self.user_data.hex()}\n"
        else:
            info += "User data:       Not included\n"
        info += f"Type:            {isk_type}\n"
        info += f"Public Key:      {str(self.isk_cert)}\n"
        return info

    def _calculate_flags(self) -> None:
        """Function to calculate parameter flags."""
        self.flags = 0
        if self.user_data:
            self.flags |= 1 << 31
        assert self.isk_cert
        if self.isk_cert.curve == "secp256r1":
            self.flags |= 1 << 0
        if self.isk_cert.curve == "secp384r1":
            self.flags |= 1 << 1

    def create_isk_signature(self, key_record_data: bytes, force: bool = False) -> None:
        """Function to create ISK signature.

        :raises SPSDKError: Signature provider is not specified.
        """
        # pylint: disable=invalid-name
        if self.signature and not force:
            return
        if not self.signature_provider:
            raise SPSDKError("ISK Certificate: The signature provider is not specified.")
        if self.offset_present:
            data = key_record_data + pack(
                "<3L", self.signature_offset, self.constraints, self.flags
            )
        else:
            data = key_record_data + pack("<2L", self.constraints, self.flags)
        data += self.isk_public_key_data + self.user_data
        self.signature = self.signature_provider.get_signature(data)

    def export(self) -> bytes:
        """Export ISK certificate as bytes array."""
        if not self.signature:
            raise SPSDKError("Signature is not set.")
        if self.offset_present:
            data = pack("<3L", self.signature_offset, self.constraints, self.flags)
        else:
            data = pack("<2L", self.constraints, self.flags)
        data += self.isk_public_key_data
        if self.user_data:
            data += self.user_data
        data += self.signature

        assert len(data) == self.expected_size
        return data

    @classmethod
    def parse(cls, data: bytes, signature_size: int) -> Self:  # type: ignore # pylint: disable=arguments-differ
        """Parse ISK certificate from bytes array.This operation is not supported.

        :param data:  Input data as bytes array
        :param signature_size: The signature size of ISK block
        :raises NotImplementedError: This operation is not supported
        """
        (signature_offset, constraints, isk_flags) = unpack_from("<3L", data)
        header_word_cnt = 3
        if signature_offset & 0xFFFF == 0x4D43:  # This means that certificate has no offset
            (constraints, isk_flags) = unpack_from("<2L", data)
            signature_offset = 72
            header_word_cnt = 2
        user_data_flag = bool(isk_flags & 0x80000000)
        isk_pub_key_length = {0x0: 32, 0x1: 32, 0x2: 48}[isk_flags & 0xF]
        offset = header_word_cnt * 4
        isk_pub_key_bytes = data[offset : offset + isk_pub_key_length * 2]
        offset += isk_pub_key_length * 2
        user_data = data[offset:signature_offset] if user_data_flag else None
        signature = data[signature_offset : signature_offset + signature_size]
        offset_present = header_word_cnt == 3
        certificate = cls(
            constraints=constraints,
            isk_cert=isk_pub_key_bytes,
            user_data=user_data,
            offset_present=offset_present,
        )
        certificate.signature = signature
        return certificate


class IskCertificateLite(BaseClass):
    """ISK certificate lite."""

    MAGIC = 0x4D43
    VERSION = 1
    HEADER_FORMAT = "<HHI"
    ISK_PUB_KEY_LENGTH = 64
    ISK_SIGNATURE_SIZE = 64
    SIGNATURE_OFFSET = 72

    def __init__(
        self,
        pub_key: Union[PublicKeyEcc, bytes],
        constraints: int = 1,
    ) -> None:
        """Constructor for ISK certificate.

        :param pub_key: ISK public key
        :param constraints: 1 = self signed, 0 = nxp signed
        :param user_data: User data
        """
        self.constraints = constraints
        self.pub_key = convert_to_ecc_key(pub_key)
        self.signature = bytes()
        self.isk_public_key_data = self.pub_key.export()

    @property
    def expected_size(self) -> int:
        """Binary block expected size."""
        return (
            +4  # magic + version
            + 4  # constraints
            + self.ISK_PUB_KEY_LENGTH  # isk public key coordinates
            + self.ISK_SIGNATURE_SIZE  # isk blob signature
        )

    def __repr__(self) -> str:
        return "ISK Certificate lite"

    def __str__(self) -> str:
        """Get info about ISK certificate."""
        info = "ISK Certificate lite\n"
        info += f"Constraints:     {self.constraints}\n"
        info += f"Public Key:      {str(self.pub_key)}\n"
        return info

    def create_isk_signature(
        self, signature_provider: Optional[SignatureProvider], force: bool = False
    ) -> None:
        """Function to create ISK signature.

        :param signature_provider: Signature Provider
        :param force: Force resign.
        :raises SPSDKError: Signature provider is not specified.
        """
        # pylint: disable=invalid-name
        if self.signature and not force:
            return
        if not signature_provider:
            raise SPSDKError("ISK Certificate: The signature provider is not specified.")

        data = pack(self.HEADER_FORMAT, self.MAGIC, self.VERSION, self.constraints)
        data += self.isk_public_key_data
        self.signature = signature_provider.get_signature(data)

    def export(self) -> bytes:
        """Export ISK certificate as bytes array."""
        if not self.signature:
            raise SPSDKError("Signature is not set.")

        data = pack(self.HEADER_FORMAT, self.MAGIC, self.VERSION, self.constraints)
        data += self.isk_public_key_data
        data += self.signature

        assert len(data) == self.expected_size, "ISK Cert data size does not match"
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:  # pylint: disable=arguments-differ
        """Parse ISK certificate from bytes array.

        :param data:  Input data as bytes array
        :raises NotImplementedError: This operation is not supported
        """
        (_, _, constraints) = unpack_from(cls.HEADER_FORMAT, data)
        offset = calcsize(cls.HEADER_FORMAT)
        isk_pub_key_bytes = data[offset : offset + cls.ISK_PUB_KEY_LENGTH]
        offset += cls.ISK_PUB_KEY_LENGTH
        signature = data[offset : offset + cls.ISK_SIGNATURE_SIZE]
        certificate = cls(
            constraints=constraints,
            pub_key=isk_pub_key_bytes,
        )
        certificate.signature = signature
        return certificate


class CertBlockV21(CertBlock):
    """Create Certificate block version 2.1.

    Used for SB 3.1 and MBI using ECC keys.
    """

    MAGIC = b"chdr"
    FORMAT_VERSION = "2.1"

    def __init__(
        self,
        root_certs: Optional[Union[Sequence[PublicKeyEcc], Sequence[bytes]]] = None,
        ca_flag: bool = False,
        version: str = "2.1",
        used_root_cert: int = 0,
        constraints: int = 0,
        signature_provider: Optional[SignatureProvider] = None,
        isk_cert: Optional[Union[PublicKeyEcc, bytes]] = None,
        user_data: Optional[bytes] = None,
        family: Optional[str] = None,
    ) -> None:
        """The Constructor for Certificate block."""
        self.header = CertificateBlockHeader(version)
        self.root_key_record = RootKeyRecord(
            ca_flag=ca_flag, used_root_cert=used_root_cert, root_certs=root_certs
        )

        self.isk_certificate = None
        if not ca_flag and signature_provider and isk_cert:
            self.isk_certificate = IskCertificate(
                constraints=constraints,
                signature_provider=signature_provider,
                isk_cert=isk_cert,
                user_data=user_data,
                family=family,
            )

    def _set_ca_flag(self, value: bool) -> None:
        self.root_key_record.ca_flag = value

    def calculate(self) -> None:
        """Calculate all internal members."""
        self.root_key_record.calculate()

    @property
    def signature_size(self) -> int:
        """Size of the signature in bytes."""
        # signature size is same as public key data
        if self.isk_certificate:
            return len(self.isk_certificate.isk_public_key_data)

        return len(self.root_key_record.root_public_key)

    @property
    def expected_size(self) -> int:
        """Expected size of binary block."""
        expected_size = self.header.SIZE
        expected_size += self.root_key_record.expected_size
        if self.isk_certificate:
            expected_size += self.isk_certificate.expected_size
        return expected_size

    @property
    def rkth(self) -> bytes:
        """Root Key Table Hash 32-byte hash (SHA-256) of SHA-256 hashes of up to four root public keys."""
        return self.root_key_record._rkht.rkth()

    def __repr__(self) -> str:
        return f"Cert block 2.1, Size:{self.expected_size}B"

    def __str__(self) -> str:
        """Get info of Certificate block."""
        msg = f"HEADER:\n{str(self.header)}\n"
        msg += f"ROOT KEY RECORD:\n{str(self.root_key_record)}\n"
        if self.isk_certificate:
            msg += f"ISK Certificate:\n{str(self.isk_certificate)}\n"
        return msg

    def export(self) -> bytes:
        """Export Certificate block as bytes array."""
        key_record_data = self.root_key_record.export()
        self.header.cert_block_size = self.header.SIZE + len(key_record_data)
        isk_cert_data = bytes()
        if self.isk_certificate:
            self.isk_certificate.create_isk_signature(key_record_data)
            isk_cert_data = self.isk_certificate.export()
            self.header.cert_block_size += len(isk_cert_data)
        header_data = self.header.export()
        return header_data + key_record_data + isk_cert_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse Certificate block from bytes array.This operation is not supported.

        :param data:  Input data as bytes array
        :raises SPSDKError: Magic do not match
        """
        # CertificateBlockHeader
        cert_header = CertificateBlockHeader.parse(data)
        offset = len(cert_header)
        # RootKeyRecord
        root_key_record = RootKeyRecord.parse(data[offset:])
        offset += root_key_record.expected_size
        # IskCertificate
        isk_certificate = None
        if root_key_record.ca_flag == 0:
            isk_certificate = IskCertificate.parse(
                data[offset:], len(root_key_record.root_public_key)
            )
        # Certification Block V2.1
        cert_block = cls()
        cert_block.header = cert_header
        cert_block.root_key_record = root_key_record
        cert_block.isk_certificate = isk_certificate
        return cert_block

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.CERT_BLOCK)
        return [sch_cfg["certificate_v21"], sch_cfg["certificate_root_keys"]]

    @classmethod
    def from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "CertBlockV21":
        """Creates an instance of CertBlockV21 from configuration.

        :param config: Input standard configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of CertBlockV21
        :raises SPSDKError: If found gap in certificates from config file. Invalid configuration.
        """
        if not isinstance(config, Dict):
            raise SPSDKError("Configuration cannot be parsed")
        cert_block = config.get("certBlock")
        if cert_block:
            try:
                return cls.parse(load_binary(cert_block, search_paths))
            except (SPSDKError, TypeError):
                if search_paths:  # append path to cert block
                    search_paths.append(os.path.dirname(cert_block))
                else:
                    search_paths = [os.path.dirname(cert_block)]
                cert_block_data = load_configuration(cert_block, search_paths)
                # temporarily pass-down family to cert-block config data
                cert_block_data["family"] = config["family"]
                return cls.from_config(cert_block_data, search_paths)

        root_certificates = find_root_certificates(config)
        main_root_cert_id = cls.get_main_cert_index(config, search_paths=search_paths)

        try:
            root_certificates[main_root_cert_id]
        except IndexError as e:
            raise SPSDKError(
                f"Main root certificate with id {main_root_cert_id} does not exist"
            ) from e

        root_certs = [
            load_binary(cert_file, search_paths=search_paths) for cert_file in root_certificates
        ]

        user_data = None
        signature_provider = None
        isk_cert = None

        use_isk = config.get("useIsk", False)
        if use_isk:
            signature_provider_config = config.get("signProvider")
            signature_provider = get_signature_provider(
                signature_provider_config,
                cls.get_root_private_key_file(config),
                search_paths=search_paths,
            )

            isk_public_key = config.get("iskPublicKey", config.get("signingCertificateFile"))
            isk_cert = load_binary(isk_public_key, search_paths=search_paths)

            isk_sign_data_path = config.get("iskCertData", config.get("signCertData"))
            if isk_sign_data_path:
                user_data = load_binary(isk_sign_data_path, search_paths=search_paths)

        isk_constraint = value_to_int(
            config.get("iskCertificateConstraint", config.get("signingCertificateConstraint", "0"))
        )
        family = config.get("family")
        cert_block = cls(
            root_certs=root_certs,
            used_root_cert=main_root_cert_id,
            user_data=user_data,
            constraints=isk_constraint,
            isk_cert=isk_cert,
            ca_flag=not use_isk,
            signature_provider=signature_provider,
            family=family,
        )
        cert_block.calculate()

        return cert_block

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of certification block class members.
        """
        self.header.parse(self.header.export())
        if self.isk_certificate and not self.isk_certificate.signature:
            if not isinstance(self.isk_certificate.signature_provider, SignatureProvider):
                raise SPSDKError("Invalid ISK certificate.")

    @staticmethod
    def generate_config_template(family: Optional[str] = None) -> str:
        """Generate configuration for certification block v21."""
        val_schemas = CertBlockV21.get_validation_schemas()
        val_schemas.append(
            DatabaseManager().db.get_schema_file(DatabaseManager.CERT_BLOCK)["cert_block_output"]
        )

        if family:
            # find family
            for schema in val_schemas:
                if "properties" in schema and "family" in schema["properties"]:
                    schema["properties"]["family"]["template_value"] = family
                    break
        return CommentedConfig("Certification Block V21 template", val_schemas).get_template()

    def get_config(self, output_folder: str) -> Dict[str, Any]:
        """Create configuration dictionary of the Certification block Image.

        :param output_folder: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg: Dict[str, Optional[Union[str, int]]] = {}
        cfg["mainRootCertPrivateKeyFile"] = "N/A"
        cfg["signingCertificatePrivateKeyFile"] = "N/A"
        for i in range(self.root_key_record.number_of_certificates):
            key: Optional[PublicKeyEcc] = None
            if i == self.root_key_record.used_root_cert:
                key = convert_to_ecc_key(self.root_key_record.root_public_key)
            else:
                if i < len(self.root_key_record.root_certs) and self.root_key_record.root_certs[i]:
                    key = convert_to_ecc_key(self.root_key_record.root_certs[i])
            if key:
                key_file_name = os.path.join(output_folder, f"rootCertificate{i}File.pub")
                key.save(key_file_name)
                cfg[f"rootCertificate{i}File"] = f"rootCertificate{i}File.pub"
            else:
                cfg[
                    f"rootCertificate{i}File"
                ] = "The public key is not possible reconstruct from the key hash"

        cfg["mainRootCertId"] = self.root_key_record.used_root_cert
        if self.isk_certificate and self.root_key_record.ca_flag == 0:
            cfg["useIsk"] = True
            assert self.isk_certificate.isk_cert
            key = self.isk_certificate.isk_cert
            key_file_name = os.path.join(output_folder, "signingCertificateFile.pub")
            key.save(key_file_name)
            cfg["signingCertificateFile"] = "signingCertificateFile.pub"
            cfg["signingCertificateConstraint"] = self.isk_certificate.constraints
            if self.isk_certificate.user_data:
                key_file_name = os.path.join(output_folder, "isk_user_data.bin")
                write_file(self.isk_certificate.user_data, key_file_name, mode="wb")
                cfg["signCertData"] = "isk_user_data.bin"

        else:
            cfg["useIsk"] = False

        return cfg

    def create_config(self, data_path: str) -> str:
        """Create configuration of the Certification block Image.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration in string.
        """
        cfg = self.get_config(data_path)
        val_schemas = CertBlockV21.get_validation_schemas()

        return CommentedConfig(
            main_title=(
                "Certification block v2.1 recreated configuration from :"
                f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}."
            ),
            schemas=val_schemas,
        ).get_config(cfg)

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Get list of supported families."""
        return super()._get_supported_families("cert_block_21")


########################################################################################################################
# Certificate Block Class for SB X
########################################################################################################################


########################################################################################################################
# Certificate Block Class for SB X
########################################################################################################################


class CertBlockVx(CertBlock):
    """Create Certificate block for MC56xx."""

    ISK_CERT_LENGTH = 136
    ISK_CERT_HASH_LENGTH = 16  # [0:127]

    def __init__(
        self,
        isk_cert: Union[PublicKeyEcc, bytes],
        signature_provider: Optional[SignatureProvider] = None,
        self_signed: bool = True,
    ) -> None:
        """The Constructor for Certificate block."""
        self.isk_cert_hash = bytes(self.ISK_CERT_HASH_LENGTH)
        self.isk_certificate = IskCertificateLite(pub_key=isk_cert, constraints=int(self_signed))
        self.signature_provider = signature_provider

    @property
    def expected_size(self) -> int:
        """Expected size of binary block."""
        return self.isk_certificate.expected_size

    @property
    def cert_hash(self) -> bytes:
        """Calculate first half [:127] of certificate hash."""
        isk_cert_data = self.isk_certificate.export()
        return get_hash(isk_cert_data)[: self.ISK_CERT_HASH_LENGTH]

    def __repr__(self) -> str:
        return "CertificateBlockVx"

    def __str__(self) -> str:
        """Get info about Certificate block."""
        msg = "Certificate block version x\n"
        msg += f"ISK Certificate:\n{str(self.isk_certificate)}\n"
        msg += f"Certificate hash: {self.cert_hash.hex()}"
        return msg

    def export(self) -> bytes:
        """Export Certificate block as bytes array."""
        isk_cert_data = bytes()
        self.isk_certificate.create_isk_signature(self.signature_provider)
        isk_cert_data = self.isk_certificate.export()
        return isk_cert_data

    @classmethod
    def parse(cls, data: bytes) -> "Self":
        """Parse Certificate block from bytes array.This operation is not supported.

        :param data:  Input data as bytes array
        :raises SPSDKValueError: In case of inval
        """
        # IskCertificate
        isk_certificate = IskCertificateLite.parse(data)
        cert_block = cls(
            isk_cert=isk_certificate.isk_public_key_data,
            self_signed=bool(isk_certificate.constraints),
        )
        cert_block.isk_certificate.signature = isk_certificate.signature
        return cert_block

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.CERT_BLOCK)
        return [sch_cfg["certificate_vx"]]

    def create_config(self, data_path: str) -> str:
        """Create configuration of the Certification block Image."""
        raise SPSDKNotImplementedError("Parsing of Cert Block Vx is not supported")

    @classmethod
    def from_config(
        cls, config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "CertBlockVx":
        """Creates an instance of CertBlockVx from configuration.

        :param config: Input standard configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: CertBlockVx
        :raises SPSDKError: If found gap in certificates from config file. Invalid configuration.
        """
        if not isinstance(config, Dict):
            raise SPSDKError("Configuration cannot be parsed")
        cert_block = config.get("certBlock")
        if cert_block:
            try:
                return cls.parse(load_binary(cert_block, search_paths))
            except Exception:
                return cls.from_config(load_configuration(cert_block, search_paths), search_paths)

        main_root_private_key_file = cls.get_root_private_key_file(config)
        signature_provider = config.get("signProvider", config.get("iskSignProvider"))
        isk_certificate = config.get("iskPublicKey", config.get("signingCertificateFile"))

        signature_provider = get_signature_provider(
            signature_provider,
            main_root_private_key_file,
            search_paths=search_paths,
        )
        isk_cert = load_binary(isk_certificate, search_paths=search_paths)
        self_signed = config.get("selfSigned", True)
        cert_block = cls(
            signature_provider=signature_provider,
            isk_cert=isk_cert,
            self_signed=self_signed,
        )

        return cert_block

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of certification block class members.
        """
        if self.isk_certificate and not self.isk_certificate.signature:
            if not isinstance(self.signature_provider, SignatureProvider):
                raise SPSDKError("Invalid ISK certificate.")

    @staticmethod
    def generate_config_template(_family: Optional[str] = None) -> str:
        """Generate configuration for certification block vX."""
        val_schemas = CertBlockVx.get_validation_schemas()
        val_schemas.append(
            DatabaseManager().db.get_schema_file(DatabaseManager.CERT_BLOCK)["cert_block_output"]
        )
        return CommentedConfig("Certification Block Vx template", val_schemas).get_template()

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Get list of supported families."""
        return super()._get_supported_families("cert_block_x")

    def get_otp_script(self) -> str:
        """Return script for writing certificate hash to OTP.

        :return: string value of blhost script
        """
        ret = (
            "# BLHOST Cert Block Vx fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# ISK Cert hash [0:127]: {self.cert_hash.hex()} \n\n"
        )

        fuse_value = change_endianness(self.cert_hash)
        fuse_idx = 12  # Fuse start IDX
        for fuse_data in split_data(fuse_value, 4):
            ret += f"flash-program-once {hex(fuse_idx)} 4 {fuse_data.hex()}\n"
            fuse_idx += 1

        return ret


def find_root_certificates(config: Dict[str, Any]) -> List[str]:
    """Find all root certificates in configuration.

    :param config: Configuration to be searched.
    :raises SPSDKError: If invalid configuration is provided.
    :return: List of root certificates.
    """
    root_certificates_loaded: List[Optional[str]] = [
        config.get(f"rootCertificate{idx}File") for idx in range(4)
    ]
    # filter out None and empty values
    root_certificates = list(filter(None, root_certificates_loaded))
    for org, filtered in zip(root_certificates_loaded, root_certificates):
        if org != filtered:
            raise SPSDKError("There are gaps in rootCertificateXFile definition")
    return root_certificates


def get_keys_or_rotkh_from_certblock_config(
    rot: Optional[str], family: Optional[str]
) -> Tuple[Optional[Iterable[str]], Optional[bytes]]:
    """Get keys or ROTKH value from ROT config.

    ROT config might be cert block config or MBI config.
    There are four cases how cert block might be configured.

    1. MBI with certBlock property pointing to YAML file
    2. MBI with certBlock property pointing to BIN file
    3. YAML configuration of cert block
    4. Binary cert block

    :param rot: Path to ROT configuration (MBI or cert block)
        or path to binary cert block
    :param family: MCU family
    :raises SPSDKError: In case the ROTKH or keys cannot be parsed
    :return: Tuple containing root of trust (list of paths to keys)
        or ROTKH in case of binary cert block
    """
    root_of_trust = None
    rotkh = None
    if rot and family:
        logger.info("Loading configuration from cert block/MBI file...")
        config_dir = os.path.dirname(rot)
        try:
            config_data = load_configuration(rot, search_paths=[config_dir])
            if "certBlock" in config_data:
                try:
                    config_data = load_configuration(
                        config_data["certBlock"], search_paths=[config_dir]
                    )
                except SPSDKError:
                    cert_block = load_binary(config_data["certBlock"], search_paths=[config_dir])
                    parsed_cert_block = CertBlock.get_cert_block_class(family).parse(cert_block)
                    rotkh = parsed_cert_block.rkth
            public_keys = find_root_certificates(config_data)
            root_of_trust = tuple((find_file(x, search_paths=[config_dir]) for x in public_keys))
        except SPSDKError:
            logger.debug("Parsing ROT from config did not succeed, trying it as binary")
            try:
                cert_block = load_binary(rot, search_paths=[config_dir])
                parsed_cert_block = CertBlock.get_cert_block_class(family).parse(cert_block)
                rotkh = parsed_cert_block.rkth
            except SPSDKError as e:
                raise SPSDKError(f"Parsing of binary cert block failed with {e}") from e

    return root_of_trust, rotkh
