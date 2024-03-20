#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Boot Image V2.0, V2.1."""

import logging
import os
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

from typing_extensions import Self

from ...crypto.certificate import Certificate
from ...crypto.hash import EnumHashAlgorithm, get_hash
from ...crypto.hmac import hmac
from ...crypto.rng import random_bytes
from ...crypto.signature_provider import (
    SignatureProvider,
    get_signature_provider,
    try_to_verify_public_key,
)
from ...crypto.symmetric import Counter, aes_key_unwrap, aes_key_wrap
from ...exceptions import SPSDKError
from ...sbfile.misc import SecBootBlckSize
from ...sbfile.sb2.sb_21_helper import SB21Helper
from ...utils.abstract import BaseClass
from ...utils.crypto.cert_blocks import CertBlockV1
from ...utils.database import DatabaseManager, get_db, get_families, get_schema_file
from ...utils.misc import (
    find_first,
    load_configuration,
    load_hex_string,
    load_text,
    value_to_int,
    write_file,
)
from ...utils.schema_validator import CommentedConfig, check_config

from . import sly_bd_parser as bd_parser
from .commands import CmdHeader
from .headers import ImageHeaderV2
from .sections import BootSectionV2, CertSectionV2

logger = logging.getLogger(__name__)


class SBV2xAdvancedParams:
    """The class holds advanced parameters for the SB file encryption.

    These parameters are used for the tests; for production, use can use default values (random keys + current time)
    """

    @staticmethod
    def _create_nonce() -> bytes:
        """Return random nonce."""
        nonce = bytearray(random_bytes(16))
        # clear nonce bit at offsets 31 and 63
        nonce[9] &= 0x7F
        nonce[13] &= 0x7F
        return bytes(nonce)

    def __init__(
        self,
        dek: Optional[bytes] = None,
        mac: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        timestamp: Optional[datetime] = None,
    ):
        """Initialize SBV2xAdvancedParams.

        :param dek: DEK key
        :param mac: MAC key
        :param nonce: nonce
        :param timestamp: fixed timestamp for the header; use None to use current date/time
        :raises SPSDKError: Invalid dek or mac
        :raises SPSDKError: Invalid length of nonce
        """
        self._dek: bytes = dek if dek else random_bytes(32)
        self._mac: bytes = mac if mac else random_bytes(32)
        self._nonce: bytes = nonce if nonce else SBV2xAdvancedParams._create_nonce()
        if timestamp is None:
            timestamp = datetime.now()
        self._timestamp = datetime.fromtimestamp(int(timestamp.timestamp()))
        if len(self._dek) != 32 and len(self._mac) != 32:
            raise SPSDKError("Invalid dek or mac")
        if len(self._nonce) != 16:
            raise SPSDKError("Invalid length of nonce")

    @property
    def dek(self) -> bytes:
        """Return DEK key."""
        return self._dek

    @property
    def mac(self) -> bytes:
        """Return MAC key."""
        return self._mac

    @property
    def nonce(self) -> bytes:
        """Return NONCE."""
        return self._nonce

    @property
    def timestamp(self) -> datetime:
        """Return timestamp."""
        return self._timestamp


########################################################################################################################
# Secure Boot Image Class (Version 2.0)
########################################################################################################################
class BootImageV20(BaseClass):
    """Boot Image V2.0 class."""

    # Image specific data
    # size of the MAC key
    HEADER_MAC_SIZE = 32
    # AES encrypted DEK and MAC, including padding
    DEK_MAC_SIZE = 32 + 32 + 16

    KEY_BLOB_SIZE = 80

    def __init__(
        self,
        signed: bool,
        kek: bytes,
        *sections: BootSectionV2,
        product_version: str = "1.0.0",
        component_version: str = "1.0.0",
        build_number: int = 0,
        advanced_params: SBV2xAdvancedParams = SBV2xAdvancedParams(),
    ) -> None:
        """Initialize Secure Boot Image V2.0.

        :param signed: True if image is signed, False otherwise
        :param kek: key for wrapping DEK and MAC keys
        :param product_version: The product version (default: 1.0.0)
        :param component_version: The component version (default: 1.0.0)
        :param build_number: The build number value (default: 0)
        :param advanced_params: Advanced parameters for encryption of the SB file, use for tests only
        :param sections: Boot sections
        :raises SPSDKError: Invalid dek or mac
        """
        self._kek = kek
        # Set Flags value
        self._signed = signed
        self.signature_provider: Optional[SignatureProvider] = None
        flags = 0x08 if self.signed else 0x04
        # Set private attributes
        self._dek: bytes = advanced_params.dek
        self._mac: bytes = advanced_params.mac
        if (
            len(self._dek) != self.HEADER_MAC_SIZE and len(self._mac) != self.HEADER_MAC_SIZE
        ):  # pragma: no cover # condition checked in SBV2xAdvancedParams constructor
            raise SPSDKError("Invalid dek or mac")
        self._header = ImageHeaderV2(
            version="2.0",
            product_version=product_version,
            component_version=component_version,
            build_number=build_number,
            flags=flags,
            nonce=advanced_params.nonce,
            timestamp=advanced_params.timestamp,
        )
        self._cert_section: Optional[CertSectionV2] = None
        self._boot_sections: List[BootSectionV2] = []
        # Generate nonce
        if self._header.nonce is None:
            nonce = bytearray(random_bytes(16))
            # clear nonce bit at offsets 31 and 63
            nonce[9] &= 0x7F
            nonce[13] &= 0x7F
            self._header.nonce = bytes(nonce)
        # Sections
        for section in sections:
            self.add_boot_section(section)

    @property
    def header(self) -> ImageHeaderV2:
        """Return image header."""
        return self._header

    @property
    def dek(self) -> bytes:
        """Data encryption key."""
        return self._dek

    @property
    def mac(self) -> bytes:
        """Message authentication code."""
        return self._mac

    @property
    def kek(self) -> bytes:
        """Return key for wrapping DEK and MAC keys."""
        return self._kek

    @property
    def signed(self) -> bool:
        """Check whether sb is signed + encrypted or only encrypted."""
        return self._signed

    @property
    def cert_block(self) -> Optional[CertBlockV1]:
        """Return certificate block; None if SB file not signed or block not assigned yet."""
        cert_sect = self._cert_section
        if cert_sect is None:
            return None

        return cert_sect.cert_block

    @cert_block.setter
    def cert_block(self, value: Optional[CertBlockV1]) -> None:
        """Setter.

        :param value: block to be assigned; None to remove previously assigned block
        :raises SPSDKError: When certificate block is used when SB file is not signed
        """
        if value is not None:
            if not self.signed:
                raise SPSDKError("Certificate block cannot be used unless SB file is signed")
        self._cert_section = CertSectionV2(value) if value else None

    @property
    def cert_header_size(self) -> int:
        """Return image raw size (not aligned) for certificate header."""
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
        for boot_section in self._boot_sections:
            size += boot_section.raw_size
        return size

    @property
    def raw_size_without_signature(self) -> int:
        """Return image raw size without signature, used to calculate image blocks."""
        # Header, HMAC and KeyBlob
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
        # Certificates Section
        if self.signed:
            size += self.DEK_MAC_SIZE
            cert_block = self.cert_block
            if not cert_block:
                raise SPSDKError("Certification block not present")
            size += cert_block.raw_size
        # Boot Sections
        for boot_section in self._boot_sections:
            size += boot_section.raw_size
        return size

    @property
    def raw_size(self) -> int:
        """Return image raw size."""
        size = self.raw_size_without_signature

        if self.signed:
            cert_block = self.cert_block
            if not cert_block:  # pragma: no cover # already checked in raw_size_without_signature
                raise SPSDKError("Certificate block not present")
            size += cert_block.signature_size

        return size

    def __len__(self) -> int:
        return len(self._boot_sections)

    def __getitem__(self, key: int) -> BootSectionV2:
        return self._boot_sections[key]

    def __setitem__(self, key: int, value: BootSectionV2) -> None:
        self._boot_sections[key] = value

    def __iter__(self) -> Iterator[BootSectionV2]:
        return self._boot_sections.__iter__()

    def update(self) -> None:
        """Update boot image."""
        if self._boot_sections:
            self._header.first_boot_section_id = self._boot_sections[0].uid
            # calculate first boot tag block
            data_size = self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
            if self._cert_section is not None:
                data_size += self._cert_section.raw_size
            self._header.first_boot_tag_block = SecBootBlckSize.to_num_blocks(data_size)
        # ...
        self._header.flags = 0x08 if self.signed else 0x04
        self._header.image_blocks = SecBootBlckSize.to_num_blocks(self.raw_size_without_signature)
        self._header.header_blocks = SecBootBlckSize.to_num_blocks(self._header.SIZE)
        self._header.max_section_mac_count = 0
        if self.signed:
            self._header.offset_to_certificate_block = (
                self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
            )
            self._header.offset_to_certificate_block += CmdHeader.SIZE + CertSectionV2.HMAC_SIZE * 2
            self._header.max_section_mac_count = 1
        for boot_sect in self._boot_sections:
            boot_sect.is_last = True  # this is unified with elftosb
            self._header.max_section_mac_count += boot_sect.hmac_count
        # Update certificates block header
        cert_blk = self.cert_block
        if cert_blk is not None:
            cert_blk.header.build_number = self._header.build_number
            cert_blk.header.image_length = self.cert_header_size

    def __repr__(self) -> str:
        return f"SB2.0, {'Signed' if self.signed else 'Plain'} "

    def __str__(self) -> str:
        """Return text description of the instance."""
        self.update()
        nfo = "\n"
        nfo += ":::::::::::::::::::::::::::::::::: IMAGE HEADER ::::::::::::::::::::::::::::::::::::::\n"
        nfo += str(self._header)
        if self._cert_section is not None:
            nfo += "::::::::::::::::::::::::::::::: CERTIFICATES BLOCK ::::::::::::::::::::::::::::::::::::\n"
            nfo += str(self._cert_section)
        nfo += "::::::::::::::::::::::::::::::::::: BOOT SECTIONS ::::::::::::::::::::::::::::::::::::\n"
        for index, section in enumerate(self._boot_sections):
            nfo += f"[ SECTION: {index} | UID: 0x{section.uid:08X} ]\n"
            nfo += str(section)
        return nfo

    def add_boot_section(self, section: BootSectionV2) -> None:
        """Add new Boot section into image.

        :param section: Boot section
        :raises SPSDKError: Raised when section is not instance of BootSectionV2 class
        :raises SPSDKError: Raised when boot section has duplicate UID
        """
        if not isinstance(section, BootSectionV2):
            raise SPSDKError("Section is not instance of BootSectionV2 class")
        duplicate_uid = find_first(self._boot_sections, lambda bs: bs.uid == section.uid)
        if duplicate_uid is not None:
            raise SPSDKError(f"Boot section with duplicate UID: {str(section.uid)}")
        self._boot_sections.append(section)

    def export(self, padding: Optional[bytes] = None) -> bytes:
        """Serialize image object.

        :param padding: header padding (8 bytes) for testing purpose; None to use random values (recommended)
        :return: exported bytes
        :raises SPSDKError: Raised when there are no boot sections or is not signed or private keys are missing
        :raises SPSDKError: Raised when there is invalid dek or mac
        :raises SPSDKError: Raised when certificate data is not present
        :raises SPSDKError: Raised when there is invalid certificate block
        :raises SPSDKError: Raised when there is invalid length of exported data
        """
        if len(self.dek) != 32 or len(self.mac) != 32:
            raise SPSDKError("Invalid dek or mac")
        # validate params
        if not self._boot_sections:
            raise SPSDKError("No boot section")
        if self.signed and (self._cert_section is None):
            raise SPSDKError("Certificate section is required for signed images")
        # update internals
        self.update()
        # Add Image Header data
        data = self._header.export(padding=padding)
        # Add Image Header HMAC data
        data += hmac(self.mac, data)
        # Add DEK and MAC keys
        data += aes_key_wrap(self.kek, self.dek + self.mac)
        # Add Padding
        data += padding if padding else random_bytes(8)
        # Add Certificates data
        if not self._header.nonce:
            raise SPSDKError("There is no nonce in the header")
        counter = Counter(self._header.nonce)
        counter.increment(SecBootBlckSize.to_num_blocks(len(data)))
        if self._cert_section is not None:
            cert_sect_bin = self._cert_section.export(dek=self.dek, mac=self.mac, counter=counter)
            counter.increment(SecBootBlckSize.to_num_blocks(len(cert_sect_bin)))
            data += cert_sect_bin
        # Add Boot Sections data
        for sect in self._boot_sections:
            data += sect.export(dek=self.dek, mac=self.mac, counter=counter)
        # Add Signature data
        if self.signed:
            if self.signature_provider is None:
                raise SPSDKError("Signature provider is not assigned, cannot sign the image.")
            if self.cert_block is None:
                raise SPSDKError("Certificate block is not assigned.")

            public_key = self.cert_block.certificates[-1].get_public_key()
            try_to_verify_public_key(self.signature_provider, public_key.export())
            data += self.signature_provider.get_signature(data)

        if len(data) != self.raw_size:
            raise SPSDKError("Invalid length of exported data")
        return data

    # pylint: disable=too-many-locals
    @classmethod
    def parse(cls, data: bytes, kek: bytes = bytes()) -> Self:
        """Parse image from bytes.

        :param data: Raw data of parsed image
        :param kek: The Key for unwrapping DEK and MAC keys (required)
        :return: parsed image object
        :raises SPSDKError: raised when header is in wrong format
        :raises SPSDKError: raised when there is invalid header version
        :raises SPSDKError: raised when signature is incorrect
        :raises SPSDKError: Raised when kek is empty
        :raises SPSDKError: raised when header's nonce is not present
        """
        if not kek:
            raise SPSDKError("kek cannot be empty")
        index = 0
        header_raw_data = data[index : index + ImageHeaderV2.SIZE]
        index += ImageHeaderV2.SIZE
        header_mac_data = data[index : index + cls.HEADER_MAC_SIZE]
        index += cls.HEADER_MAC_SIZE
        key_blob = data[index : index + cls.KEY_BLOB_SIZE]
        index += cls.KEY_BLOB_SIZE
        key_blob_unwrap = aes_key_unwrap(kek, key_blob[:-8])
        dek = key_blob_unwrap[:32]
        mac = key_blob_unwrap[32:]
        header_mac_data_calc = hmac(mac, header_raw_data)
        if header_mac_data != header_mac_data_calc:
            raise SPSDKError("Invalid header MAC data")
        # Parse Header
        header = ImageHeaderV2.parse(header_raw_data)
        if header.version != "2.0":
            raise SPSDKError(f"Invalid Header Version: {header.version} instead 2.0")
        image_size = header.image_blocks * 16
        # Initialize counter
        if not header.nonce:
            raise SPSDKError("Header's nonce not present")
        counter = Counter(header.nonce)
        counter.increment(SecBootBlckSize.to_num_blocks(index))
        # ...
        signed = header.flags == 0x08
        adv_params = SBV2xAdvancedParams(
            dek=dek, mac=mac, nonce=header.nonce, timestamp=header.timestamp
        )
        obj = cls(
            signed,
            kek=kek,
            product_version=str(header.product_version),
            component_version=str(header.component_version),
            build_number=header.build_number,
            advanced_params=adv_params,
        )
        # Parse Certificate section
        if header.flags == 0x08:
            cert_sect = CertSectionV2.parse(data, index, dek=dek, mac=mac, counter=counter)
            obj._cert_section = cert_sect
            index += cert_sect.raw_size
            # Check Signature
            if not cert_sect.cert_block.verify_data(data[image_size:], data[:image_size]):
                raise SPSDKError("Parsing Certification section failed")
        # Parse Boot Sections
        while index < (image_size):
            boot_section = BootSectionV2.parse(data, index, dek=dek, mac=mac, counter=counter)
            obj.add_boot_section(boot_section)
            index += boot_section.raw_size
        return obj


########################################################################################################################
# Secure Boot Image Class (Version 2.1)
########################################################################################################################
class BootImageV21(BaseClass):
    """Boot Image V2.1 class."""

    # Image specific data
    HEADER_MAC_SIZE = 32
    KEY_BLOB_SIZE = 80
    SHA_256_SIZE = 32

    # defines
    FLAGS_SHA_PRESENT_BIT = 0x8000  # image contains SHA-256
    FLAGS_ENCRYPTED_SIGNED_BIT = 0x0008  # image is signed and encrypted

    def __init__(
        self,
        kek: bytes,
        *sections: BootSectionV2,
        product_version: str = "1.0.0",
        component_version: str = "1.0.0",
        build_number: int = 0,
        advanced_params: SBV2xAdvancedParams = SBV2xAdvancedParams(),
        flags: int = FLAGS_SHA_PRESENT_BIT | FLAGS_ENCRYPTED_SIGNED_BIT,
    ) -> None:
        """Initialize Secure Boot Image V2.1.

        :param kek: key to wrap DEC and MAC keys

        :param product_version: The product version (default: 1.0.0)
        :param component_version: The component version (default: 1.0.0)
        :param build_number: The build number value (default: 0)

        :param advanced_params: optional advanced parameters for encryption; it is recommended to use default value
        :param flags: see flags defined in class.
        :param sections: Boot sections
        """
        self._kek = kek
        self.signature_provider: Optional[
            SignatureProvider
        ] = None  # this should be assigned for export, not needed for parsing
        self._dek = advanced_params.dek
        self._mac = advanced_params.mac
        self._header = ImageHeaderV2(
            version="2.1",
            product_version=product_version,
            component_version=component_version,
            build_number=build_number,
            flags=flags,
            nonce=advanced_params.nonce,
            timestamp=advanced_params.timestamp,
        )
        self._cert_block: Optional[CertBlockV1] = None
        self.boot_sections: List[BootSectionV2] = []
        # ...
        for section in sections:
            self.add_boot_section(section)

    @property
    def header(self) -> ImageHeaderV2:
        """Return image header."""
        return self._header

    @property
    def dek(self) -> bytes:
        """Data encryption key."""
        return self._dek

    @property
    def mac(self) -> bytes:
        """Message authentication code."""
        return self._mac

    @property
    def kek(self) -> bytes:
        """Return key to wrap DEC and MAC keys."""
        return self._kek

    @property
    def cert_block(self) -> Optional[CertBlockV1]:
        """Return certificate block; None if SB file not signed or block not assigned yet."""
        return self._cert_block

    @cert_block.setter
    def cert_block(self, value: CertBlockV1) -> None:
        """Setter.

        :param value: block to be assigned; None to remove previously assigned block
        """
        assert isinstance(value, CertBlockV1)
        self._cert_block = value
        self._cert_block.alignment = 16

    @property
    def signed(self) -> bool:
        """Return flag whether SB file is signed."""
        return True  # SB2.1 is always signed

    @property
    def cert_header_size(self) -> int:
        """Return image raw size (not aligned) for certificate header."""
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE
        size += self.KEY_BLOB_SIZE
        # Certificates Section
        cert_blk = self.cert_block
        if cert_blk:
            size += cert_blk.raw_size
        return size

    @property
    def raw_size(self) -> int:
        """Return image raw size (not aligned)."""
        # Header, HMAC and KeyBlob
        size = ImageHeaderV2.SIZE + self.HEADER_MAC_SIZE
        size += self.KEY_BLOB_SIZE
        # Certificates Section
        cert_blk = self.cert_block
        if cert_blk:
            size += cert_blk.raw_size
            if not self.signed:  # pragma: no cover # SB2.1 is always signed
                raise SPSDKError("Certificate block is not signed")
            size += cert_blk.signature_size
        # Boot Sections
        for boot_section in self.boot_sections:
            size += boot_section.raw_size
        return size

    def __len__(self) -> int:
        return len(self.boot_sections)

    def __getitem__(self, key: int) -> BootSectionV2:
        return self.boot_sections[key]

    def __setitem__(self, key: int, value: BootSectionV2) -> None:
        self.boot_sections[key] = value

    def __iter__(self) -> Iterator[BootSectionV2]:
        return self.boot_sections.__iter__()

    def update(self) -> None:
        """Update BootImageV21."""
        if self.boot_sections:
            self._header.first_boot_section_id = self.boot_sections[0].uid
            # calculate first boot tag block
            data_size = self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
            cert_blk = self.cert_block
            if cert_blk is not None:
                data_size += cert_blk.raw_size
                if not self.signed:  # pragma: no cover # SB2.1 is always signed
                    raise SPSDKError("Certificate block is not signed")
                data_size += cert_blk.signature_size
            self._header.first_boot_tag_block = SecBootBlckSize.to_num_blocks(data_size)
        # ...
        self._header.image_blocks = SecBootBlckSize.to_num_blocks(self.raw_size)
        self._header.header_blocks = SecBootBlckSize.to_num_blocks(self._header.SIZE)
        self._header.offset_to_certificate_block = (
            self._header.SIZE + self.HEADER_MAC_SIZE + self.KEY_BLOB_SIZE
        )
        # Get HMAC count
        self._header.max_section_mac_count = 0
        for boot_sect in self.boot_sections:
            boot_sect.is_last = True  # unified with elftosb
            self._header.max_section_mac_count += boot_sect.hmac_count
        # Update certificates block header
        cert_clk = self.cert_block
        if cert_clk is not None:
            cert_clk.header.build_number = self._header.build_number
            cert_clk.header.image_length = self.cert_header_size

    def __repr__(self) -> str:
        return f"SB2.1, {'Signed' if self.signed else 'Plain'} "

    def __str__(self) -> str:
        """Return text description of the instance."""
        self.update()
        nfo = "\n"
        nfo += ":::::::::::::::::::::::::::::::::: IMAGE HEADER ::::::::::::::::::::::::::::::::::::::\n"
        nfo += str(self._header)
        if self.cert_block is not None:
            nfo += "::::::::::::::::::::::::::::::: CERTIFICATES BLOCK ::::::::::::::::::::::::::::::::::::\n"
            nfo += str(self.cert_block)
        nfo += "::::::::::::::::::::::::::::::::::: BOOT SECTIONS ::::::::::::::::::::::::::::::::::::\n"
        for index, section in enumerate(self.boot_sections):
            nfo += f"[ SECTION: {index} | UID: 0x{section.uid:08X} ]\n"
            nfo += str(section)
        return nfo

    def add_boot_section(self, section: BootSectionV2) -> None:
        """Add new Boot section into image.

        :param section: Boot section to be added
        :raises SPSDKError: Raised when section is not instance of BootSectionV2 class
        """
        if not isinstance(section, BootSectionV2):
            raise SPSDKError("Section is not instance of BootSectionV2 class")
        self.boot_sections.append(section)

    # pylint: disable=too-many-locals
    def export(self, padding: Optional[bytes] = None) -> bytes:
        """Serialize image object.

        :param padding: header padding (8 bytes) for testing purpose; None to use random values (recommended)
        :return: exported bytes
        :raises SPSDKError: Raised when there is no boot section to be added
        :raises SPSDKError: Raised when certificate is not assigned
        :raises SPSDKError: Raised when private key is not assigned
        :raises SPSDKError: Raised when private header's nonce is invalid
        :raises SPSDKError: Raised when private key does not match certificate
        :raises SPSDKError: Raised when there is no debug info
        """
        # validate params
        if not self.boot_sections:
            raise SPSDKError("At least one Boot Section must be added")
        if self.cert_block is None:
            raise SPSDKError("Certificate is not assigned")
        if self.signature_provider is None:
            raise SPSDKError("Signature provider is not assigned, cannot sign the image")
        # Update internals
        self.update()
        # Export Boot Sections
        bs_data = bytes()
        bs_offset = (
            ImageHeaderV2.SIZE
            + self.HEADER_MAC_SIZE
            + self.KEY_BLOB_SIZE
            + self.cert_block.raw_size
            + self.cert_block.signature_size
        )
        if self.header.flags & self.FLAGS_SHA_PRESENT_BIT:
            bs_offset += self.SHA_256_SIZE

        if not self._header.nonce:
            raise SPSDKError("Invalid header's nonce")
        counter = Counter(self._header.nonce, SecBootBlckSize.to_num_blocks(bs_offset))
        for sect in self.boot_sections:
            bs_data += sect.export(dek=self.dek, mac=self.mac, counter=counter)
        # Export Header
        signed_data = self._header.export(padding=padding)
        #  Add HMAC data
        first_bs_hmac_count = self.boot_sections[0].hmac_count
        hmac_data = bs_data[CmdHeader.SIZE : CmdHeader.SIZE + (first_bs_hmac_count * 32) + 32]
        hmac_bytes = hmac(self.mac, hmac_data)
        signed_data += hmac_bytes
        # Add KeyBlob data
        key_blob = aes_key_wrap(self.kek, self.dek + self.mac)
        key_blob += b"\00" * (self.KEY_BLOB_SIZE - len(key_blob))
        signed_data += key_blob
        # Add Certificates data
        signed_data += self.cert_block.export()
        # Add SHA-256 of Bootable sections if requested
        if self.header.flags & self.FLAGS_SHA_PRESENT_BIT:
            signed_data += get_hash(bs_data)
        # Add Signature data
        signature = self.signature_provider.get_signature(signed_data)

        return signed_data + signature + bs_data

    # pylint: disable=too-many-locals
    @classmethod
    def parse(
        cls,
        data: bytes,
        offset: int = 0,
        kek: bytes = bytes(),
        plain_sections: bool = False,
    ) -> "BootImageV21":
        """Parse image from bytes.

        :param data: Raw data of parsed image
        :param offset: The offset of input data
        :param kek: The Key for unwrapping DEK and MAC keys (required)
        :param plain_sections: Sections are not encrypted; this is used only for debugging,
            not supported by ROM code
        :return: BootImageV21 parsed object
        :raises SPSDKError: raised when header is in incorrect format
        :raises SPSDKError: raised when signature is incorrect
        :raises SPSDKError: Raised when kek is empty
        :raises SPSDKError: raised when header's nonce not present"
        """
        if not kek:
            raise SPSDKError("kek cannot be empty")
        index = offset
        header_raw_data = data[index : index + ImageHeaderV2.SIZE]
        index += ImageHeaderV2.SIZE
        # Not used right now: hmac_data = data[index: index + cls.HEADER_MAC_SIZE]
        index += cls.HEADER_MAC_SIZE
        key_blob = data[index : index + cls.KEY_BLOB_SIZE]
        index += cls.KEY_BLOB_SIZE
        key_blob_unwrap = aes_key_unwrap(kek, key_blob[:-8])
        dek = key_blob_unwrap[:32]
        mac = key_blob_unwrap[32:]
        # Parse Header
        header = ImageHeaderV2.parse(header_raw_data)
        if header.offset_to_certificate_block != (index - offset):
            raise SPSDKError("Invalid offset")
        # Parse Certificate Block
        cert_block = CertBlockV1.parse(data[index:])
        index += cert_block.raw_size

        # Verify Signature
        signature_index = index
        # The image may contain SHA, in such a case the signature is placed
        # after SHA. Thus we must shift the index by SHA size.
        if header.flags & BootImageV21.FLAGS_SHA_PRESENT_BIT:
            signature_index += BootImageV21.SHA_256_SIZE
        result = cert_block.verify_data(
            data[signature_index : signature_index + cert_block.signature_size],
            data[offset:signature_index],
        )

        if not result:
            raise SPSDKError("Verification failed")
        # Check flags, if 0x8000 bit is set, the SB file contains SHA-256 between
        # certificate and signature.
        if header.flags & BootImageV21.FLAGS_SHA_PRESENT_BIT:
            bootable_section_sha256 = data[index : index + BootImageV21.SHA_256_SIZE]
            index += BootImageV21.SHA_256_SIZE
        index += cert_block.signature_size
        # Check first Boot Section HMAC
        # Not implemented yet
        # hmac_data_calc = hmac(mac, data[index + CmdHeader.SIZE: index + CmdHeader.SIZE + ((2) * 32)])
        # if hmac_data != hmac_data_calc:
        #    raise SPSDKError("HMAC failed")
        if not header.nonce:
            raise SPSDKError("Header's nonce not present")
        counter = Counter(header.nonce)
        counter.increment(SecBootBlckSize.to_num_blocks(index - offset))
        boot_section = BootSectionV2.parse(
            data, index, dek=dek, mac=mac, counter=counter, plain_sect=plain_sections
        )
        if header.flags & BootImageV21.FLAGS_SHA_PRESENT_BIT:
            computed_bootable_section_sha256 = get_hash(
                data[index:], algorithm=EnumHashAlgorithm.SHA256
            )

            if bootable_section_sha256 != computed_bootable_section_sha256:
                raise SPSDKError(
                    desc=(
                        "Error: invalid Bootable section SHA."
                        f"Expected {bootable_section_sha256.decode('utf-8')},"
                        f"got {computed_bootable_section_sha256.decode('utf-8')}"
                    )
                )
        adv_params = SBV2xAdvancedParams(
            dek=dek, mac=mac, nonce=header.nonce, timestamp=header.timestamp
        )
        obj = cls(
            kek=kek,
            product_version=str(header.product_version),
            component_version=str(header.component_version),
            build_number=header.build_number,
            advanced_params=adv_params,
        )
        obj.cert_block = cert_block
        obj.add_boot_section(boot_section)
        return obj

    @staticmethod
    def get_supported_families() -> List[str]:
        """Return list of supported families.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.SB21)

    @classmethod
    def get_commands_validation_schemas(cls, family: Optional[str] = None) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Device family filter, if None all commands are returned.
        :return: List of validation schemas.
        """
        sb2_sch_cfg = get_schema_file(DatabaseManager.SB21)

        schemas: List[Dict[str, Any]] = [sb2_sch_cfg["sb2_sections"]]
        if family:
            db = get_db(family, "latest")
            # remove unused command for current family
            supported_commands = db.get_list(DatabaseManager.SB21, "supported_commands")
            list_of_commands: List[Dict] = schemas[0]["properties"]["sections"]["items"][
                "properties"
            ]["commands"]["items"]["oneOf"]

            schemas[0]["properties"]["sections"]["items"]["properties"]["commands"]["items"][
                "oneOf"
            ] = [
                command
                for command in list_of_commands
                if list(command["properties"].keys())[0] in supported_commands
            ]

        return schemas

    @classmethod
    def get_validation_schemas(cls, family: Optional[str] = None) -> List[Dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Device family
        :return: List of validation schemas.
        """
        sb2_schema = get_schema_file(DatabaseManager.SB21)
        mbi_schema = get_schema_file(DatabaseManager.MBI)

        schemas: List[Dict[str, Any]] = []
        schemas.extend([mbi_schema[x] for x in ["signature_provider", "cert_block_v1"]])
        schemas.extend([sb2_schema[x] for x in ["sb2_output", "sb2_family", "common", "sb2"]])

        add_keyblob = True

        if family:
            add_keyblob = get_db(family, "latest").get_bool(
                DatabaseManager.SB21, "keyblobs", default=True
            )

        if add_keyblob:
            schemas.append(sb2_schema["keyblobs"])
        schemas.extend(cls.get_commands_validation_schemas(family))

        # find family
        for schema in schemas:
            if "properties" in schema and "family" in schema["properties"]:
                if family:
                    schema["properties"]["family"]["template_value"] = family
                schema["properties"]["family"]["enum"] = cls.get_supported_families()
                if family:
                    schema["properties"]["family"]["template_value"] = family
                break

        return schemas

    @classmethod
    def generate_config_template(cls, family: Optional[str]) -> str:
        """Generate configuration template.

        :param family: Device family.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        title = "Secure Binary v2.1 Configuration template"
        if family in cls.get_supported_families():
            title += f" for {family}"
        return CommentedConfig(
            title,
            cls.get_validation_schemas(family),
        ).get_template()

    @classmethod
    def parse_sb21_config(
        cls,
        config_path: str,
        external_files: Optional[List[str]] = None,
    ) -> Dict[Any, Any]:
        """Create lexer and parser, load the BD file content and parse it.

        :param config_path: Path to configuration file either BD or YAML formatted.
        :param external_files: Optional list of external files for BD processing
        :return: Dictionary with parsed configuration.
        """
        try:
            bd_file_content = load_text(config_path)
            parser = bd_parser.BDParser()
            parsed_conf = parser.parse(text=bd_file_content, extern=external_files)
            if parsed_conf is None:
                raise SPSDKError("Invalid bd file, secure binary file generation terminated")
        except SPSDKError:
            parsed_conf = load_configuration(config_path)
            config_dir = os.path.dirname(config_path)
            family = parsed_conf.get("family")
            schemas = BootImageV21.get_validation_schemas(family)
            check_config(parsed_conf, schemas, search_paths=[config_dir])

        return parsed_conf

    @classmethod
    def load_from_config(
        cls,
        config: Dict[str, Any],
        key_file_path: Optional[str] = None,
        signature_provider: Optional[SignatureProvider] = None,
        signing_certificate_file_paths: Optional[List[str]] = None,
        root_key_certificate_paths: Optional[List[str]] = None,
        rkth_out_path: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> "BootImageV21":
        """Creates an instance of BootImageV21 from configuration.

        :param config: Input standard configuration.
        :param key_file_path: path to key file.
        :param signature_provider: Signature provider to sign final image
        :param signing_certificate_file_paths: signing certificate chain.
        :param root_key_certificate_paths: paths to root key certificate(s) for
            verifying other certificates. Only 4 root key certificates are allowed,
            others are ignored. One of the certificates must match the first certificate
            passed in signing_certificate_file_paths.
        :param rkth_out_path: output path to hash of hashes of root keys. If set to
            None, 'hash.bin' is created under working directory.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Instance of Secure Binary V2.1 class
        """
        flags = config["options"].get(
            "flags", BootImageV21.FLAGS_SHA_PRESENT_BIT | BootImageV21.FLAGS_ENCRYPTED_SIGNED_BIT
        )
        # Flags may be a hex string
        flags = value_to_int(flags)

        product_version = config["options"].get("productVersion", "1.0.0")
        component_version = config["options"].get("componentVersion", "1.0.0")

        if signing_certificate_file_paths and root_key_certificate_paths:
            build_number = config["options"].get("buildNumber", 1)
            cert_block = CertBlockV1(build_number=build_number)
            for cert_path in signing_certificate_file_paths:
                cert = Certificate.load(cert_path)
                cert_block.add_certificate(cert)
            for cert_idx, cert_path in enumerate(root_key_certificate_paths):
                cert = Certificate.load(cert_path)
                cert_block.set_root_key_hash(cert_idx, cert)
        else:
            cert_block = CertBlockV1.from_config(config, search_paths=search_paths)

        if key_file_path:
            key = key_file_path
        else:
            key = config["containerKeyBlobEncryptionKey"]

        sb_kek = load_hex_string(key, expected_size=32, search_paths=search_paths)

        # validate keyblobs and perform appropriate actions
        keyblobs = config.get("keyblobs", [])

        sb21_helper = SB21Helper(search_paths)
        sb_sections = []
        sections = config["sections"]
        for section_id, section in enumerate(sections):
            commands = []
            for cmd in section["commands"]:
                for key, value in cmd.items():
                    # we use a helper function, based on the key ('load', 'erase'
                    # etc.) to create a command object. The helper function knows
                    # how to handle the parameters of each command.
                    cmd_fce = sb21_helper.get_command(key)
                    if key in ("keywrap", "encrypt"):
                        keyblob = {"keyblobs": keyblobs}
                        value.update(keyblob)
                    cmd = cmd_fce(value)
                    commands.append(cmd)

            sb_sections.append(BootSectionV2(section_id, *commands))

        # We have a list of sections and their respective commands, lets create
        # a boot image v2.1 object
        secure_binary = BootImageV21(
            sb_kek,
            *sb_sections,
            product_version=product_version,
            component_version=component_version,
            build_number=cert_block.header.build_number,
            flags=flags,
        )

        # We have our secure binary, now we attach to it the certificate block and
        # the private key content
        secure_binary.cert_block = cert_block

        if not signature_provider:
            signing_key_path = config.get("signPrivateKey", config.get("mainCertPrivateKeyFile"))
            signature_provider = get_signature_provider(
                sp_cfg=config.get("signProvider"),
                local_file_key=signing_key_path,
                search_paths=search_paths,
            )

        secure_binary.signature_provider = signature_provider

        if not rkth_out_path:
            rkth_out_path = config.get("RKTHOutputPath", os.path.join(os.getcwd(), "hash.bin"))
        assert isinstance(rkth_out_path, str), "Hash of hashes path must be string"
        write_file(secure_binary.cert_block.rkth, rkth_out_path, mode="wb")

        return secure_binary
