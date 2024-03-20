#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""The module provides support for IEE for RTxxxx devices."""

import logging
from copy import deepcopy
from struct import pack
from typing import Any, Dict, List, Optional, Union

from crcmod.predefined import mkPredefinedCrcFun

from spsdk import version as spsdk_version
from spsdk.apps.utils.utils import filepath_from_config
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.symmetric import Counter, aes_ctr_encrypt, aes_xts_encrypt
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import (
    Endianness,
    align_block,
    load_hex_string,
    reverse_bytes_in_longs,
    split_data,
    value_to_bytes,
    value_to_int,
)
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import CommentedConfig
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class IeeKeyBlobLockAttributes(SpsdkEnum):
    """IEE keyblob lock attributes."""

    LOCK = (0x95, "LOCK")  #  IEE region lock.
    UNLOCK = (0x59, "UNLOCK")  #  IEE region unlock.


class IeeKeyBlobKeyAttributes(SpsdkEnum):
    """IEE keyblob key attributes."""

    CTR128XTS256 = (0x5A, "CTR128XTS256")  # AES 128 bits (CTR), 256 bits (XTS)
    CTR256XTS512 = (0xA5, "CTR256XTS512")  # AES 256 bits (CTR), 512 bits (XTS)


class IeeKeyBlobModeAttributes(SpsdkEnum):
    """IEE Keyblob mode attributes."""

    Bypass = (0x6A, "Bypass")  # AES encryption/decryption bypass
    AesXTS = (0xA6, "AesXTS")  # AES XTS mode
    AesCTRWAddress = (0x66, "AesCTRWAddress")  # AES CTR w address binding mode
    AesCTRWOAddress = (0xAA, "AesCTRWOAddress")  # AES CTR w/o address binding mode
    AesCTRkeystream = (0x19, "AesCTRkeystream")  # AES CTR keystream only


class IeeKeyBlobWritePmsnAttributes(SpsdkEnum):
    """IEE keblob write permission attributes."""

    ENABLE = (0x99, "ENABLE")  # Enable write permission in APC IEE
    DISABLE = (0x11, "DISABLE")  # Disable write permission in APC IEE


class IeeKeyBlobAttribute:
    """IEE Keyblob Attribute.

    | typedef struct _iee_keyblob_attribute
    | {
    |     uint8_t lock;      #  IEE Region Lock control flag.
    |     uint8_t keySize;   #  IEE AES key size.
    |     uint8_t aesMode;   #  IEE AES mode.
    |     uint8_t reserved;  #  Reserved.
    | } iee_keyblob_attribute_t;
    """

    _FORMAT = "<BBBB"
    _SIZE = 4

    def __init__(
        self,
        lock: IeeKeyBlobLockAttributes,
        key_attribute: IeeKeyBlobKeyAttributes,
        aes_mode: IeeKeyBlobModeAttributes,
    ) -> None:
        """IEE keyblob constructor.

        :param lock: IeeKeyBlobLockAttributes
        :param key_attribute: IeeKeyBlobKeyAttributes
        :param aes_mode: IeeKeyBlobModeAttributes
        """
        self.lock = lock
        self.key_attribute = key_attribute
        self.aes_mode = aes_mode

    @property
    def ctr_mode(self) -> bool:
        """Return true if AES mode is CTR.

        :return: True if AES-CTR, false otherwise
        """
        if self.aes_mode in [
            IeeKeyBlobModeAttributes.AesCTRWAddress,
            IeeKeyBlobModeAttributes.AesCTRWOAddress,
            IeeKeyBlobModeAttributes.AesCTRkeystream,
        ]:
            return True
        return False

    @property
    def key1_size(self) -> int:
        """Return IEE key size based on selected mode.

        :return: Key size in bytes
        """
        if self.key_attribute == IeeKeyBlobKeyAttributes.CTR128XTS256:
            return 16
        return 32

    @property
    def key2_size(self) -> int:
        """Return IEE key size based on selected mode.

        :return: Key size in bytes
        """
        if self.key_attribute == IeeKeyBlobKeyAttributes.CTR128XTS256:
            return 16
        if self.ctr_mode:
            return 16
        return 32

    def export(self) -> bytes:
        """Export binary representation of KeyBlobAttribute.

        :return: serialized binary data
        """
        return pack(self._FORMAT, self.lock.tag, self.key_attribute.tag, self.aes_mode.tag, 0)


class IeeKeyBlob:
    """IEE KeyBlob.

    | typedef struct _iee_keyblob_
    | {
    |     uint32_t header;                   #  IEE Key Blob header tag.
    |     uint32_t version;                  #  IEE Key Blob version, upward compatible.
    |     iee_keyblob_attribute_t attribute; #  IEE configuration attribute.
    |     uint32_t pageOffset;               #  IEE page offset.
    |     uint32_t key1[IEE_MAX_AES_KEY_SIZE_IN_BYTE /
    |                   sizeof(uint32_t)]; #  Encryption key1 for XTS-AES mode, encryption key for AES-CTR mode.
    |     uint32_t key2[IEE_MAX_AES_KEY_SIZE_IN_BYTE /
    |                   sizeof(uint32_t)]; #  Encryption key2 for XTS-AES mode, initial counter for AES-CTR mode.
    |     uint32_t startAddr;              #  Physical address of encryption region.
    |     uint32_t endAddr;                #  Physical address of encryption region.
    |     uint32_t reserved;               #  Reserved word.
    |     uint32_t crc32;                  #  Entire IEE Key Blob CRC32 value. Must be the last struct member.
    | } iee_keyblob_t
    """

    _FORMAT = "LL4BL8L8LLLLL96B"

    HEADER_TAG = 0x49454542
    # Tag used in keyblob header
    # (('I' << 24) | ('E' << 16) | ('E' << 8) | ('B' << 0))
    KEYBLOB_VERSION = 0x56010000
    # Identifier of IEE keyblob version
    # (('V' << 24) | (1 << 16) | (0 << 8) | (0 << 0))
    KEYBLOB_OFFSET = 0x1000

    _IEE_ENCR_BLOCK_SIZE_XTS = 0x1000

    _ENCRYPTION_BLOCK_SIZE = 0x10

    _START_ADDR_MASK = 0x400 - 1
    # Region addresses are modulo 1024

    _END_ADDR_MASK = 0x3F8

    def __init__(
        self,
        attributes: IeeKeyBlobAttribute,
        start_addr: int,
        end_addr: int,
        key1: Optional[bytes] = None,
        key2: Optional[bytes] = None,
        page_offset: int = 0,
        crc: Optional[bytes] = None,
    ):
        """Constructor.

        :param attributes: IEE keyblob attributes
        :param start_addr: start address of the region
        :param end_addr: end address of the region
        :param key1: Encryption key1 for XTS-AES mode, encryption key for AES-CTR mode.
        :param key2: Encryption key2 for XTS-AES mode, initial_counter for AES-CTR mode.
        :param crc: optional value for unused CRC fill (for testing only); None to use calculated value
        :raises SPSDKError: Start or end address are not aligned
        :raises SPSDKError: When there is invalid key
        :raises SPSDKError: When there is invalid start/end address
        """
        self.attributes = attributes

        if key1 is None:
            key1 = random_bytes(self.attributes.key1_size)
        if key2 is None:
            key2 = random_bytes(self.attributes.key2_size)

        key1 = value_to_bytes(key1, byte_cnt=self.attributes.key1_size)
        key2 = value_to_bytes(key2, byte_cnt=self.attributes.key2_size)

        if start_addr < 0 or start_addr > end_addr or end_addr > 0xFFFFFFFF:
            raise SPSDKError("Invalid start/end address")

        if (start_addr & self._START_ADDR_MASK) != 0:
            raise SPSDKError(
                f"Start address must be aligned to {hex(self._START_ADDR_MASK + 1)} boundary"
            )

        self.start_addr = start_addr
        self.end_addr = end_addr

        self.key1 = key1
        self.key2 = key2
        self.page_offset = page_offset

        self.crc_fill = crc

    def __str__(self) -> str:
        """Text info about the instance."""
        msg = ""
        msg += f"KEY 1:        {self.key1.hex()}\n"
        msg += f"KEY 2:       {self.key2.hex()}\n"
        msg += f"Start Addr: {hex(self.start_addr)}\n"
        msg += f"End Addr:   {hex(self.end_addr)}\n"
        return msg

    def plain_data(self) -> bytes:
        """Plain data for selected key range.

        :return: key blob exported into binary form (serialization)
        """
        result = bytes()
        result += pack("<II", self.HEADER_TAG, self.KEYBLOB_VERSION)
        result += self.attributes.export()
        result += pack("<I", self.page_offset)
        result += align_block(self.key1, 32)
        result += align_block(self.key2, 32)
        result += pack("<III", self.start_addr, self.end_addr, 0)
        crc: bytes = mkPredefinedCrcFun("crc-32-mpeg")(result).to_bytes(4, Endianness.LITTLE.value)
        result += crc

        return result

    def contains_addr(self, addr: int) -> bool:
        """Whether key blob contains specified address.

        :param addr: to be tested
        :return: True if yes, False otherwise
        """
        return self.start_addr <= addr <= self.end_addr

    def matches_range(self, image_start: int, image_end: int) -> bool:
        """Whether key blob matches address range of the image to be encrypted.

        :param image_start: start address of the image
        :param image_end: last address of the image
        :return: True if yes, False otherwise
        """
        return self.contains_addr(image_start) and self.contains_addr(image_end)

    def encrypt_image_xts(self, base_address: int, data: bytes) -> bytes:
        """Encrypt specified data using AES-XTS.

        :param base_address: of the data in target memory; must be >= self.start_addr
        :param data: to be encrypted (e.g. plain image); base_address + len(data) must be <= self.end_addr
        :return: encrypted data
        """
        encrypted_data = bytes()
        current_start = base_address
        key1 = reverse_bytes_in_longs(self.key1)
        key2 = reverse_bytes_in_longs(self.key2)

        for block in split_data(bytearray(data), self._IEE_ENCR_BLOCK_SIZE_XTS):
            tweak = self.calculate_tweak(current_start)

            encrypted_block = aes_xts_encrypt(
                key1 + key2,
                block,
                tweak,
            )
            encrypted_data += encrypted_block
            current_start += len(block)

        return encrypted_data

    def encrypt_image_ctr(self, base_address: int, data: bytes) -> bytes:
        """Encrypt specified data using AES-CTR.

        :param base_address: of the data in target memory; must be >= self.start_addr
        :param data: to be encrypted (e.g. plain image); base_address + len(data) must be <= self.end_addr
        :return: encrypted data
        """
        encrypted_data = bytes()
        key = reverse_bytes_in_longs(self.key1)
        nonce = reverse_bytes_in_longs(self.key2)

        counter = Counter(nonce, ctr_value=base_address >> 4, ctr_byteorder_encoding=Endianness.BIG)

        for block in split_data(bytearray(data), self._ENCRYPTION_BLOCK_SIZE):
            encrypted_block = aes_ctr_encrypt(
                key,
                block,
                counter.value,
            )
            encrypted_data += encrypted_block
            counter.increment(self._ENCRYPTION_BLOCK_SIZE >> 4)

        return encrypted_data

    def encrypt_image(self, base_address: int, data: bytes) -> bytes:
        """Encrypt specified data.

        :param base_address: of the data in target memory; must be >= self.start_addr
        :param data: to be encrypted (e.g. plain image); base_address + len(data) must be <= self.end_addr
        :return: encrypted data
        :raises SPSDKError: If start address is not valid
        :raises NotImplementedError: AES-CTR is not implemented yet
        """
        if base_address % 16 != 0:
            raise SPSDKError("Invalid start address")  # Start address has to be 16 byte aligned
        data = align_block(data, self._ENCRYPTION_BLOCK_SIZE)  # align data length
        data_len = len(data)

        # check start and end addresses
        if not self.matches_range(base_address, base_address + data_len - 1):
            logger.warning(
                f"Image address range is not within key blob: {hex(self.start_addr)}-{hex(self.end_addr)}."
            )

        if self.attributes.ctr_mode:
            return self.encrypt_image_ctr(base_address, data)
        return self.encrypt_image_xts(base_address, data)

    @staticmethod
    def calculate_tweak(address: int) -> bytes:
        """Calculate tweak value for AES-XTS encryption based on the address value.

        :param address: start address of encryption
        :return: 16 byte tweak values
        """
        sector = address >> 12
        tweak = bytearray(16)
        for n in range(16):
            tweak[n] = sector & 0xFF
            sector = sector >> 8
        return bytes(tweak)


class Iee:
    """IEE: Inline Encryption Engine."""

    IEE_DATA_UNIT = 0x1000
    IEE_KEY_BLOBS_SIZE = 384

    def __init__(self) -> None:
        """Constructor."""
        self._key_blobs: List[IeeKeyBlob] = []

    def __getitem__(self, index: int) -> IeeKeyBlob:
        return self._key_blobs[index]

    def __setitem__(self, index: int, value: IeeKeyBlob) -> None:
        self._key_blobs.remove(self._key_blobs[index])
        self._key_blobs.insert(index, value)

    def add_key_blob(self, key_blob: IeeKeyBlob) -> None:
        """Add key for specified address range.

        :param key_blob: to be added
        """
        self._key_blobs.append(key_blob)

    def encrypt_image(self, image: bytes, base_addr: int) -> bytes:
        """Encrypt image with all available keyblobs.

        :param image: plain image to be encrypted
        :param base_addr: where the image will be located in target processor
        :return: encrypted image
        """
        encrypted_data = bytearray(image)
        addr = base_addr
        for block in split_data(image, self.IEE_DATA_UNIT):
            for key_blob in self._key_blobs:
                if key_blob.matches_range(addr, addr + len(block)):
                    logger.debug(
                        f"Encrypting {hex(addr)}:{hex(len(block) + addr)}"
                        f" with keyblob: \n {str(key_blob)}"
                    )
                    encrypted_data[
                        addr - base_addr : len(block) + addr - base_addr
                    ] = key_blob.encrypt_image(addr, block)
            addr += len(block)

        return bytes(encrypted_data)

    def get_key_blobs(self) -> bytes:
        """Get key blobs.

        :return: Binary key blobs joined together
        """
        result = bytes()
        for key_blob in self._key_blobs:
            result += key_blob.plain_data()

        # return result
        return align_block(result, self.IEE_KEY_BLOBS_SIZE)

    def encrypt_key_blobs(
        self,
        ibkek1: Union[bytes, str],
        ibkek2: Union[bytes, str],
        keyblob_address: int,
    ) -> bytes:
        """Encrypt keyblobs and export them as binary.

        :param ibkek1: key encryption key AES-XTS 256 bit
        :param ibkek2: key encryption key AES-XTS 256 bit
        :param keyblob_address: keyblob base address
        :return: encrypted keyblobs
        """
        plain_key_blobs = self.get_key_blobs()

        ibkek1 = reverse_bytes_in_longs(value_to_bytes(ibkek1, byte_cnt=32))
        logger.debug(f"IBKEK1: {' '.join(f'{b:02x}' for b in ibkek1)}")
        ibkek2 = reverse_bytes_in_longs(value_to_bytes(ibkek2, byte_cnt=32))
        logger.debug(f"IBKEK2 {' '.join(f'{b:02x}' for b in ibkek2)}")

        tweak = IeeKeyBlob.calculate_tweak(keyblob_address)
        return aes_xts_encrypt(
            ibkek1 + ibkek2,
            plain_key_blobs,
            tweak,
        )


class IeeNxp(Iee):
    """IEE: Inline Encryption Engine."""

    def __init__(
        self,
        family: str,
        keyblob_address: int,
        ibkek1: Union[bytes, str],
        ibkek2: Union[bytes, str],
        key_blobs: Optional[List[IeeKeyBlob]] = None,
        binaries: Optional[BinaryImage] = None,
    ) -> None:
        """Constructor.

        :param family: Device family
        :param ibkek1: 256 bit key to encrypt IEE keyblob
        :param ibkek2: 256 bit key to encrypt IEE keyblob
        :param key_blobs: Optional Key blobs to add to IEE, defaults to None
        :raises SPSDKValueError: Unsupported family
        """
        super().__init__()

        if family not in self.get_supported_families():
            raise SPSDKValueError(f"Unsupported family{family} by IEE")

        self.family = family
        self.ibkek1 = bytes.fromhex(ibkek1) if isinstance(ibkek1, str) else ibkek1
        self.ibkek2 = bytes.fromhex(ibkek2) if isinstance(ibkek2, str) else ibkek2
        self.keyblob_address = keyblob_address
        self.binaries = binaries

        self.db = get_db(family, "latest")
        self.blobs_min_cnt = self.db.get_int(DatabaseManager.IEE, "key_blob_min_cnt")
        self.blobs_max_cnt = self.db.get_int(DatabaseManager.IEE, "key_blob_max_cnt")
        self.generate_keyblob = self.db.get_bool(DatabaseManager.IEE, "generate_keyblob")

        if key_blobs:
            for key_blob in key_blobs:
                self.add_key_blob(key_blob)

    def export_key_blobs(self) -> bytes:
        """Export encrypted keyblobs in binary.

        :return: Encrypted keyblobs
        """
        return self.encrypt_key_blobs(self.ibkek1, self.ibkek2, self.keyblob_address)

    def export_image(self) -> Optional[BinaryImage]:
        """Export encrypted image.

        :return: Encrypted image
        """
        if self.binaries is None:
            return None
        self.binaries.validate()

        binaries: BinaryImage = deepcopy(self.binaries)

        for binary in binaries.sub_images:
            if binary.binary:
                binary.binary = self.encrypt_image(
                    binary.binary, binary.absolute_address + self.keyblob_address
                )
            for segment in binary.sub_images:
                if segment.binary:
                    segment.binary = self.encrypt_image(
                        segment.binary,
                        segment.absolute_address + self.keyblob_address,
                    )

        binaries.validate()
        return binaries

    def get_blhost_script_otp_kek(self) -> str:
        """Create BLHOST script to load fuses needed to run IEE with OTP fuses.

        :return: BLHOST script that loads the keys into fuses.
        """
        if not self.db.get_bool(DatabaseManager.IEE, "has_kek_fuses", default=False):
            logger.debug(f"The {self.family} has no IEE KEK fuses")
            return ""

        xml_fuses = self.db.get_file_path(DatabaseManager.IEE, "reg_fuses", default=None)
        if not xml_fuses:
            logger.debug(f"The {self.family} has no IEE fuses definition")
            return ""

        fuses = Registers(self.family, base_endianness=Endianness.LITTLE)
        grouped_regs = self.db.get_list(DatabaseManager.IEE, "grouped_registers", default=None)

        fuses.load_registers_from_xml(xml_fuses, grouped_regs=grouped_regs)
        fuses.find_reg("USER_KEY1").set_value(self.ibkek1)
        fuses.find_reg("USER_KEY2").set_value(self.ibkek2)

        load_iee = fuses.find_reg("LOAD_IEE_KEY")
        load_iee.find_bitfield("LOAD_IEE_KEY_BITFIELD").set_value(1)

        encrypt_engine = fuses.find_reg("ENCRYPT_XIP_ENGINE")
        encrypt_engine.find_bitfield("ENCRYPT_XIP_ENGINE_BITFIELD").set_value(1)

        boot_cfg = fuses.find_reg("BOOT_CFG")
        boot_cfg.find_bitfield("ENCRYPT_XIP_EN_BITFIELD").set_value(1)

        ibkek_lock = fuses.find_reg("USER_KEY_RLOCK")
        ibkek_lock.find_bitfield("USER_KEY1_RLOCK").set_value(1)
        ibkek_lock.find_bitfield("USER_KEY2_RLOCK").set_value(1)

        ret = (
            "# BLHOST IEE fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# Chip: {self.family} \n\n"
        )

        ret += f"# OTP IBKEK1: {self.ibkek1.hex()}\n\n"
        for reg in fuses.find_reg("USER_KEY1").sub_regs:
            ret += f"# {reg.name} fuse.\n"
            ret += f"efuse-program-once {hex(reg.offset)} 0x{reg.get_hex_value(raw=True)} --no-verify\n"

        ret += f"\n\n# OTP IBKEK2: {self.ibkek2.hex()}\n\n"
        for reg in fuses.find_reg("USER_KEY2").sub_regs:
            ret += f"# {reg.name} fuse.\n"
            ret += f"efuse-program-once {hex(reg.offset)} 0x{reg.get_hex_value(raw=True)} --no-verify\n"

        ret += f"\n\n# {load_iee.name} fuse.\n"
        for bitfield in load_iee.get_bitfields():
            ret += f"#   {bitfield.name}: {bitfield.get_enum_value()}\n"
        ret += f"efuse-program-once {hex(load_iee.offset)} 0x{load_iee.get_hex_value(raw=True)} --no-verify\n"

        ret += f"\n\n# {encrypt_engine.name} fuse.\n"
        for bitfield in encrypt_engine.get_bitfields():
            ret += f"#   {bitfield.name}: {bitfield.get_enum_value()}\n"
        ret += (
            f"efuse-program-once {hex(encrypt_engine.offset)} "
            f"0x{encrypt_engine.get_hex_value(raw=True)} --no-verify\n"
        )

        ret += f"\n\n# {ibkek_lock.name} fuse.\n"
        for bitfield in ibkek_lock.get_bitfields():
            ret += f"#   {bitfield.name}: {bitfield.get_enum_value()}\n"
        ret += f"efuse-program-once {hex(ibkek_lock.offset)} 0x{ibkek_lock.get_hex_value(raw=True)} --no-verify\n"

        ret += f"\n\n# {boot_cfg.name} fuse.\n"
        ret += "WARNING!! Check SRM and set all desired bitfields for boot configuration"
        for bitfield in boot_cfg.get_bitfields():
            ret += f"#   {bitfield.name}: {bitfield.get_enum_value()}\n"
        ret += (
            f"# efuse-program-once {hex(boot_cfg.offset)} "
            f"0x{boot_cfg.get_hex_value(raw=True)} --no-verify\n"
        )

        return ret

    def binary_image(
        self,
        plain_data: bool = False,
        data_alignment: int = 16,
        keyblob_name: str = "iee_keyblob.bin",
        image_name: str = "encrypted.bin",
    ) -> BinaryImage:
        """Get the IEE Binary Image representation.

        :param plain_data: Binary representation in plain format, defaults to False
        :param data_alignment: Alignment of data part key blobs.
        :param keyblob_name: Filename of the IEE keyblob
        :param image_name: Filename of the IEE image
        :return: IEE in BinaryImage.
        """
        iee = BinaryImage(image_name, offset=self.keyblob_address)
        if self.generate_keyblob:
            # Add mandatory IEE keyblob
            iee_keyblobs = self.get_key_blobs() if plain_data else self.export_key_blobs()
            iee.add_image(
                BinaryImage(
                    keyblob_name,
                    offset=0,
                    description=f"IEE keyblobs {self.family}",
                    binary=iee_keyblobs,
                )
            )
        binaries = self.export_image()

        if binaries:
            binaries.alignment = data_alignment
            binaries.validate()
            iee.add_image(binaries)

        return iee

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get all supported families for AHAB container.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.IEE)

    @staticmethod
    def get_validation_schemas(family: str) -> List[Dict[str, Any]]:
        """Get list of validation schemas.

        :param family: Family for which the template should be generated.
        :return: Validation list of schemas.
        """
        if family not in IeeNxp.get_supported_families():
            return []

        database = get_db(family, "latest")
        schemas = get_schema_file(DatabaseManager.IEE)
        family_sch = schemas["iee_family"]
        family_sch["properties"]["family"]["enum"] = IeeNxp.get_supported_families()
        family_sch["properties"]["family"]["template_value"] = family
        ret = [family_sch, schemas["iee_output"], schemas["iee"]]
        additional_schemes = database.get_list(
            DatabaseManager.IEE, "additional_template", default=[]
        )
        ret.extend([schemas[x] for x in additional_schemes])
        return ret

    @staticmethod
    def get_validation_schemas_family() -> List[Dict[str, Any]]:
        """Get list of validation schemas for family key.

        :return: Validation list of schemas.
        """
        schemas = get_schema_file(DatabaseManager.IEE)
        family_sch = schemas["iee_family"]
        family_sch["properties"]["family"]["enum"] = IeeNxp.get_supported_families()
        return [family_sch]

    @staticmethod
    def generate_config_template(family: str) -> Dict[str, Any]:
        """Generate IEE configuration template.

        :param family: Family for which the template should be generated.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        val_schemas = IeeNxp.get_validation_schemas(family)
        database = get_db(family, "latest")

        if val_schemas:
            template_note = database.get_str(
                DatabaseManager.IEE, "additional_template_text", default=""
            )
            title = f"IEE: Inline Encryption Engine Configuration template for {family}."

            yaml_data = CommentedConfig(title, val_schemas, note=template_note).get_template()

            return {f"{family}_iee": yaml_data}

        return {}

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], config_dir: str, search_paths: Optional[List[str]] = None
    ) -> "IeeNxp":
        """Converts the configuration option into an IEE image object.

        "config" content array of containers configurations.

        :param config: array of IEE configuration dictionaries.
        :param config_dir: directory where the config is located
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: initialized IEE object.
        """
        iee_config: List[Dict[str, Any]] = config.get("key_blobs", [config.get("key_blob")])
        family = config["family"]
        ibkek1 = load_hex_string(
            config.get(
                "ibkek1",
                "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ),
            32,
        )
        ibkek2 = load_hex_string(
            config.get(
                "ibkek2",
                "0x202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            ),
            32,
        )

        logger.debug(f"Loaded IBKEK1: {ibkek1.hex()}")
        logger.debug(f"Loaded IBKEK2: {ibkek2.hex()}")

        keyblob_address = value_to_int(config["keyblob_address"])
        start_address = min(
            [value_to_int(addr.get("start_address", 0xFFFFFFFF)) for addr in iee_config]
        )

        data_blobs: Optional[List[Dict]] = config.get("data_blobs")
        binaries = None
        if data_blobs:
            # start address to calculate offset from keyblob, min from keyblob or data blob address
            # pylint: disable-next=nested-min-max
            start_address = min(
                min([value_to_int(addr.get("address", 0xFFFFFFFF)) for addr in data_blobs]),
                start_address,
            )
            binaries = BinaryImage(
                filepath_from_config(
                    config, "encrypted_name", "encrypted_blobs", config_dir, config["output_folder"]
                ),
                offset=start_address - keyblob_address,
                alignment=IeeKeyBlob._ENCRYPTION_BLOCK_SIZE,
            )
            for data_blob in data_blobs:
                address = value_to_int(
                    data_blob.get("address", 0), keyblob_address + binaries.offset
                )

                binary = BinaryImage.load_binary_image(
                    path=data_blob["data"],
                    search_paths=search_paths,
                    offset=address - keyblob_address - binaries.offset,
                    alignment=IeeKeyBlob._ENCRYPTION_BLOCK_SIZE,
                    size=0,
                )

                binaries.add_image(binary)

        iee = IeeNxp(family, keyblob_address, ibkek1, ibkek2, binaries=binaries)

        for key_blob_cfg in iee_config:
            aes_mode = key_blob_cfg["aes_mode"]
            region_lock = "LOCK" if key_blob_cfg.get("region_lock") else "UNLOCK"
            key_size = key_blob_cfg["key_size"]

            attributes = IeeKeyBlobAttribute(
                IeeKeyBlobLockAttributes.from_label(region_lock),
                IeeKeyBlobKeyAttributes.from_label(key_size),
                IeeKeyBlobModeAttributes.from_label(aes_mode),
            )

            key1 = load_hex_string(key_blob_cfg["key1"], attributes.key1_size)
            key2 = load_hex_string(key_blob_cfg["key2"], attributes.key2_size)

            start_addr = value_to_int(key_blob_cfg.get("start_address", start_address))
            end_addr = value_to_int(key_blob_cfg.get("end_address", 0xFFFFFFFF))
            page_offset = value_to_int(key_blob_cfg.get("page_offset", 0))

            iee.add_key_blob(
                IeeKeyBlob(
                    attributes=attributes,
                    start_addr=start_addr,
                    end_addr=end_addr,
                    key1=key1,
                    key2=key2,
                    page_offset=page_offset,
                )
            )

        return iee
