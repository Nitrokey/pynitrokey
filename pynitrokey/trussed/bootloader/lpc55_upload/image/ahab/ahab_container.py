#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of raw AHAB container support.

This module represents a generic AHAB container implementation. You can set the
containers values at will. From this perspective, consult with your reference
manual of your device for allowed values.
"""
# pylint: disable=too-many-lines
import logging
import math
import os
from struct import calcsize, pack, unpack
from typing import Any, Dict, List, Optional, Tuple, Union

from typing_extensions import Self

from ... import version as spsdk_version
from ...crypto.hash import EnumHashAlgorithm, get_hash
from ...crypto.keys import (
    IS_OSCCA_SUPPORTED,
    EccCurve,
    PublicKey,
    PublicKeyEcc,
    PublicKeyRsa,
    PublicKeySM2,
)
from ...crypto.signature_provider import SignatureProvider, get_signature_provider
from ...crypto.symmetric import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
)
from ...crypto.types import SPSDKEncoding
from ...crypto.utils import extract_public_key, get_matching_key_id
from ...ele.ele_constants import KeyBlobEncryptionAlgorithm
from ...exceptions import SPSDKError, SPSDKLengthError, SPSDKParsingError, SPSDKValueError
from ...image.ahab.ahab_abstract_interfaces import (
    Container,
    HeaderContainer,
    HeaderContainerInversed,
)
from ...utils.database import DatabaseManager, get_db, get_families
from ...utils.images import BinaryImage
from ...utils.misc import (
    BinaryPattern,
    Endianness,
    align,
    align_block,
    check_range,
    extend_block,
    find_file,
    load_binary,
    load_configuration,
    load_hex_string,
    reverse_bytes_in_longs,
    value_to_bytes,
    value_to_int,
    write_file,
)
from ...utils.schema_validator import CommentedConfig, check_config
from ...utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)

LITTLE_ENDIAN = "<"
UINT8 = "B"
UINT16 = "H"
UINT32 = "L"
UINT64 = "Q"
RESERVED = 0
CONTAINER_ALIGNMENT = 8
START_IMAGE_ADDRESS = 0x2000
START_IMAGE_ADDRESS_NAND = 0x1C00


TARGET_MEMORY_SERIAL_DOWNLOADER = "serial_downloader"
TARGET_MEMORY_NOR = "nor"
TARGET_MEMORY_NAND_4K = "nand_4k"
TARGET_MEMORY_NAND_2K = "nand_2k"

TARGET_MEMORY_BOOT_OFFSETS = {
    TARGET_MEMORY_SERIAL_DOWNLOADER: 0x400,
    TARGET_MEMORY_NOR: 0x1000,
    TARGET_MEMORY_NAND_4K: 0x400,
    TARGET_MEMORY_NAND_2K: 0x400,
}


class AHABTags(SpsdkEnum):
    """AHAB container related tags."""

    BLOB = (0x81, "Blob (Wrapped Data Encryption Key).")
    CONTAINER_HEADER = (0x87, "Container header.")
    SIGNATURE_BLOCK = (0x90, "Signature block.")
    CERTIFICATE_UUID = (0xA0, "Certificate with UUID.")
    CERTIFICATE_NON_UUID = (0xAF, "Certificate without UUID.")
    SRK_TABLE = (0xD7, "SRK table.")
    SIGNATURE = (0xD8, "Signature part of signature block.")
    SRK_RECORD = (0xE1, "SRK record.")


class AHABCoreId(SpsdkEnum):
    """AHAB cored IDs."""

    UNDEFINED = (0, "undefined", "Undefined core")
    CORTEX_M33 = (1, "cortex-m33", "Cortex M33")
    CORTEX_M4 = (2, "cortex-m4", "Cortex M4")
    CORTEX_M7 = (2, "cortex-m7", "Cortex M7")
    CORTEX_A55 = (2, "cortex-a55", "Cortex A55")
    CORTEX_M4_1 = (3, "cortex-m4_1", "Cortex M4 alternative")
    CORTEX_A53 = (4, "cortex-a53", "Cortex A53")
    CORTEX_A35 = (4, "cortex-a35", "Cortex A35")
    CORTEX_A72 = (5, "cortex-a72", "Cortex A72")
    SECO = (6, "seco", "EL enclave")
    HDMI_TX = (7, "hdmi-tx", "HDMI Tx")
    HDMI_RX = (8, "hdmi-rx", "HDMI Rx")
    V2X_1 = (9, "v2x-1", "V2X 1")
    V2X_2 = (10, "v2x-2", "V2X 2")


def get_key_by_val(dictionary: Dict, val: Any) -> Any:
    """Get Dictionary key by its value or default.

    :param dictionary: Dictionary to search in.
    :param val: Value to search
    :raises SPSDKValueError: In case that dictionary doesn't contains the value.
    :return: Key.
    """
    for key, value in dictionary.items():
        if value == val:
            return key
    raise SPSDKValueError(
        f"The requested value [{val}] in dictionary [{dictionary}] is not available."
    )


class ImageArrayEntry(Container):
    """Class representing image array entry as part of image array in the AHAB container.

    Image Array Entry content::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |                        Image Offset                           |
        +-----+---------------------------------------------------------------+
        |0x04 |                        Image Size                             |
        +-----+---------------------------------------------------------------+
        |0x08 |                                                               |
        |-----+                        Load Address (64 bits)                 |
        |0x0C |                                                               |
        +-----+---------------------------------------------------------------+
        |0x10 |                                                               |
        |-----+                        Entry Point (64 bits)                  |
        |0x14 |                                                               |
        +-----+---------------------------------------------------------------+
        |0x18 |                        Flags                                  |
        +-----+---------------------------------------------------------------+
        |0x1C |                        Image meta data                        |
        +-----+---------------------------------------------------------------+
        |0x20 |                                                               |
        |-----+                        Hash (512 bits)                        |
        |.... |                                                               |
        +-----+---------------------------------------------------------------+
        |0x60 |                        IV (256 bits)                          |
        +-----+---------------------------------------------------------------+

    """

    IMAGE_OFFSET_LEN = 4
    IMAGE_SIZE_LEN = 4
    LOAD_ADDRESS_LEN = 8
    ENTRY_POINT_ADDRESS_LEN = 8
    FLAGS_LEN = 4
    IMAGE_META_DATA_LEN = 4
    HASH_LEN = 64
    IV_LEN = 32
    FLAGS_TYPE_OFFSET = 0
    FLAGS_TYPE_SIZE = 4
    FLAGS_TYPES = {
        "csf": 0x01,
        "scd": 0x02,
        "executable": 0x03,
        "data": 0x04,
        "dcd_image": 0x05,
        "seco": 0x06,
        "provisioning_image": 0x07,
        "dek_validation_fcb_chk": 0x08,
        "provisioning_data": 0x09,
        "executable_fast_boot_image": 0x0A,
        "v2x_primary": 0x0B,
        "v2x_secondary": 0x0C,
        "v2x_rom_patch": 0x0D,
        "v2x_dummy": 0x0E,
    }
    FLAGS_CORE_ID_OFFSET = 4
    FLAGS_CORE_ID_SIZE = 4
    FLAGS_HASH_OFFSET = 8
    FLAGS_HASH_SIZE = 3
    FLAGS_IS_ENCRYPTED_OFFSET = 11
    FLAGS_IS_ENCRYPTED_SIZE = 1
    FLAGS_BOOT_FLAGS_OFFSET = 16
    FLAGS_BOOT_FLAGS_SIZE = 15
    METADATA_START_CPU_ID_OFFSET = 0
    METADATA_START_CPU_ID_SIZE = 10
    METADATA_MU_CPU_ID_OFFSET = 10
    METADATA_MU_CPU_ID_SIZE = 10
    METADATA_START_PARTITION_ID_OFFSET = 20
    METADATA_START_PARTITION_ID_SIZE = 8

    IMAGE_ALIGNMENTS = {
        TARGET_MEMORY_SERIAL_DOWNLOADER: 512,
        TARGET_MEMORY_NOR: 1024,
        TARGET_MEMORY_NAND_2K: 2048,
        TARGET_MEMORY_NAND_4K: 4096,
    }

    def __init__(
        self,
        parent: "AHABContainer",
        image: Optional[bytes] = None,
        image_offset: int = 0,
        load_address: int = 0,
        entry_point: int = 0,
        flags: int = 0,
        image_meta_data: int = 0,
        image_hash: Optional[bytes] = None,
        image_iv: Optional[bytes] = None,
        already_encrypted_image: bool = False,
    ) -> None:
        """Class object initializer.

        :param parent: Parent AHAB Container object.
        :param image: Image in bytes.
        :param image_offset: Offset in bytes from start of container to beginning of image.
        :param load_address: Address the image is written to in memory (absolute address in system memory map).
        :param entry_point: Entry point of image (absolute address). Only valid for executable image types.
            For other image types the value is irrelevant.
        :param flags: flags.
        :param image_meta_data: image meta-data.
        :param image_hash: SHA of image (512 bits) in big endian. Left
            aligned and padded with zeroes for hash sizes below 512 bits.
        :param image_iv: SHA256 of plain text image (256 bits) in big endian.
        :param already_encrypted_image: The input image is already encrypted.
            Used only for encrypted images.
        """
        self._image_offset = 0
        self.parent = parent
        self.flags = flags
        self.already_encrypted_image = already_encrypted_image
        self.image = image if image else b""
        self.image_offset = image_offset
        self.image_size = self._get_valid_size(self.image)
        self.load_address = load_address
        self.entry_point = entry_point
        self.image_meta_data = image_meta_data
        self.image_hash = image_hash
        self.image_iv = (
            image_iv or get_hash(self.plain_image, algorithm=EnumHashAlgorithm.SHA256)
            if self.flags_is_encrypted
            else bytes(self.IV_LEN)
        )

    @property
    def _ahab_container(self) -> "AHABContainer":
        """AHAB Container object."""
        return self.parent

    @property
    def _ahab_image(self) -> "AHABImage":
        """AHAB Image object."""
        return self._ahab_container.parent

    @property
    def image_offset(self) -> int:
        """Image offset."""
        return self._image_offset + self._ahab_container.container_offset

    @image_offset.setter
    def image_offset(self, offset: int) -> None:
        """Image offset.

        :param offset: Image offset.
        """
        self._image_offset = offset - self._ahab_container.container_offset

    @property
    def image_offset_real(self) -> int:
        """Real offset in Bootable image."""
        target_memory = self._ahab_image.target_memory
        return self.image_offset + TARGET_MEMORY_BOOT_OFFSETS[target_memory]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ImageArrayEntry):
            if (
                self.image_offset  # pylint: disable=too-many-boolean-expressions
                == other.image_offset
                and self.image_size == other.image_size
                and self.load_address == other.load_address
                and self.entry_point == other.entry_point
                and self.flags == other.flags
                and self.image_meta_data == other.image_meta_data
                and self.image_hash == other.image_hash
                and self.image_iv == other.image_iv
            ):
                return True

        return False

    def __repr__(self) -> str:
        return f"AHAB Image Array Entry, load address({hex(self.load_address)})"

    def __str__(self) -> str:
        return (
            "AHAB Image Array Entry:\n"
            f"  Image size:             {self.image_size}B\n"
            f"  Image offset in table:  {hex(self.image_offset)}\n"
            f"  Image offset real:      {hex(self.image_offset_real)}\n"
            f"  Entry point:            {hex(self.entry_point)}\n"
            f"  Load address:           {hex(self.load_address)}\n"
            f"  Flags:                  {hex(self.flags)})\n"
            f"  Meta data:              {hex(self.image_meta_data)})\n"
            f"  Image hash:             {self.image_hash.hex() if self.image_hash else 'Not available'})\n"
            f"  Image IV:               {self.image_iv.hex()})\n"
        )

    @property
    def image(self) -> bytes:
        """Image data for this Image array entry.

        The class decide by flags if encrypted of plain data has been returned.

        :raises SPSDKError: Invalid Image - Image is not encrypted yet.
        :return: Image bytes.
        """
        # if self.flags_is_encrypted and not self.already_encrypted_image:
        #     raise SPSDKError("Image is NOT encrypted, yet.")

        if self.flags_is_encrypted and self.already_encrypted_image:
            return self.encrypted_image
        return self.plain_image

    @image.setter
    def image(self, data: bytes) -> None:
        """Image data for this Image array entry.

        The class decide by flags if encrypted of plain data has been stored.
        """
        input_image = align_block(
            data, 16 if self.flags_is_encrypted else 4, padding=RESERVED
        )  # align to encryptable block
        self.plain_image = input_image if not self.already_encrypted_image else b""
        self.encrypted_image = input_image if self.already_encrypted_image else b""

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()  # endianness from base class
            + UINT32  # Image Offset
            + UINT32  # Image Size
            + UINT64  # Load Address
            + UINT64  # Entry Point
            + UINT32  # Flags
            + UINT32  # Image Meta Data
            + "64s"  # HASH
            + "32s"  # Input Vector
        )

    def update_fields(self) -> None:
        """Updates the image fields in container based on provided image."""
        # self.image = align_block(self.image, self.get_valid_alignment(), 0)
        self.image_size = self._get_valid_size(self.image)
        algorithm = self.get_hash_from_flags(self.flags)
        self.image_hash = extend_block(
            get_hash(self.image, algorithm=algorithm),
            self.HASH_LEN,
            padding=0,
        )
        if not self.image_iv and self.flags_is_encrypted:
            self.image_iv = get_hash(self.plain_image, algorithm=EnumHashAlgorithm.SHA256)

    @staticmethod
    def create_meta(start_cpu_id: int = 0, mu_cpu_id: int = 0, start_partition_id: int = 0) -> int:
        """Create meta data field.

        :param start_cpu_id: ID of CPU to start, defaults to 0
        :param mu_cpu_id: ID of MU for selected CPU to start, defaults to 0
        :param start_partition_id: ID of partition to start, defaults to 0
        :return: Image meta data field.
        """
        meta_data = start_cpu_id
        meta_data |= mu_cpu_id << 10
        meta_data |= start_partition_id << 20
        return meta_data

    @staticmethod
    def create_flags(
        image_type: str = "executable",
        core_id: AHABCoreId = AHABCoreId.CORTEX_M33,
        hash_type: EnumHashAlgorithm = EnumHashAlgorithm.SHA256,
        is_encrypted: bool = False,
        boot_flags: int = 0,
    ) -> int:
        """Create flags field.

        :param image_type: Type of image, defaults to "executable"
        :param core_id: Core ID, defaults to "cortex-m33"
        :param hash_type: Hash type, defaults to sha256
        :param is_encrypted: Is image encrypted, defaults to False
        :param boot_flags: Boot flags controlling the SCFW boot, defaults to 0
        :return: Image flags data field.
        """
        flags_data = ImageArrayEntry.FLAGS_TYPES[image_type]
        flags_data |= core_id.tag << ImageArrayEntry.FLAGS_CORE_ID_OFFSET
        flags_data |= {
            EnumHashAlgorithm.SHA256: 0x0,
            EnumHashAlgorithm.SHA384: 0x1,
            EnumHashAlgorithm.SHA512: 0x2,
            EnumHashAlgorithm.SM3: 0x3,
        }[hash_type] << ImageArrayEntry.FLAGS_HASH_OFFSET
        flags_data |= 1 << ImageArrayEntry.FLAGS_IS_ENCRYPTED_OFFSET if is_encrypted else 0
        flags_data |= boot_flags << ImageArrayEntry.FLAGS_BOOT_FLAGS_OFFSET

        return flags_data

    @staticmethod
    def get_hash_from_flags(flags: int) -> EnumHashAlgorithm:
        """Get Hash algorithm name from flags.

        :param flags: Value of flags.
        :return: Hash name.
        """
        hash_val = (flags >> ImageArrayEntry.FLAGS_HASH_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_HASH_SIZE) - 1
        )
        return {
            0x00: EnumHashAlgorithm.SHA256,
            0x01: EnumHashAlgorithm.SHA384,
            0x02: EnumHashAlgorithm.SHA512,
            0x03: EnumHashAlgorithm.SM3,
        }[hash_val]

    @property
    def flags_image_type(self) -> str:
        """Get Image type name from flags.

        :return: Image type name
        """
        image_type_val = (self.flags >> ImageArrayEntry.FLAGS_TYPE_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_TYPE_SIZE) - 1
        )
        try:
            return get_key_by_val(ImageArrayEntry.FLAGS_TYPES, image_type_val)
        except SPSDKValueError:
            return f"Unknown Image Type {image_type_val}"

    @property
    def flags_core_id(self) -> int:
        """Get Core ID from flags.

        :return: Core ID
        """
        return (self.flags >> ImageArrayEntry.FLAGS_CORE_ID_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_CORE_ID_SIZE) - 1
        )

    @property
    def flags_is_encrypted(self) -> bool:
        """Get Is encrypted property from flags.

        :return: True if is encrypted, false otherwise
        """
        return bool(
            (self.flags >> ImageArrayEntry.FLAGS_IS_ENCRYPTED_OFFSET)
            & ((1 << ImageArrayEntry.FLAGS_IS_ENCRYPTED_SIZE) - 1)
        )

    @property
    def flags_boot_flags(self) -> int:
        """Get boot flags property from flags.

        :return: Boot flags
        """
        return (self.flags >> ImageArrayEntry.FLAGS_BOOT_FLAGS_OFFSET) & (
            (1 << ImageArrayEntry.FLAGS_BOOT_FLAGS_SIZE) - 1
        )

    @property
    def metadata_start_cpu_id(self) -> int:
        """Get CPU ID property from Meta data.

        :return: Start CPU ID
        """
        return (self.image_meta_data >> ImageArrayEntry.METADATA_START_CPU_ID_OFFSET) & (
            (1 << ImageArrayEntry.METADATA_START_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_mu_cpu_id(self) -> int:
        """Get Start CPU Memory Unit ID property from Meta data.

        :return: Start CPU MU ID
        """
        return (self.image_meta_data >> ImageArrayEntry.METADATA_MU_CPU_ID_OFFSET) & (
            (1 << ImageArrayEntry.METADATA_MU_CPU_ID_SIZE) - 1
        )

    @property
    def metadata_start_partition_id(self) -> int:
        """Get Start Partition ID property from Meta data.

        :return: Start Partition ID
        """
        return (self.image_meta_data >> ImageArrayEntry.METADATA_START_PARTITION_ID_OFFSET) & (
            (1 << ImageArrayEntry.METADATA_START_PARTITION_ID_SIZE) - 1
        )

    def export(self) -> bytes:
        """Serializes container object into bytes in little endian.

        The hash and IV are kept in big endian form.

        :return: bytes representing container content.
        """
        # hash: fixed at 512 bits, left aligned and padded with zeros for hash below 512 bits.
        # In case the hash is shorter, the pack() (in little endian mode) should grant, that the
        # hash is left aligned and padded with zeros due to the '64s' formatter.
        # iv: fixed at 256 bits.
        data = pack(
            self.format(),
            self._image_offset,
            self.image_size,
            self.load_address,
            self.entry_point,
            self.flags,
            self.image_meta_data,
            self.image_hash,
            self.image_iv,
        )

        return data

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        if self.image is None or self._get_valid_size(self.image) != self.image_size:
            raise SPSDKValueError("Image Entry: Invalid Image binary.")
        if self.image_offset is None or not check_range(self.image_offset, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Offset: {self.image_offset}")
        if self.image_size is None or not check_range(self.image_size, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Size: {self.image_size}")
        if self.load_address is None or not check_range(self.load_address, end=(1 << 64) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Load address: {self.load_address}")
        if self.entry_point is None or not check_range(self.entry_point, end=(1 << 64) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Entry point: {self.entry_point}")
        if self.flags is None or not check_range(self.flags, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Flags: {self.flags}")
        if self.image_meta_data is None or not check_range(self.image_meta_data, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Image Entry: Invalid Image Meta data: {self.image_meta_data}")
        if (
            self.image_hash is None
            or not any(self.image_hash)
            or len(self.image_hash) != self.HASH_LEN
        ):
            raise SPSDKValueError("Image Entry: Invalid Image Hash.")

    @classmethod
    def parse(cls, data: bytes, parent: "AHABContainer") -> Self:  # type: ignore # pylint: disable=arguments-differ
        """Parse input binary chunk to the container object.

        :param parent: Parent AHABContainer object.
        :param data: Binary data with Image Array Entry block to parse.
        :raises SPSDKLengthError: If invalid length of image is detected.
        :raises SPSDKValueError: Invalid hash for image.
        :return: Object recreated from the binary data.
        """
        binary_size = len(data)
        # Just updates offsets from AHAB Image start As is feature of none xip containers
        ImageArrayEntry._check_fixed_input_length(data)
        (
            image_offset,
            image_size,
            load_address,
            entry_point,
            flags,
            image_meta_data,
            image_hash,
            image_iv,
        ) = unpack(ImageArrayEntry.format(), data[: ImageArrayEntry.fixed_length()])

        iae = cls(
            parent=parent,
            image_offset=0,
            image=None,
            load_address=load_address,
            entry_point=entry_point,
            flags=flags,
            image_meta_data=image_meta_data,
            image_hash=image_hash,
            image_iv=image_iv,
            already_encrypted_image=bool(
                (flags >> ImageArrayEntry.FLAGS_IS_ENCRYPTED_OFFSET)
                & ((1 << ImageArrayEntry.FLAGS_IS_ENCRYPTED_SIZE) - 1)
            ),
        )
        iae._image_offset = image_offset

        iae_offset = (
            AHABContainer.fixed_length()
            + parent.image_array_len * ImageArrayEntry.fixed_length()
            + parent.container_offset
        )

        logger.debug(
            (
                "Parsing Image array Entry:\n"
                f"Image offset: {hex(iae.image_offset)}\n"
                f"Image offset raw: {hex(iae._image_offset)}\n"
                f"Image offset real: {hex(iae.image_offset_real)}"
            )
        )
        if iae.image_offset + image_size - iae_offset > binary_size:
            raise SPSDKLengthError(
                "Container data image is out of loaded binary:"
                f"Image entry record has end of image at {hex(iae.image_offset + image_size - iae_offset)},"
                f" but the loaded image length has only {hex(binary_size)}B size."
            )
        image = data[iae.image_offset - iae_offset : iae.image_offset - iae_offset + image_size]
        image_hash_cmp = extend_block(
            get_hash(image, algorithm=ImageArrayEntry.get_hash_from_flags(flags)),
            ImageArrayEntry.HASH_LEN,
            padding=0,
        )
        if image_hash != image_hash_cmp:
            raise SPSDKValueError("Parsed Container data image has invalid HASH!")
        iae.image = image
        return iae

    @staticmethod
    def load_from_config(parent: "AHABContainer", config: Dict[str, Any]) -> "ImageArrayEntry":
        """Converts the configuration option into an AHAB image array entry object.

        "config" content of container configurations.

        :param parent: Parent AHABContainer object.
        :param config: Configuration of ImageArray.
        :return: Container Header Image Array Entry object.
        """
        image_path = config.get("image_path")
        search_paths = parent.search_paths
        assert isinstance(image_path, str)
        is_encrypted = config.get("is_encrypted", False)
        meta_data = ImageArrayEntry.create_meta(
            value_to_int(config.get("meta_data_start_cpu_id", 0)),
            value_to_int(config.get("meta_data_mu_cpu_id", 0)),
            value_to_int(config.get("meta_data_start_partition_id", 0)),
        )
        image_data = load_binary(image_path, search_paths=search_paths)
        flags = ImageArrayEntry.create_flags(
            image_type=config.get("image_type", "executable"),
            core_id=AHABCoreId.from_label(config.get("core_id", "cortex-m33")),
            hash_type=EnumHashAlgorithm.from_label(config.get("hash_type", "sha256")),
            is_encrypted=is_encrypted,
            boot_flags=value_to_int(config.get("boot_flags", 0)),
        )
        return ImageArrayEntry(
            parent=parent,
            image=image_data,
            image_offset=value_to_int(config.get("image_offset", 0)),
            load_address=value_to_int(config.get("load_address", 0)),
            entry_point=value_to_int(config.get("entry_point", 0)),
            flags=flags,
            image_meta_data=meta_data,
            image_iv=None,  # IV data are updated by UpdateFields function
        )

    def create_config(self, index: int, image_index: int, data_path: str) -> Dict[str, Any]:
        """Create configuration of the AHAB Image data blob.

        :param index: Container index.
        :param image_index: Data Image index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg: Dict[str, Union[str, int, bool]] = {}
        image_name = "N/A"
        if self.plain_image:
            image_name = f"container{index}_image{image_index}_{self.flags_image_type}.bin"
            write_file(self.plain_image, os.path.join(data_path, image_name), "wb")
        if self.encrypted_image:
            image_name_encrypted = (
                f"container{index}_image{image_index}_{self.flags_image_type}_encrypted.bin"
            )
            write_file(self.encrypted_image, os.path.join(data_path, image_name_encrypted), "wb")
            if image_name == "N/A":
                image_name = image_name_encrypted

        ret_cfg["image_path"] = image_name
        ret_cfg["image_offset"] = hex(self.image_offset)
        ret_cfg["load_address"] = hex(self.load_address)
        ret_cfg["entry_point"] = hex(self.entry_point)
        ret_cfg["image_type"] = self.flags_image_type
        core_ids = self.parent.parent._database.get_dict(DatabaseManager.AHAB, "core_ids")
        ret_cfg["core_id"] = core_ids.get(self.flags_core_id, f"Unknown ID: {self.flags_core_id}")
        ret_cfg["is_encrypted"] = bool(self.flags_is_encrypted)
        ret_cfg["boot_flags"] = self.flags_boot_flags
        ret_cfg["meta_data_start_cpu_id"] = self.metadata_start_cpu_id
        ret_cfg["meta_data_mu_cpu_id"] = self.metadata_mu_cpu_id
        ret_cfg["meta_data_start_partition_id"] = self.metadata_start_partition_id
        ret_cfg["hash_type"] = self.get_hash_from_flags(self.flags).label

        return ret_cfg

    def get_valid_alignment(self) -> int:
        """Get valid alignment for AHAB container and memory target.

        :return: AHAB valid alignment
        """
        if (
            self.flags_image_type == "seco"
            and self.parent.parent.target_memory == TARGET_MEMORY_SERIAL_DOWNLOADER
        ):
            return 4

        return max([self.IMAGE_ALIGNMENTS[self._ahab_image.target_memory], 1024])

    def _get_valid_size(self, image: Optional[bytes]) -> int:
        """Get valid image size that will be stored.

        :return: AHAB valid image size
        """
        if not image:
            return 0
        return align(len(image), 4 if self.flags_image_type == "seco" else 1)

    def get_valid_offset(self, original_offset: int) -> int:
        """Get valid offset for AHAB container.

        :param original_offset: Offset that should be updated to valid one
        :return: AHAB valid offset
        """
        alignment = self.get_valid_alignment()
        alignment = max(
            alignment,
            self.parent.parent._database.get_int(
                DatabaseManager.AHAB, "valid_offset_minimal_alignment", 4
            ),
        )
        return align(original_offset, alignment)


class SRKRecord(HeaderContainerInversed):
    """Class representing SRK (Super Root Key) record as part of SRK table in the AHAB container.

    The class holds information about RSA/ECDSA signing algorithms.

    SRK Record::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |         Length of SRK         | Signing Algo   |
        +-----+---------------------------------------------------------------+
        |0x04 |    Hash Algo | Key Size/Curve |    Not Used  |   SRK Flags    |
        +-----+---------------------------------------------------------------+
        |0x08 | RSA modulus len / ECDSA X len | RSA exponent len / ECDSA Y len|
        +-----+---------------------------------------------------------------+
        |0x0C | RSA modulus (big endian) / ECDSA X (big endian)               |
        +-----+---------------------------------------------------------------+
        |...  | RSA exponent (big endian) / ECDSA Y (big endian)              |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SRK_RECORD.tag
    VERSION = [0x21, 0x27, 0x28]  # type: ignore
    VERSION_ALGORITHMS = {"rsa": 0x21, "ecdsa": 0x27, "sm2": 0x28}
    HASH_ALGORITHM = {
        EnumHashAlgorithm.SHA256: 0x0,
        EnumHashAlgorithm.SHA384: 0x1,
        EnumHashAlgorithm.SHA512: 0x2,
        EnumHashAlgorithm.SM3: 0x3,
    }
    ECC_KEY_TYPE = {EccCurve.SECP521R1: 0x3, EccCurve.SECP384R1: 0x2, EccCurve.SECP256R1: 0x1}
    RSA_KEY_TYPE = {2048: 0x5, 4096: 0x7}
    SM2_KEY_TYPE = 0x8
    KEY_SIZES = {
        0x1: (32, 32),
        0x2: (48, 48),
        0x3: (66, 66),
        0x5: (128, 128),
        0x7: (256, 256),
        0x8: (32, 32),
    }

    FLAGS_CA_MASK = 0x80

    def __init__(
        self,
        src_key: Optional[PublicKey] = None,
        signing_algorithm: str = "rsa",
        hash_type: EnumHashAlgorithm = EnumHashAlgorithm.SHA256,
        key_size: int = 0,
        srk_flags: int = 0,
        crypto_param1: bytes = b"",
        crypto_param2: bytes = b"",
    ):
        """Class object initializer.

        :param src_key: Optional source public key used to create the SRKRecord
        :param signing_algorithm: signing algorithm type.
        :param hash_type: hash algorithm type.
        :param key_size: key (curve) size.
        :param srk_flags: flags.
        :param crypto_param1: RSA modulus (big endian) or ECDSA X (big endian)
        :param crypto_param2: RSA exponent (big endian) or ECDSA Y (big endian)
        """
        super().__init__(
            tag=self.TAG, length=-1, version=self.VERSION_ALGORITHMS[signing_algorithm]
        )
        self.signing_algorithm = signing_algorithm
        self.src_key = src_key
        self.hash_algorithm = self.HASH_ALGORITHM[hash_type]
        self.key_size = key_size
        self.srk_flags = srk_flags
        self.crypto_param1 = crypto_param1
        self.crypto_param2 = crypto_param2

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SRKRecord):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self.hash_algorithm == other.hash_algorithm
                and self.key_size == other.key_size
                and self.srk_flags == other.srk_flags
                and self.crypto_param1 == other.crypto_param1
                and self.crypto_param2 == other.crypto_param2
            ):
                return True

        return False

    def __len__(self) -> int:
        return super().__len__() + len(self.crypto_param1) + len(self.crypto_param2)

    def __repr__(self) -> str:
        return f"AHAB SRK record, key: {self.get_key_name()}"

    def __str__(self) -> str:
        return (
            "AHAB SRK Record:\n"
            f"  Key:                {self.get_key_name()}\n"
            f"  SRK flags:          {hex(self.srk_flags)}\n"
            f"  Param 1 value:      {self.crypto_param1.hex()})\n"
            f"  Param 2 value:      {self.crypto_param2.hex()})\n"
        )

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()
            + UINT8  # Hash Algorithm
            + UINT8  # Key Size / Curve
            + UINT8  # Not Used
            + UINT8  # SRK Flags
            + UINT16  # crypto_param2_len
            + UINT16  # crypto_param1_len
        )

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        self.length = len(self)

    def export(self) -> bytes:
        """Export one SRK record, little big endian format.

        The crypto parameters (X/Y for ECDSA or modulus/exponent) are kept in
        big endian form.

        :return: bytes representing container content.
        """
        return (
            pack(
                self.format(),
                self.tag,
                self.length,
                self.version,
                self.hash_algorithm,
                self.key_size,
                RESERVED,
                self.srk_flags,
                len(self.crypto_param1),
                len(self.crypto_param2),
            )
            + self.crypto_param1
            + self.crypto_param2
        )

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()
        if self.hash_algorithm is None or not check_range(self.hash_algorithm, end=2):
            raise SPSDKValueError(f"SRK record: Invalid Hash algorithm: {self.hash_algorithm}")

        if self.srk_flags is None or not check_range(self.srk_flags, end=0xFF):
            raise SPSDKValueError(f"SRK record: Invalid Flags: {self.srk_flags}")

        if self.version == 0x21:  # Signing algorithm RSA
            if self.key_size not in self.RSA_KEY_TYPE.values():
                raise SPSDKValueError(
                    f"SRK record: Invalid Key size in match to RSA signing algorithm: {self.key_size}"
                )
        elif self.version == 0x27:  # Signing algorithm ECDSA
            if self.key_size not in self.ECC_KEY_TYPE.values():
                raise SPSDKValueError(
                    f"SRK record: Invalid Key size in match to ECDSA signing algorithm: {self.key_size}"
                )
        elif self.version == 0x28:  # Signing algorithm SM2
            if self.key_size != self.SM2_KEY_TYPE:
                raise SPSDKValueError(
                    f"SRK record: Invalid Key size in match to SM2 signing algorithm: {self.key_size}"
                )
        else:
            raise SPSDKValueError(f"SRK record: Invalid Signing algorithm: {self.version}")

        # Check lengths

        if (
            self.crypto_param1 is None
            or len(self.crypto_param1) != self.KEY_SIZES[self.key_size][0]
        ):
            raise SPSDKValueError(
                f"SRK record: Invalid Crypto parameter 1: 0x{self.crypto_param1.hex()}"
            )

        if (
            self.crypto_param2 is None
            or len(self.crypto_param2) != self.KEY_SIZES[self.key_size][1]
        ):
            raise SPSDKValueError(
                f"SRK record: Invalid Crypto parameter 2: 0x{self.crypto_param2.hex()}"
            )

        computed_length = (
            self.fixed_length()
            + self.KEY_SIZES[self.key_size][0]
            + self.KEY_SIZES[self.key_size][1]
        )
        if self.length != len(self) or self.length != computed_length:
            raise SPSDKValueError(
                f"SRK record: Invalid Length: Length of SRK:{self.length}"
                f", Computed Length of SRK:{computed_length}"
            )

    @staticmethod
    def create_from_key(public_key: PublicKey, srk_flags: int = 0) -> "SRKRecord":
        """Create instance from key data.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        :raises SPSDKValueError: Unsupported keys size is detected.
        """
        if isinstance(public_key, PublicKeyRsa):
            par_n: int = public_key.public_numbers.n
            par_e: int = public_key.public_numbers.e
            key_size = SRKRecord.RSA_KEY_TYPE[public_key.key_size]
            return SRKRecord(
                src_key=public_key,
                signing_algorithm="rsa",
                hash_type=EnumHashAlgorithm.SHA256,
                key_size=key_size,
                srk_flags=srk_flags,
                crypto_param1=par_n.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
                ),
                crypto_param2=par_e.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][1], byteorder=Endianness.BIG.value
                ),
            )

        elif isinstance(public_key, PublicKeyEcc):
            par_x: int = public_key.x
            par_y: int = public_key.y
            key_size = SRKRecord.ECC_KEY_TYPE[public_key.curve]

            if not public_key.key_size in [256, 384, 521]:
                raise SPSDKValueError(
                    f"Unsupported ECC key for AHAB container: {public_key.key_size}"
                )
            hash_type = {
                256: EnumHashAlgorithm.SHA256,
                384: EnumHashAlgorithm.SHA384,
                521: EnumHashAlgorithm.SHA512,
            }[public_key.key_size]

            return SRKRecord(
                signing_algorithm="ecdsa",
                hash_type=hash_type,
                key_size=key_size,
                srk_flags=srk_flags,
                crypto_param1=par_x.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][0], byteorder=Endianness.BIG.value
                ),
                crypto_param2=par_y.to_bytes(
                    length=SRKRecord.KEY_SIZES[key_size][1], byteorder=Endianness.BIG.value
                ),
            )

        assert isinstance(public_key, PublicKeySM2), "Unsupported public key for SRK record"
        param1: bytes = value_to_bytes("0x" + public_key.public_numbers[:64], byte_cnt=32)
        param2: bytes = value_to_bytes("0x" + public_key.public_numbers[64:], byte_cnt=32)
        assert len(param1 + param2) == 64, "Invalid length of the SM2 key"
        key_size = SRKRecord.SM2_KEY_TYPE
        return SRKRecord(
            src_key=public_key,
            signing_algorithm="sm2",
            hash_type=EnumHashAlgorithm.SM3,
            key_size=key_size,
            srk_flags=srk_flags,
            crypto_param1=param1,
            crypto_param2=param2,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with SRK record block to parse.
        :raises SPSDKLengthError: Invalid length of SRK record data block.
        :return: SRK record recreated from the binary data.
        """
        SRKRecord.check_container_head(data)
        (
            _,  # tag
            container_length,
            signing_algo,
            hash_algo,
            key_size_curve,
            _,  # reserved
            srk_flags,
            crypto_param1_len,
            crypto_param2_len,
        ) = unpack(SRKRecord.format(), data[: SRKRecord.fixed_length()])

        # Although we know from the total length, that we have enough bytes,
        # the crypto param lengths may be set improperly and we may get into trouble
        # while parsing. So we need to check the lengths as well.
        param_length = SRKRecord.fixed_length() + crypto_param1_len + crypto_param2_len
        if container_length < param_length:
            raise SPSDKLengthError(
                "Parsing error of SRK Record data."
                "SRK record lengths mismatch. Sum of lengths declared in container "
                f"({param_length} (= {SRKRecord.fixed_length()} + {crypto_param1_len} + "
                f"{crypto_param2_len})) doesn't match total length declared in container ({container_length})!"
            )
        crypto_param1 = data[
            SRKRecord.fixed_length() : SRKRecord.fixed_length() + crypto_param1_len
        ]
        crypto_param2 = data[
            SRKRecord.fixed_length()
            + crypto_param1_len : SRKRecord.fixed_length()
            + crypto_param1_len
            + crypto_param2_len
        ]

        return cls(
            signing_algorithm=get_key_by_val(SRKRecord.VERSION_ALGORITHMS, signing_algo),
            hash_type=get_key_by_val(SRKRecord.HASH_ALGORITHM, hash_algo),
            key_size=key_size_curve,
            srk_flags=srk_flags,
            crypto_param1=crypto_param1,
            crypto_param2=crypto_param2,
        )

    def get_key_name(self) -> str:
        """Get text key name in SRK record.

        :return: Key name.
        """
        if get_key_by_val(self.VERSION_ALGORITHMS, self.version) == "rsa":
            return f"rsa{get_key_by_val(self.RSA_KEY_TYPE, self.key_size)}"
        if get_key_by_val(self.VERSION_ALGORITHMS, self.version) == "ecdsa":
            return get_key_by_val(self.ECC_KEY_TYPE, self.key_size)
        if get_key_by_val(self.VERSION_ALGORITHMS, self.version) == "sm2":
            return "sm2"
        return "Unknown Key name!"

    def get_public_key(self, encoding: SPSDKEncoding = SPSDKEncoding.PEM) -> bytes:
        """Store the SRK public key as a file.

        :param encoding: Public key encoding style, default is PEM.
        :raises SPSDKError: Unsupported public key
        """
        par1 = int.from_bytes(self.crypto_param1, Endianness.BIG.value)
        par2 = int.from_bytes(self.crypto_param2, Endianness.BIG.value)
        key: Union[PublicKey, PublicKeyEcc, PublicKeyRsa, PublicKeySM2]
        if get_key_by_val(self.VERSION_ALGORITHMS, self.version) == "rsa":
            # RSA Key to store
            key = PublicKeyRsa.recreate(par1, par2)
        elif get_key_by_val(self.VERSION_ALGORITHMS, self.version) == "ecdsa":
            # ECDSA Key to store
            curve = get_key_by_val(self.ECC_KEY_TYPE, self.key_size)
            key = PublicKeyEcc.recreate(par1, par2, curve=curve)
        elif get_key_by_val(self.VERSION_ALGORITHMS, self.version) == "sm2" and IS_OSCCA_SUPPORTED:
            encoding = SPSDKEncoding.DER
            key = PublicKeySM2.recreate(self.crypto_param1 + self.crypto_param2)

        return key.export(encoding=encoding)


class SRKTable(HeaderContainerInversed):
    """Class representing SRK (Super Root Key) table in the AHAB container as part of signature block.

    SRK Table::

        +-----+---------------------------------------------------------------+
        |Off  |    Byte 3    |    Byte 2      |    Byte 1    |     Byte 0     |
        +-----+---------------------------------------------------------------+
        |0x00 |    Tag       |         Length of SRK Table   |     Version    |
        +-----+---------------------------------------------------------------+
        |0x04 |    SRK Record 1                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 2                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 3                                               |
        +-----+---------------------------------------------------------------+
        |...  |    SRK Record 4                                               |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SRK_TABLE.tag
    VERSION = 0x42
    SRK_RECORDS_CNT = 4

    def __init__(self, srk_records: Optional[List[SRKRecord]] = None) -> None:
        """Class object initializer.

        :param srk_records: list of SRKRecord objects.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._srk_records: List[SRKRecord] = srk_records or []
        self.length = len(self)

    def __repr__(self) -> str:
        return f"AHAB SRK TABLE, keys count: {len(self._srk_records)}"

    def __str__(self) -> str:
        return (
            "AHAB SRK table:\n"
            f"  Keys count:         {len(self._srk_records)}\n"
            f"  Length:             {self.length}\n"
            f"SRK table HASH:       {self.compute_srk_hash().hex()}"
        )

    def clear(self) -> None:
        """Clear the SRK Table Object."""
        self._srk_records.clear()
        self.length = -1

    def add_record(self, public_key: PublicKey, srk_flags: int = 0) -> None:
        """Add SRK table record.

        :param public_key: Loaded public key.
        :param srk_flags: SRK flags for key.
        """
        self._srk_records.append(
            SRKRecord.create_from_key(public_key=public_key, srk_flags=srk_flags)
        )
        self.length = len(self)

    def __eq__(self, other: object) -> bool:
        """Compares for equality with other SRK Table objects.

        :param other: object to compare with.
        :return: True on match, False otherwise.
        """
        if isinstance(other, SRKTable):
            if super().__eq__(other) and self._srk_records == other._srk_records:
                return True

        return False

    def __len__(self) -> int:
        records_len = 0
        for record in self._srk_records:
            records_len += len(record)
        return super().__len__() + records_len

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        for rec in self._srk_records:
            rec.update_fields()
        self.length = len(self)

    def compute_srk_hash(self) -> bytes:
        """Computes a SHA256 out of all SRK records.

        :return: SHA256 computed over SRK records.
        """
        return get_hash(data=self.export(), algorithm=EnumHashAlgorithm.SHA256)

    def get_source_keys(self) -> List[PublicKey]:
        """Return list of source public keys.

        Either from the src_key field or recreate them.
        :return: List of public keys.
        """
        ret = []
        for srk in self._srk_records:
            if srk.src_key:
                # return src key if available
                ret.append(srk.src_key)
            else:
                # recreate the key
                ret.append(PublicKey.parse(srk.get_public_key()))
        return ret

    def export(self) -> bytes:
        """Serializes container object into bytes in little endian.

        :return: bytes representing container content.
        """
        data = pack(self.format(), self.tag, self.length, self.version)

        for srk_record in self._srk_records:
            data += srk_record.export()

        return data

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()
        if self._srk_records is None or len(self._srk_records) != self.SRK_RECORDS_CNT:
            raise SPSDKValueError(f"SRK table: Invalid SRK records: {self._srk_records}")

        # Validate individual SRK records
        for srk_rec in self._srk_records:
            srk_rec.validate()

        # Check if all SRK records has same type
        srk_records_info = [
            (x.version, x.hash_algorithm, x.key_size, x.length, x.srk_flags)
            for x in self._srk_records
        ]

        messages = ["Signing algorithm", "Hash algorithm", "Key Size", "Length", "Flags"]
        for i in range(4):
            if not all(srk_records_info[0][i] == x[i] for x in srk_records_info):
                raise SPSDKValueError(
                    f"SRK table: SRK records haven't same {messages[i]}: {[x[i] for x in srk_records_info]}"
                )

        if "srkh_sha_supports" in data.keys():
            if (
                get_key_by_val(SRKRecord.HASH_ALGORITHM, self._srk_records[0].hash_algorithm).label
                not in data["srkh_sha_supports"]
            ):
                raise SPSDKValueError(
                    "SRK table: SRK records haven't supported hash algorithm:"
                    f" Used:{self._srk_records[0].hash_algorithm} is not member of"
                    f" {data['srkh_sha_supports']}"
                )
        # Check container length
        if self.length != len(self):
            raise SPSDKValueError(
                f"SRK table: Invalid Length of SRK table: {self.length} != {len(self)}"
            )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with SRK table block to parse.
        :raises SPSDKLengthError: Invalid length of SRK table data block.
        :return: Object recreated from the binary data.
        """
        SRKTable.check_container_head(data)
        srk_rec_offset = SRKTable.fixed_length()
        _, container_length, _ = unpack(SRKTable.format(), data[:srk_rec_offset])
        if ((container_length - srk_rec_offset) % SRKTable.SRK_RECORDS_CNT) != 0:
            raise SPSDKLengthError("SRK table: Invalid length of SRK records data.")
        srk_rec_size = math.ceil((container_length - srk_rec_offset) / SRKTable.SRK_RECORDS_CNT)

        # try to parse records
        srk_records: List[SRKRecord] = []
        for _ in range(SRKTable.SRK_RECORDS_CNT):
            srk_record = SRKRecord.parse(data[srk_rec_offset:])
            srk_rec_offset += srk_rec_size
            srk_records.append(srk_record)

        return cls(srk_records=srk_records)

    def create_config(self, index: int, data_path: str) -> Dict[str, Any]:
        """Create configuration of the AHAB Image SRK Table.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg: Dict[str, Union[List, bool]] = {}
        cfg_srks = []

        ret_cfg["flag_ca"] = bool(self._srk_records[0].srk_flags & SRKRecord.FLAGS_CA_MASK)

        for ix_srk, srk in enumerate(self._srk_records):
            filename = f"container{index}_srk_public_key{ix_srk}_{srk.get_key_name()}.PEM"
            write_file(data=srk.get_public_key(), path=os.path.join(data_path, filename), mode="wb")
            cfg_srks.append(filename)

        ret_cfg["srk_array"] = cfg_srks
        return ret_cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "SRKTable":
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: SRK Table object.
        """
        srk_table = SRKTable()
        flags = 0
        flag_ca = config.get("flag_ca", False)
        if flag_ca:
            flags |= SRKRecord.FLAGS_CA_MASK
        srk_list = config.get("srk_array")
        assert isinstance(srk_list, list)
        for srk_key in srk_list:
            assert isinstance(srk_key, str)
            srk_key_path = find_file(srk_key, search_paths=search_paths)
            srk_table.add_record(extract_public_key(srk_key_path), srk_flags=flags)
        return srk_table


class ContainerSignature(HeaderContainer):
    """Class representing the signature in AHAB container as part of the signature block.

    Signature::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 |                        Reserved                               |
        +-----+---------------------------------------------------------------+
        |0x08 |                      Signature Data                           |
        +-----+---------------------------------------------------------------+

    """

    TAG = AHABTags.SIGNATURE.tag
    VERSION = 0x00

    def __init__(
        self,
        signature_data: Optional[bytes] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ) -> None:
        """Class object initializer.

        :param signature_data: signature.
        :param signature_provider: Signature provider use to sign the image.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._signature_data = signature_data or b""
        self.signature_provider = signature_provider
        self.length = len(self)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ContainerSignature):
            if super().__eq__(other) and self._signature_data == other._signature_data:
                return True

        return False

    def __len__(self) -> int:
        if (not self._signature_data or len(self._signature_data) == 0) and self.signature_provider:
            return super().__len__() + self.signature_provider.signature_length

        sign_data_len = len(self._signature_data)
        if sign_data_len == 0:
            return 0

        return super().__len__() + sign_data_len

    def __repr__(self) -> str:
        return "AHAB Container Signature"

    def __str__(self) -> str:
        return (
            "AHAB Container Signature:\n"
            f"  Signature provider: {self.signature_provider.info() if self.signature_provider else 'Not available'}\n"
            f"  Signature:          {self.signature_data.hex() if self.signature_data else 'Not available'}"
        )

    @property
    def signature_data(self) -> bytes:
        """Get the signature data.

        :return: signature data.
        """
        return self._signature_data

    @signature_data.setter
    def signature_data(self, value: bytes) -> None:
        """Set the signature data.

        :param value: signature data.
        """
        self._signature_data = value
        self.length = len(self)

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return super().format() + UINT32  # reserved

    def sign(self, data_to_sign: bytes) -> None:
        """Sign the data_to_sign and store signature into class.

        :param data_to_sign: Data to be signed by store private key
        :raises SPSDKError: Missing private key or raw signature data.
        """
        if not self.signature_provider and len(self._signature_data) == 0:
            raise SPSDKError(
                "The Signature container doesn't have specified the private key to sign."
            )

        if self.signature_provider:
            self._signature_data = self.signature_provider.get_signature(data_to_sign)

    def export(self) -> bytes:
        """Export signature data that is part of Signature Block.

        :return: bytes representing container signature content.
        """
        if len(self) == 0:
            return b""

        data = (
            pack(
                self.format(),
                self.version,
                self.length,
                self.tag,
                RESERVED,
            )
            + self._signature_data
        )

        return data

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()
        if self._signature_data is None or len(self._signature_data) < 20:
            raise SPSDKValueError(
                f"Signature: Invalid Signature data: 0x{self.signature_data.hex()}"
            )
        if self.length != len(self):
            raise SPSDKValueError(
                f"Signature: Invalid Signature length: {self.length} != {len(self)}."
            )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with Container signature block to parse.
        :return: Object recreated from the binary data.
        """
        ContainerSignature.check_container_head(data)
        fix_len = ContainerSignature.fixed_length()

        _, container_length, _, _ = unpack(ContainerSignature.format(), data[:fix_len])
        signature_data = data[fix_len:container_length]

        return cls(signature_data=signature_data)

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "ContainerSignature":
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Container signature object.
        """
        signature_provider = get_signature_provider(
            sp_cfg=config.get("signature_provider"),
            local_file_key=config.get("signing_key"),
            search_paths=search_paths,
        )
        assert signature_provider
        return ContainerSignature(signature_provider=signature_provider)


class Certificate(HeaderContainer):
    """Class representing certificate in the AHAB container as part of the signature block.

    The Certificate comes in two forms - with and without UUID.

    Certificate format 1::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 | Permissions  | Perm (invert)|      Signature offset           |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                        Public Key                             |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature                              |
        +-----+---------------------------------------------------------------+

    Certificate format 2::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 | Permissions  | Perm (invert)|      Signature offset           |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                            UUID                               |
        +-----+---------------------------------------------------------------+
        |...  |                        Public Key                             |
        +-----+---------------------------------------------------------------+
        |...  |                        Signature                              |
        +-----+---------------------------------------------------------------+

    """

    TAG = [AHABTags.CERTIFICATE_UUID.tag, AHABTags.CERTIFICATE_NON_UUID.tag]  # type: ignore
    UUID_LEN = 16
    UUID_OFFSET = 0x08
    VERSION = 0x00
    PERM_NXP = {
        "secure_enclave_debug": 0x02,
        "hdmi_debug": 0x04,
        "life_cycle": 0x10,
        "hdcp_fuses": 0x20,
    }
    PERM_OEM = {
        "container": 0x01,
        "phbc_debug": 0x02,
        "soc_debug_domain_1": 0x04,
        "soc_debug_domain_2": 0x08,
        "life_cycle": 0x10,
        "monotonic_counter": 0x20,
    }
    PERM_SIZE = 8

    def __init__(
        self,
        permissions: int = 0,
        uuid: Optional[bytes] = None,
        public_key: Optional[SRKRecord] = None,
        signature_provider: Optional[SignatureProvider] = None,
    ):
        """Class object initializer.

        :param permissions: used to indicate what a certificate can be used for.
        :param uuid: optional 128-bit unique identifier.
        :param public_key: public Key. SRK record entry describing the key.
        :param signature_provider: Signature provider for certificate. Signature is calculated over
            all data from beginning of the certificate up to, but not including the signature.
        """
        tag = AHABTags.CERTIFICATE_UUID.tag if uuid else AHABTags.CERTIFICATE_NON_UUID.tag
        super().__init__(tag=tag, length=-1, version=self.VERSION)
        self._permissions = permissions
        self.signature_offset = -1
        self._uuid = uuid
        self.public_key = public_key
        self.signature = ContainerSignature(
            signature_data=b"", signature_provider=signature_provider
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Certificate):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self._permissions == other._permissions
                and self.signature_offset == other.signature_offset
                and self._uuid == other._uuid
                and self.public_key == other.public_key
                and self.signature == other.signature
            ):
                return True

        return False

    def __repr__(self) -> str:
        return "AHAB Certificate"

    def __str__(self) -> str:
        return (
            "AHAB Certificate:\n"
            f"  Permission:         {hex(self._permissions)}\n"
            f"  UUID:               {self._uuid.hex() if self._uuid else 'Not Available'}\n"
            f"  Public Key:         {str(self.public_key) if self.public_key else 'Not available'}\n"
            f"  Signature:          {str(self.signature) if self.signature else 'Not available'}"
        )

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()  # endianness, header: version, length, tag
            + UINT16  # signature offset
            + UINT8  # inverted permissions
            + UINT8  # permissions
        )

    def __len__(self) -> int:
        assert self.public_key
        uuid_len = len(self._uuid) if self._uuid else 0
        return super().__len__() + uuid_len + len(self.public_key) + len(self.signature)

    @staticmethod
    def create_permissions(permissions: List[str]) -> int:
        """Create integer representation of permission field.

        :param permissions: List of string permissions.
        :return: Integer representation of permissions.
        """
        ret = 0
        permission_map = {}
        permission_map.update(Certificate.PERM_NXP)
        permission_map.update(Certificate.PERM_OEM)
        for permission in permissions:
            ret |= permission_map[permission]

        return ret

    @property
    def permission_to_sign_container(self) -> bool:
        """Certificate has permission to sign container."""
        return bool(self._permissions & self.PERM_OEM["container"])

    def create_config_permissions(self, srk_set: str) -> List[str]:
        """Create list of string representation of permission field.

        :param srk_set: SRK set to get proper string values.
        :return: List of string representation of permissions.
        """
        ret = []
        perm_maps = {"nxp": self.PERM_NXP, "oem": self.PERM_OEM}
        perm_map = perm_maps.get(srk_set)

        for i in range(self.PERM_SIZE):
            if self._permissions & (1 << i):
                ret.append(
                    get_key_by_val(perm_map, 1 << i)
                    if perm_map and (1 << i) in perm_map.values()
                    else f"Unknown permission {hex(1<<i)}"
                )

        return ret

    def get_signature_data(self) -> bytes:
        """Returns binary data to be signed.

        The certificate block must be properly initialized, so the data are valid for
        signing. There is signed whole certificate block without signature part.


        :raises SPSDKValueError: if Signature Block or SRK Table is missing.
        :return: bytes representing data to be signed.
        """
        assert self.public_key
        cert_data_to_sign = (
            pack(
                self.format(),
                self.version,
                self.length,
                self.tag,
                self.signature_offset,
                ~self._permissions & 0xFF,
                self._permissions,
            )
            + self.public_key.export()
        )
        # if uuid is present, insert it into the cert data
        if self._uuid:
            cert_data_to_sign = (
                cert_data_to_sign[: self.UUID_OFFSET]
                + self._uuid
                + cert_data_to_sign[self.UUID_OFFSET :]
            )

        return cert_data_to_sign

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        assert self.public_key
        self.public_key.update_fields()
        self.tag = (
            AHABTags.CERTIFICATE_UUID.tag if self._uuid else AHABTags.CERTIFICATE_NON_UUID.tag
        )
        self.signature_offset = (
            super().__len__() + (len(self._uuid) if self._uuid else 0) + len(self.public_key)
        )
        self.length = len(self)
        self.signature.sign(self.get_signature_data())

    def export(self) -> bytes:
        """Export container certificate object into bytes.

        :return: bytes representing container content.
        """
        assert self.public_key
        cert = (
            pack(
                self.format(),
                self.version,
                self.length,
                self.tag,
                self.signature_offset,
                ~self._permissions & 0xFF,
                self._permissions,
            )
            + self.public_key.export()
            + self.signature.export()
        )
        # if uuid is present, insert it into the cert data
        if self._uuid:
            cert = cert[: self.UUID_OFFSET] + self._uuid + cert[self.UUID_OFFSET :]
        assert self.length == len(cert)
        return cert

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()
        if self._permissions is None or not check_range(self._permissions, end=0xFF):
            raise SPSDKValueError(f"Certificate: Invalid Permission data: {self._permissions}")
        if self.public_key is None:
            raise SPSDKValueError("Certificate: Missing public key.")
        self.public_key.validate()

        if not self.signature:
            raise SPSDKValueError("Signature must be provided")

        self.signature.validate()

        expected_signature_offset = (
            super().__len__() + (len(self._uuid) if self._uuid else 0) + len(self.public_key)
        )
        if self.signature_offset != expected_signature_offset:
            raise SPSDKValueError(
                f"Certificate: Invalid signature offset. "
                f"{self.signature_offset} != {expected_signature_offset}"
            )
        if self._uuid and len(self._uuid) != self.UUID_LEN:
            raise SPSDKValueError(
                f"Certificate: Invalid UUID size. {len(self._uuid)} != {self.UUID_LEN}"
            )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with Certificate block to parse.
        :raises SPSDKValueError: Certificate permissions are invalid.
        :return: Object recreated from the binary data.
        """
        Certificate.check_container_head(data)
        certificate_data_offset = Certificate.fixed_length()
        image_format = Certificate.format()
        (
            _,  # version,
            container_length,
            tag,
            signature_offset,
            inverted_permissions,
            permissions,
        ) = unpack(image_format, data[:certificate_data_offset])

        if inverted_permissions != ~permissions & 0xFF:
            raise SPSDKValueError("Certificate parser: Invalid permissions record.")

        uuid = None

        if AHABTags.CERTIFICATE_UUID == tag:
            uuid = data[certificate_data_offset : certificate_data_offset + Certificate.UUID_LEN]
            certificate_data_offset += Certificate.UUID_LEN

        public_key = SRKRecord.parse(data[certificate_data_offset:])

        signature = ContainerSignature.parse(data[signature_offset:container_length])

        cert = cls(
            permissions=permissions,
            uuid=uuid,
            public_key=public_key,
        )
        cert.signature = signature
        return cert

    def create_config(self, index: int, data_path: str, srk_set: str = "oem") -> Dict[str, Any]:
        """Create configuration of the AHAB Image Certificate.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :param srk_set: SRK set to know how to create certificate permissions.
        :return: Configuration dictionary.
        """
        ret_cfg: Dict[str, Any] = {}
        assert self.public_key
        ret_cfg["permissions"] = self.create_config_permissions(srk_set)
        if self._uuid:
            ret_cfg["uuid"] = "0x" + self._uuid.hex()
        filename = f"container{index}_certificate_public_key_{self.public_key.get_key_name()}.PEM"
        write_file(
            data=self.public_key.get_public_key(), path=os.path.join(data_path, filename), mode="wb"
        )
        ret_cfg["public_key"] = filename
        ret_cfg["signature_provider"] = "N/A"

        return ret_cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "Certificate":
        """Converts the configuration option into an AHAB image signature block certificate object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Certificate object.
        """
        cert_permissions_list = config.get("permissions", [])
        cert_uuid_raw = config.get("uuid")
        cert_uuid = value_to_bytes(cert_uuid_raw) if cert_uuid_raw else None
        cert_public_key_path = config.get("public_key")
        assert isinstance(cert_public_key_path, str)
        cert_public_key_path = find_file(cert_public_key_path, search_paths=search_paths)
        cert_public_key = extract_public_key(cert_public_key_path)
        cert_srk_rec = SRKRecord.create_from_key(cert_public_key)
        cert_signature_provider = get_signature_provider(
            config.get("signature_provider"),
            config.get("signing_key"),
            search_paths=search_paths,
        )
        return Certificate(
            permissions=Certificate.create_permissions(cert_permissions_list),
            uuid=cert_uuid,
            public_key=cert_srk_rec,
            signature_provider=cert_signature_provider,
        )

    @staticmethod
    def get_validation_schemas() -> List[Dict[str, Any]]:
        """Get list of validation schemas.

        :return: Validation list of schemas.
        """
        return [DatabaseManager().db.get_schema_file(DatabaseManager.AHAB)["ahab_certificate"]]

    @staticmethod
    def generate_config_template() -> str:
        """Generate AHAB configuration template.

        :return: Certificate configuration templates.
        """
        yaml_data = CommentedConfig(
            "Advanced High-Assurance Boot Certificate Configuration template.",
            Certificate.get_validation_schemas(),
        ).get_template()

        return yaml_data


class Blob(HeaderContainer):
    """The Blob object used in Signature Container.

    Blob (DEK) content::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 |    Mode      | Algorithm    |      Size      |     Flags      |
        +-----+--------------+--------------+----------------+----------------+
        |0x08 |                        Wrapped Key                            |
        +-----+--------------+--------------+----------------+----------------+

    """

    TAG = AHABTags.BLOB.tag
    VERSION = 0x00
    FLAGS = 0x80  # KEK key flag
    SUPPORTED_KEY_SIZES = [128, 192, 256]

    def __init__(
        self,
        flags: int = 0x80,
        size: int = 0,
        algorithm: KeyBlobEncryptionAlgorithm = KeyBlobEncryptionAlgorithm.AES_CBC,
        mode: int = 0,
        dek: Optional[bytes] = None,
        dek_keyblob: Optional[bytes] = None,
        key_identifier: int = 0,
    ) -> None:
        """Class object initializer.

        :param flags: Keyblob flags
        :param size: key size [128,192,256]
        :param dek: DEK key
        :param mode: DEK BLOB mode
        :param algorithm: Encryption algorithm
        :param dek_keyblob: DEK keyblob
        :param key_identifier: Key identifier. Must be same as it was used for keyblob generation
        """
        super().__init__(tag=self.TAG, length=56 + size // 8, version=self.VERSION)
        self.mode = mode
        self.algorithm = algorithm
        self._size = size
        self.flags = flags
        self.dek = dek
        self.dek_keyblob = dek_keyblob or b""
        self.key_identifier = key_identifier

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Blob):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self.mode == other.mode
                and self.algorithm == other.algorithm
                and self._size == other._size
                and self.flags == other.flags
                and self.dek_keyblob == other.dek_keyblob
                and self.key_identifier == other.key_identifier
            ):
                return True

        return False

    def __repr__(self) -> str:
        return "AHAB Blob"

    def __str__(self) -> str:
        return (
            "AHAB Blob:\n"
            f"  Mode:               {self.mode}\n"
            f"  Algorithm:          {self.algorithm.label}\n"
            f"  Key Size:           {self._size}\n"
            f"  Flags:              {self.flags}\n"
            f"  Key identifier:     {hex(self.key_identifier)}\n"
            f"  DEK keyblob:        {self.dek_keyblob.hex() if self.dek_keyblob else 'N/A'}"
        )

    @staticmethod
    def compute_keyblob_size(key_size: int) -> int:
        """Compute Keyblob size.

        :param key_size: Input AES key size in bits
        :return: Keyblob size in bytes.
        """
        return (key_size // 8) + 48

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()  # endianness, header: tag, length, version
            + UINT8  # mode
            + UINT8  # algorithm
            + UINT8  # size
            + UINT8  # flags
        )

    def __len__(self) -> int:
        # return super()._total_length() + len(self.dek_keyblob)
        return self.length

    def export(self) -> bytes:
        """Export Signature Block Blob.

        :return: bytes representing Signature Block Blob.
        """
        blob = (
            pack(
                self.format(),
                self.version,
                self.length,
                self.tag,
                self.flags,
                self._size // 8,
                self.algorithm.tag,
                self.mode,
            )
            + self.dek_keyblob
        )

        return blob

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of AHAB Blob
        """
        self.validate_header()

        if self._size not in self.SUPPORTED_KEY_SIZES:
            raise SPSDKValueError("AHAB Blob: Invalid key size.")
        if self.mode is None:
            raise SPSDKValueError("AHAB Blob: Invalid mode.")
        if self.algorithm is None:
            raise SPSDKValueError("AHAB Blob: Invalid algorithm.")
        if self.dek and len(self.dek) != self._size // 8:
            raise SPSDKValueError("AHAB Blob: Invalid DEK key size.")
        if self.dek_keyblob is None or len(self.dek_keyblob) != self.compute_keyblob_size(
            self._size
        ):
            raise SPSDKValueError("AHAB Blob: Invalid Wrapped key.")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with Blob block to parse.
        :return: Object recreated from the binary data.
        """
        Blob.check_container_head(data)
        (
            _,  # version
            container_length,
            _,  # tag
            flags,
            size,
            algorithm,  # algorithm
            mode,  # mode
        ) = unpack(Blob.format(), data[: Blob.fixed_length()])

        dek_keyblob = data[Blob.fixed_length() : container_length]

        return cls(
            size=size * 8,
            flags=flags,
            dek_keyblob=dek_keyblob,
            mode=mode,
            algorithm=KeyBlobEncryptionAlgorithm.from_tag(algorithm),
        )

    def create_config(self, index: int, data_path: str) -> Dict[str, Any]:
        """Create configuration of the AHAB Image Blob.

        :param index: Container Index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg: Dict[str, Any] = {}
        assert self.dek_keyblob
        filename = f"container{index}_dek_keyblob.bin"
        write_file(self.export(), os.path.join(data_path, filename), "wb")
        ret_cfg["dek_key_size"] = self._size
        ret_cfg["dek_key"] = "N/A"
        ret_cfg["dek_keyblob"] = filename
        ret_cfg["key_identifier"] = self.key_identifier

        return ret_cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "Blob":
        """Converts the configuration option into an AHAB image signature block blob object.

        "config" content of container configurations.

        :param config: Blob configuration
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKValueError: Invalid configuration - Invalid DEK KeyBlob
        :return: Blob object.
        """
        dek_size = value_to_int(config.get("dek_key_size", 128))
        dek_input = config.get("dek_key")
        dek_keyblob_input = config.get("dek_keyblob")
        key_identifier = config.get("key_identifier", 0)
        assert dek_input, "Missing DEK value"
        assert dek_keyblob_input, "Missing DEK KEYBLOB value"

        dek = load_hex_string(dek_input, dek_size // 8, search_paths)
        dek_keyblob_value = load_hex_string(
            dek_keyblob_input, Blob.compute_keyblob_size(dek_size) + 8, search_paths
        )
        if not dek_keyblob_value:
            raise SPSDKValueError("Invalid DEK KeyBlob.")

        keyblob = Blob.parse(dek_keyblob_value)
        keyblob.dek = dek
        keyblob.key_identifier = key_identifier
        return keyblob

    def encrypt_data(self, iv: bytes, data: bytes) -> bytes:
        """Encrypt data.

        :param iv: Initial vector 128 bits length
        :param data: Data to encrypt
        :raises SPSDKError: Missing DEK, unsupported algorithm
        :return: Encrypted data
        """
        if not self.dek:
            raise SPSDKError("The AHAB keyblob hasn't defined DEK to encrypt data")

        encryption_methods = {
            KeyBlobEncryptionAlgorithm.AES_CBC: aes_cbc_encrypt,
            KeyBlobEncryptionAlgorithm.SM4_CBC: sm4_cbc_encrypt,
        }

        if not encryption_methods.get(self.algorithm):
            raise SPSDKError(f"Unsupported encryption algorithm: {self.algorithm}")
        return encryption_methods[self.algorithm](self.dek, data, iv)

    def decrypt_data(self, iv: bytes, encrypted_data: bytes) -> bytes:
        """Encrypt data.

        :param iv: Initial vector 128 bits length
        :param encrypted_data: Data to decrypt
        :raises SPSDKError: Missing DEK, unsupported algorithm
        :return: Plain data
        """
        if not self.dek:
            raise SPSDKError("The AHAB keyblob hasn't defined DEK to encrypt data")

        decryption_methods = {
            KeyBlobEncryptionAlgorithm.AES_CBC: aes_cbc_decrypt,
            KeyBlobEncryptionAlgorithm.SM4_CBC: sm4_cbc_decrypt,
        }

        if not decryption_methods.get(self.algorithm):
            raise SPSDKError(f"Unsupported encryption algorithm: {self.algorithm}")
        return decryption_methods[self.algorithm](self.dek, encrypted_data, iv)


class SignatureBlock(HeaderContainer):
    """Class representing signature block in the AHAB container.

    Signature Block::

        +---------------+----------------+----------------+----------------+-----+
        |    Byte 3     |     Byte 2     |      Byte 1    |     Byte 0     | Fix |
        |---------------+----------------+----------------+----------------+ len |
        |      Tag      |              Length             |    Version     |     |
        |---------------+---------------------------------+----------------+     |
        |       SRK Table Offset         |         Certificate Offset      |     |
        |--------------------------------+---------------------------------+     |
        |          Blob Offset           |          Signature Offset       |     |
        |--------------------------------+---------------------------------+     |
        |              Key identifier in case that Blob is present         |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                             SRK Table                            |     |
        +------------------------------------------------------------------+-----+ Padding length
        |                          64 bit alignment                        |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                              Signature                           |     |
        +------------------------------------------------------------------+-----+ Padding length
        |                          64 bit alignment                        |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                              Certificate                         |     |
        +------------------------------------------------------------------+-----+ Padding length
        |                          64 bit alignment                        |     |
        +------------------------------------------------------------------+-----+ Starting offset
        |                              Blob                                |     |
        +------------------------------------------------------------------+-----+

    """

    TAG = AHABTags.SIGNATURE_BLOCK.tag
    VERSION = 0x00

    def __init__(
        self,
        srk_table: Optional["SRKTable"] = None,
        container_signature: Optional["ContainerSignature"] = None,
        certificate: Optional["Certificate"] = None,
        blob: Optional["Blob"] = None,
    ):
        """Class object initializer.

        :param srk_table: SRK table.
        :param container_signature: container signature.
        :param certificate: container certificate.
        :param blob: container blob.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self._srk_table_offset = 0
        self._certificate_offset = 0
        self._blob_offset = 0
        self.signature_offset = 0
        self.srk_table = srk_table
        self.signature = container_signature
        self.certificate = certificate
        self.blob = blob

    def __eq__(self, other: object) -> bool:
        """Compares for equality with other Signature Block objects.

        :param other: object to compare with.
        :return: True on match, False otherwise.
        """
        if isinstance(other, SignatureBlock):
            if (
                super().__eq__(other)  # pylint: disable=too-many-boolean-expressions
                and self._srk_table_offset == other._srk_table_offset
                and self._certificate_offset == other._certificate_offset
                and self._blob_offset == other._blob_offset
                and self.signature_offset == other.signature_offset
                and self.srk_table == other.srk_table
                and self.signature == other.signature
                and self.certificate == other.certificate
                and self.blob == other.blob
            ):
                return True

        return False

    def __len__(self) -> int:
        self.update_fields()
        return self.length

    def __repr__(self) -> str:
        return "AHAB Signature Block"

    def __str__(self) -> str:
        return (
            "AHAB Signature Block:\n"
            f"  SRK Table:          {bool(self.srk_table)}\n"
            f"  Certificate:        {bool(self.certificate)}\n"
            f"  Signature:          {bool(self.signature)}\n"
            f"  Blob:               {bool(self.blob)}"
        )

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()
            + UINT16  # certificate offset
            + UINT16  # SRK table offset
            + UINT16  # signature offset
            + UINT16  # blob offset
            + UINT32  # key_identifier if blob is used
        )

    def update_fields(self) -> None:
        """Update all fields depended on input values."""
        # 1: Update SRK Table
        # Nothing to do with SRK Table
        last_offset = 0
        last_block_size = align(calcsize(self.format()), CONTAINER_ALIGNMENT)
        if self.srk_table:
            self.srk_table.update_fields()
            last_offset = self._srk_table_offset = last_offset + last_block_size
            last_block_size = align(len(self.srk_table), CONTAINER_ALIGNMENT)
        else:
            self._srk_table_offset = 0

        # 2: Update Signature (at least length)
        # Nothing to do with Signature - in this time , it MUST be ready
        if self.signature:
            last_offset = self.signature_offset = last_offset + last_block_size
            last_block_size = align(len(self.signature), CONTAINER_ALIGNMENT)
        else:
            self.signature_offset = 0
        # 3: Optionally update Certificate
        if self.certificate:
            self.certificate.update_fields()
            last_offset = self._certificate_offset = last_offset + last_block_size
            last_block_size = align(len(self.certificate), CONTAINER_ALIGNMENT)
        else:
            self._certificate_offset = 0
        # 4: Optionally update Blob
        if self.blob:
            last_offset = self._blob_offset = last_offset + last_block_size
            last_block_size = align(len(self.blob), CONTAINER_ALIGNMENT)
        else:
            self._blob_offset = 0

        # 5: Update length of Signature block
        self.length = last_offset + last_block_size

    def export(self) -> bytes:
        """Export Signature block.

        :raises SPSDKLengthError: if exported data length doesn't match container length.
        :return: bytes signature block content.
        """
        extended_header = pack(
            self.format(),
            self.version,
            self.length,
            self.tag,
            self._certificate_offset,
            self._srk_table_offset,
            self.signature_offset,
            self._blob_offset,
            self.blob.key_identifier if self.blob else RESERVED,
        )

        signature_block = bytearray(len(self))
        signature_block[0 : self.fixed_length()] = extended_header
        if self.srk_table:
            signature_block[
                self._srk_table_offset : self._srk_table_offset + len(self.srk_table)
            ] = self.srk_table.export()
        if self.signature:
            signature_block[
                self.signature_offset : self.signature_offset + len(self.signature)
            ] = self.signature.export()
        if self.certificate:
            signature_block[
                self._certificate_offset : self._certificate_offset + len(self.certificate)
            ] = self.certificate.export()
        if self.blob:
            signature_block[
                self._blob_offset : self._blob_offset + len(self.blob)
            ] = self.blob.export()

        return signature_block

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """

        def check_offset(name: str, min_offset: int, offset: int) -> None:
            if offset < min_offset:
                raise SPSDKValueError(
                    f"Signature Block: Invalid {name} offset: {offset} < minimal offset {min_offset}"
                )
            if offset != align(offset, CONTAINER_ALIGNMENT):
                raise SPSDKValueError(
                    f"Signature Block: Invalid {name} offset alignment: {offset} is not aligned to 64 bits!"
                )

        self.validate_header()
        if self.length != len(self):
            raise SPSDKValueError(
                f"Signature Block: Invalid block length: {self.length} != {len(self)}"
            )
        if bool(self._srk_table_offset) != bool(self.srk_table):
            raise SPSDKValueError("Signature Block: Invalid setting of SRK table offset.")
        if bool(self.signature_offset) != bool(self.signature):
            raise SPSDKValueError("Signature Block: Invalid setting of Signature offset.")
        if bool(self._certificate_offset) != bool(self.certificate):
            raise SPSDKValueError("Signature Block: Invalid setting of Certificate offset.")
        if bool(self._blob_offset) != bool(self.blob):
            raise SPSDKValueError("Signature Block: Invalid setting of Blob offset.")

        min_offset = self.fixed_length()
        if self.srk_table:
            self.srk_table.validate(data)
            check_offset("SRK table", min_offset, self._srk_table_offset)
            min_offset = self._srk_table_offset + len(self.srk_table)
        if self.signature:
            self.signature.validate()
            check_offset("Signature", min_offset, self.signature_offset)
            min_offset = self.signature_offset + len(self.signature)
        if self.certificate:
            self.certificate.validate()
            check_offset("Certificate", min_offset, self._certificate_offset)
            min_offset = self._certificate_offset + len(self.certificate)
        if self.blob:
            self.blob.validate()
            check_offset("Blob", min_offset, self._blob_offset)
            min_offset = self._blob_offset + len(self.blob)

        if "flag_used_srk_id" in data.keys() and self.signature and self.srk_table:
            public_keys = self.srk_table.get_source_keys()
            if (
                self.signature.signature_provider
                and self.certificate
                and not self.certificate.permission_to_sign_container
            ):
                # Container is signed by SRK key. Get the matching key and verify that the private key
                # belongs to the public key in SRK
                srk_pair_id = get_matching_key_id(public_keys, self.signature.signature_provider)
                if srk_pair_id != data["flag_used_srk_id"]:
                    raise SPSDKValueError(
                        f"Signature Block: Configured SRK ID ({data['flag_used_srk_id']})"
                        f" doesn't match detected SRK ID for signing key ({srk_pair_id})."
                    )
            elif self.certificate and self.certificate.permission_to_sign_container:
                # In this case the certificate is signed by the key with given SRK ID
                if not public_keys[data["flag_used_srk_id"]].verify_signature(
                    self.certificate.signature.signature_data, self.certificate.get_signature_data()
                ):
                    raise SPSDKValueError(
                        f"Certificate signature cannot be verified with the key with SRK ID {data['flag_used_srk_id']} "
                    )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary chunk to the container object.

        :param data: Binary data with Signature block to parse.
        :return: Object recreated from the binary data.
        """
        SignatureBlock.check_container_head(data)
        (
            _,  # version
            _,  # container_length
            _,  # tag
            certificate_offset,
            srk_table_offset,
            signature_offset,
            blob_offset,
            key_identifier,
        ) = unpack(SignatureBlock.format(), data[: SignatureBlock.fixed_length()])

        signature_block = cls()
        signature_block.srk_table = (
            SRKTable.parse(data[srk_table_offset:]) if srk_table_offset else None
        )
        signature_block.certificate = (
            Certificate.parse(data[certificate_offset:]) if certificate_offset else None
        )
        signature_block.signature = (
            ContainerSignature.parse(data[signature_offset:]) if signature_offset else None
        )
        try:
            signature_block.blob = Blob.parse(data[blob_offset:]) if blob_offset else None
            if signature_block.blob:
                signature_block.blob.key_identifier = key_identifier
        except SPSDKParsingError as exc:
            logger.warning(
                "AHAB Blob parsing error. In case that no encrypted images"
                " are presented in container, it should not be an big issue."
                f"\n{str(exc)}"
            )
            signature_block.blob = None

        return signature_block

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "SignatureBlock":
        """Converts the configuration option into an AHAB Signature block object.

        "config" content of container configurations.

        :param config: array of AHAB signature block configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: AHAB Signature block object.
        """
        signature_block = SignatureBlock()
        # SRK Table
        srk_table_cfg = config.get("srk_table")
        signature_block.srk_table = (
            SRKTable.load_from_config(srk_table_cfg, search_paths) if srk_table_cfg else None
        )

        # Container Signature
        srk_set = config.get("srk_set", "none")
        signature_block.signature = (
            ContainerSignature.load_from_config(config, search_paths) if srk_set != "none" else None
        )

        # Certificate Block
        signature_block.certificate = None
        certificate_cfg = config.get("certificate")

        if certificate_cfg:
            try:
                cert_cfg = load_configuration(certificate_cfg)
                check_config(
                    cert_cfg, Certificate.get_validation_schemas(), search_paths=search_paths
                )
                signature_block.certificate = Certificate.load_from_config(cert_cfg)
            except SPSDKError:
                # this could be pre-exported binary certificate :-)
                signature_block.certificate = Certificate.parse(
                    load_binary(certificate_cfg, search_paths)
                )

        # DEK blob
        blob_cfg = config.get("blob")
        signature_block.blob = Blob.load_from_config(blob_cfg, search_paths) if blob_cfg else None

        return signature_block


class AHABContainerBase(HeaderContainer):
    """Class representing AHAB container base class (common for Signed messages and AHAB Image).

    Container header::

        +---------------+----------------+----------------+----------------+
        |    Byte 3     |     Byte 2     |      Byte 1    |     Byte 0     |
        +---------------+----------------+----------------+----------------+
        |      Tag      |              Length             |    Version     |
        +---------------+---------------------------------+----------------+
        |                              Flags                               |
        +---------------+----------------+---------------------------------+
        |  # of images  |  Fuse version  |             SW version          |
        +---------------+----------------+---------------------------------+
        |              Reserved          |       Signature Block Offset    |
        +--------------------------------+---------------------------------+
        |             Payload (Signed Message or Image Array)              |
        +------------------------------------------------------------------+
        |                      Signature block                             |
        +------------------------------------------------------------------+

    """

    TAG = 0x00  # Need to be updated by child class
    VERSION = 0x00
    FLAGS_SRK_SET_OFFSET = 0
    FLAGS_SRK_SET_SIZE = 2
    FLAGS_SRK_SET_VAL = {"none": 0, "nxp": 1, "oem": 2}
    FLAGS_USED_SRK_ID_OFFSET = 4
    FLAGS_USED_SRK_ID_SIZE = 2
    FLAGS_SRK_REVOKE_MASK_OFFSET = 8
    FLAGS_SRK_REVOKE_MASK_SIZE = 4

    def __init__(
        self,
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        signature_block: Optional["SignatureBlock"] = None,
    ):
        """Class object initializer.

        :param flags: flags.
        :param fuse_version: value must be equal to or greater than the version
            stored in the fuses to allow loading this container.
        :param sw_version: used by PHBC (Privileged Host Boot Companion) to select
            between multiple images with same fuse version field.
        :param signature_block: signature block.
        """
        super().__init__(tag=self.TAG, length=-1, version=self.VERSION)
        self.flags = flags
        self.fuse_version = fuse_version
        self.sw_version = sw_version
        self.signature_block = signature_block or SignatureBlock()
        self.search_paths: List[str] = []
        self.lock = False

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AHABContainerBase):
            if (
                super().__eq__(other)
                and self.flags == other.flags
                and self.fuse_version == other.fuse_version
                and self.sw_version == other.sw_version
            ):
                return True

        return False

    def set_flags(
        self, srk_set: str = "none", used_srk_id: int = 0, srk_revoke_mask: int = 0
    ) -> None:
        """Set the flags value.

        :param srk_set: Super Root Key (SRK) set, defaults to "none"
        :param used_srk_id: Which key from SRK set is being used, defaults to 0
        :param srk_revoke_mask: SRK revoke mask, defaults to 0
        """
        flags = self.FLAGS_SRK_SET_VAL[srk_set.lower()]
        flags |= used_srk_id << 4
        flags |= srk_revoke_mask << 8
        self.flags = flags

    @property
    def flag_srk_set(self) -> str:
        """SRK set flag in string representation.

        :return: Name of SRK Set flag.
        """
        srk_set = (self.flags >> self.FLAGS_SRK_SET_OFFSET) & ((1 << self.FLAGS_SRK_SET_SIZE) - 1)
        return get_key_by_val(self.FLAGS_SRK_SET_VAL, srk_set)

    @property
    def flag_used_srk_id(self) -> int:
        """Used SRK ID flag.

        :return: Index of Used SRK ID.
        """
        return (self.flags >> self.FLAGS_USED_SRK_ID_OFFSET) & (
            (1 << self.FLAGS_USED_SRK_ID_SIZE) - 1
        )

    @property
    def flag_srk_revoke_mask(self) -> str:
        """SRK Revoke mask flag.

        :return: SRK revoke mask in HEX.
        """
        srk_revoke_mask = (self.flags >> self.FLAGS_SRK_REVOKE_MASK_OFFSET) & (
            (1 << self.FLAGS_SRK_REVOKE_MASK_SIZE) - 1
        )
        return hex(srk_revoke_mask)

    @property
    def _signature_block_offset(self) -> int:
        """Returns current signature block offset.

        :return: Offset in bytes of Signature block.
        """
        # Constant size of Container header + Image array Entry table
        return align(
            super().__len__(),
            CONTAINER_ALIGNMENT,
        )

    @property
    def image_array_len(self) -> int:
        """Get image array length if available.

        :return: Length of image array.
        """
        return 0

    def __len__(self) -> int:
        """Get total length of AHAB container.

        :return: Size in bytes of AHAB Container.
        """
        # If there are no images just return length of header
        return self.header_length()

    def header_length(self) -> int:
        """Length of AHAB Container header.

        :return: Length in bytes of AHAB Container header.
        """
        return super().__len__() + len(  # This returns the fixed length of the container header
            self.signature_block
        )

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()
            + UINT32  # Flags
            + UINT16  # SW version
            + UINT8  # Fuse version
            + UINT8  # Number of Images
            + UINT16  # Signature Block Offset
            + UINT16  # Reserved
        )

    def update_fields(self) -> None:
        """Updates all volatile information in whole container structure.

        :raises SPSDKError: When inconsistent image array length is detected.
        """
        # Update the signature block to get overall size of it
        self.signature_block.update_fields()
        # Update the Container header length
        self.length = self.header_length()
        # # Sign the image header
        if self.flag_srk_set != "none":
            assert self.signature_block.signature
            self.signature_block.signature.sign(self.get_signature_data())

    def get_signature_data(self) -> bytes:
        """Returns binary data to be signed.

        The container must be properly initialized, so the data are valid for
        signing, i.e. the offsets, lengths etc. must be set prior invoking this
        method, otherwise improper data will be signed.

        The whole container gets serialized first. Afterwards the binary data
        is sliced so only data for signing get's returned. The signature data
        length is evaluated based on offsets, namely the signature block offset,
        the container signature offset and the container signature fixed data length.

        Signature data structure::

            +---------------------------------------------------+----------------+
            |                  Container header                 |                |
            +---+---+-----------+---------+--------+------------+     Data       |
            | S |   |    tag    | length  | length | version    |                |
            | i |   +-----------+---------+--------+------------+                |
            | g |   |                  flags                    |      to        |
            | n |   +---------------------+---------------------+                |
            | a |   |  srk table offset   | certificate offset  |                |
            | t |   +---------------------+---------------------+     Sign       |
            | u |   |     blob offset     | signature offset    |                |
            | r |   +---------------------+---------------------+                |
            | e |   |                   SRK Table               |                |
            |   +---+-----------+---------+--------+------------+----------------+
            | B | S |   tag     | length  | length | version    | Signature data |
            | l | i +-----------+---------+--------+------------+ fixed length   |
            | o | g |               Reserved                    |                |
            | c | n +-------------------------------------------+----------------+
            | k | a |               Signature data              |
            |   | t |                                           |
            |   | u |                                           |
            |   | r |                                           |
            |   | e |                                           |
            +---+---+-------------------------------------------+

        :raises SPSDKValueError: if Signature Block or SRK Table is missing.
        :return: bytes representing data to be signed.
        """
        if not self.signature_block.signature or not self.signature_block.srk_table:
            raise SPSDKValueError(
                "Can't retrieve data block to sign. Signature or SRK table is missing!"
            )

        signature_offset = self._signature_block_offset + self.signature_block.signature_offset
        return self._export()[:signature_offset]

    def _export(self) -> bytes:
        """Export container header into bytes.

        :return: bytes representing container header content including the signature block.
        """
        return pack(
            self.format(),
            self.version,
            self.length,
            self.tag,
            self.flags,
            self.sw_version,
            self.fuse_version,
            self.image_array_len,
            self._signature_block_offset,
            RESERVED,  # Reserved field
        )

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        self.validate_header()

        if self.flags is None or not check_range(self.flags, end=(1 << 32) - 1):
            raise SPSDKValueError(f"Container Header: Invalid flags: {hex(self.flags)}")
        if self.sw_version is None or not check_range(self.sw_version, end=(1 << 16) - 1):
            raise SPSDKValueError(f"Container Header: Invalid SW version: {hex(self.sw_version)}")
        if self.fuse_version is None or not check_range(self.fuse_version, end=(1 << 8) - 1):
            raise SPSDKValueError(
                f"Container Header: Invalid Fuse version: {hex(self.fuse_version)}"
            )
        self.signature_block.validate(data)

    @staticmethod
    def _parse(binary: bytes) -> Tuple[int, int, int, int, int]:
        """Parse input binary chunk to the container object.

        :param parent: AHABImage object.
        :param binary: Binary data with Container block to parse.
        :return: Object recreated from the binary data.
        """
        AHABContainer.check_container_head(binary)
        image_format = AHABContainer.format()
        (
            _,  # version
            _,  # container_length
            _,  # tag
            flags,
            sw_version,
            fuse_version,
            number_of_images,
            signature_block_offset,
            _,  # reserved
        ) = unpack(image_format, binary[: AHABContainer.fixed_length()])

        return (flags, sw_version, fuse_version, number_of_images, signature_block_offset)

    def _create_config(self, index: int, data_path: str) -> Dict[str, Any]:
        """Create configuration of the AHAB Image.

        :param index: Container index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg: Dict[str, Any] = {}

        cfg["srk_set"] = self.flag_srk_set
        cfg["used_srk_id"] = self.flag_used_srk_id
        cfg["srk_revoke_mask"] = self.flag_srk_revoke_mask
        cfg["fuse_version"] = self.fuse_version
        cfg["sw_version"] = self.sw_version
        cfg["signing_key"] = "N/A"

        if self.signature_block.srk_table:
            cfg["srk_table"] = self.signature_block.srk_table.create_config(index, data_path)

        if self.signature_block.certificate:
            cert_cfg = self.signature_block.certificate.create_config(
                index, data_path, self.flag_srk_set
            )
            write_file(
                CommentedConfig(
                    "Parsed AHAB Certificate", Certificate.get_validation_schemas()
                ).get_config(cert_cfg),
                os.path.join(data_path, "certificate.yaml"),
            )
            cfg["certificate"] = "certificate.yaml"

        if self.signature_block.blob:
            cfg["blob"] = self.signature_block.blob.create_config(index, data_path)

        return cfg

    def load_from_config_generic(self, config: Dict[str, Any]) -> None:
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param config: array of AHAB containers configuration dictionaries.
        """
        self.set_flags(
            srk_set=config.get("srk_set", "none"),
            used_srk_id=value_to_int(config.get("used_srk_id", 0)),
            srk_revoke_mask=value_to_int(config.get("srk_revoke_mask", 0)),
        )
        self.fuse_version = value_to_int(config.get("fuse_version", 0))
        self.sw_version = value_to_int(config.get("sw_version", 0))

        self.signature_block = SignatureBlock.load_from_config(
            config, search_paths=self.search_paths
        )


class AHABContainer(AHABContainerBase):
    """Class representing AHAB container.

    Container header::

        +---------------+----------------+----------------+----------------+
        |    Byte 3     |     Byte 2     |      Byte 1    |     Byte 0     |
        +---------------+----------------+----------------+----------------+
        |      Tag      |              Length             |    Version     |
        +---------------+---------------------------------+----------------+
        |                              Flags                               |
        +---------------+----------------+---------------------------------+
        |  # of images  |  Fuse version  |             SW version          |
        +---------------+----------------+---------------------------------+
        |              Reserved          |       Signature Block Offset    |
        +----+---------------------------+---------------------------------+
        | I  |image0: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        + m  |-------------------------------------------------------------+
        | g  |image1: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        + .  |-------------------------------------------------------------+
        | A  |...                                                          |
        | r  |...                                                          |
        | r  |                                                             |
        + a  |-------------------------------------------------------------+
        | y  |imageN: Offset, Size, LoadAddr, EntryPoint, Flags, Hash, IV  |
        +----+-------------------------------------------------------------+
        |                      Signature block                             |
        +------------------------------------------------------------------+
        |                                                                  |
        |                                                                  |
        |                                                                  |
        +------------------------------------------------------------------+
        |                      Data block_0                                |
        +------------------------------------------------------------------+
        |                                                                  |
        |                                                                  |
        +------------------------------------------------------------------+
        |                      Data block_n                                |
        +------------------------------------------------------------------+

    """

    TAG = AHABTags.CONTAINER_HEADER.tag

    def __init__(
        self,
        parent: "AHABImage",
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        image_array: Optional[List["ImageArrayEntry"]] = None,
        signature_block: Optional["SignatureBlock"] = None,
        container_offset: int = 0,
    ):
        """Class object initializer.

        :parent: Parent AHABImage object.
        :param flags: flags.
        :param fuse_version: value must be equal to or greater than the version
            stored in the fuses to allow loading this container.
        :param sw_version: used by PHBC (Privileged Host Boot Companion) to select
            between multiple images with same fuse version field.
        :param image_array: array of image entries, must be `number of images` long.
        :param signature_block: signature block.
        """
        super().__init__(
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            signature_block=signature_block,
        )
        self.parent = parent
        assert self.parent is not None
        self.image_array = image_array or []
        self.container_offset = container_offset
        self.search_paths: List[str] = []

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AHABContainer):
            if super().__eq__(other) and self.image_array == other.image_array:
                return True

        return False

    def __repr__(self) -> str:
        return f"AHAB Container at offset {hex(self.container_offset)} "

    def __str__(self) -> str:
        return (
            "AHAB Container:\n"
            f"  Index:              {'0' if self.container_offset == 0 else '1'}\n"
            f"  Flags:              {hex(self.flags)}\n"
            f"  Fuse version:       {hex(self.fuse_version)}\n"
            f"  SW version:         {hex(self.sw_version)}\n"
            f"  Images count:       {self.image_array_len}"
        )

    @property
    def image_array_len(self) -> int:
        """Get image array length if available.

        :return: Length of image array.
        """
        return len(self.image_array)

    @property
    def _signature_block_offset(self) -> int:
        """Returns current signature block offset.

        :return: Offset in bytes of Signature block.
        """
        # Constant size of Container header + Image array Entry table
        return align(
            super().fixed_length() + len(self.image_array) * ImageArrayEntry.fixed_length(),
            CONTAINER_ALIGNMENT,
        )

    def __len__(self) -> int:
        """Get total length of AHAB container.

        :return: Size in bytes of AHAB Container.
        """
        # Get image which has biggest offset
        possible_sizes = [self.header_length()]
        possible_sizes.extend([align(x.image_offset + x.image_size) for x in self.image_array])

        return align(max(possible_sizes), CONTAINER_ALIGNMENT)

    def header_length(self) -> int:
        """Length of AHAB Container header.

        :return: Length in bytes of AHAB Container header.
        """
        return (
            super().fixed_length()  # This returns the fixed length of the container header
            # This returns the total length of all image array entries
            + len(self.image_array) * ImageArrayEntry.fixed_length()
            # This returns the length of signature block (including SRK table,
            # blob etc. if present)
            + len(self.signature_block)
        )

    def update_fields(self) -> None:
        """Updates all volatile information in whole container structure.

        :raises SPSDKError: When inconsistent image array length is detected.
        """
        # 1. Encrypt all images if applicable
        for image_entry in self.image_array:
            if (
                image_entry.flags_is_encrypted
                and not image_entry.already_encrypted_image
                and self.signature_block.blob
            ):
                image_entry.encrypted_image = self.signature_block.blob.encrypt_data(
                    image_entry.image_iv[16:], image_entry.plain_image
                )
                image_entry.already_encrypted_image = True

        # 2. Update the signature block to get overall size of it
        self.signature_block.update_fields()
        # 3. Updates Image Entries
        for image_entry in self.image_array:
            image_entry.update_fields()
        # 4. Update the Container header length
        self.length = self.header_length()
        # 5. Sign the image header
        if self.flag_srk_set != "none":
            assert self.signature_block.signature
            self.signature_block.signature.sign(self.get_signature_data())

    def decrypt_data(self) -> None:
        """Decrypt all images if possible."""
        for i, image_entry in enumerate(self.image_array):
            if image_entry.flags_is_encrypted:
                if self.signature_block.blob is None:
                    raise SPSDKError("Cannot decrypt image without Blob!")

                decrypted_data = self.signature_block.blob.decrypt_data(
                    image_entry.image_iv[16:], image_entry.encrypted_image
                )
                if image_entry.image_iv == get_hash(
                    decrypted_data, algorithm=EnumHashAlgorithm.SHA256
                ):
                    image_entry.plain_image = decrypted_data
                    logger.info(
                        f" Image{i} from AHAB container at offset {hex(self.container_offset)} has been decrypted."
                    )
                else:
                    logger.warning(
                        f" Image{i} from AHAB container at offset {hex(self.container_offset)} decryption failed."
                    )

    def _export(self) -> bytes:
        """Export container header into bytes.

        :return: bytes representing container header content including the signature block.
        """
        return self.export()

    def export(self) -> bytes:
        """Export container header into bytes.

        :return: bytes representing container header content including the signature block.
        """
        container_header = bytearray(align(self.header_length(), CONTAINER_ALIGNMENT))
        container_header_only = super()._export()

        for image_array_entry in self.image_array:
            container_header_only += image_array_entry.export()

        container_header[: self._signature_block_offset] = container_header_only
        # Add Signature Block
        container_header[
            self._signature_block_offset : self._signature_block_offset
            + align(len(self.signature_block), CONTAINER_ALIGNMENT)
        ] = self.signature_block.export()

        return container_header

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        data["flag_used_srk_id"] = self.flag_used_srk_id
        self.validate_header()
        if self.length != self.header_length():
            raise SPSDKValueError(
                f"Container 0x{self.container_offset:04X} "
                f"Header: Invalid block length: {self.length} != {self.header_length()}"
            )

        super().validate(data)

        if self.image_array is None or len(self.image_array) == 0:
            raise SPSDKValueError(
                f"Container 0x{self.container_offset:04X} Header: Invalid Image Array: {self.image_array}"
            )

        for container, offset in zip(self.parent.ahab_containers, self.parent.ahab_address_map):
            if self == container:
                if self.container_offset != offset:
                    raise SPSDKValueError(
                        f"AHAB Container 0x{self.container_offset:04X}: Invalid Container Offset."
                    )

        if self.signature_block.srk_table and self.signature_block.signature:
            # Get public key with the SRK ID
            key = self.signature_block.srk_table.get_source_keys()[self.flag_used_srk_id]
            if self.signature_block.certificate:
                # Verify signature of certificate
                if not key.verify_signature(
                    self.signature_block.certificate.signature.signature_data,
                    self.signature_block.certificate.get_signature_data(),
                ):
                    raise SPSDKValueError(
                        f"AHAB Container 0x{self.container_offset:04X}: Certificate block signature "
                        f"cannot be verified with SRK ID {self.flag_used_srk_id}"
                    )

            if (
                self.signature_block.certificate
                and self.signature_block.certificate.permission_to_sign_container
            ):
                # Container is signed by certificate, get public key from certificate
                assert (
                    self.signature_block.certificate.public_key
                ), "Certificate must contain public key"
                key = PublicKey.parse(self.signature_block.certificate.public_key.get_public_key())

            if not key.verify_signature(
                self.signature_block.signature.signature_data, self.get_signature_data()
            ):
                if (
                    self.signature_block.certificate
                    and self.signature_block.certificate.permission_to_sign_container
                ):
                    raise SPSDKValueError(
                        f"AHAB Container 0x{self.container_offset:04X}: "
                        "Signature cannot be verified with the public key from certificate"
                    )
                raise SPSDKValueError(
                    f"AHAB Container 0x{self.container_offset:04X}: "
                    f"Signature cannot be verified with SRK ID {self.flag_used_srk_id}"
                )

        for image in self.image_array:
            image.validate()

    @classmethod
    def parse(cls, data: bytes, parent: "AHABImage", container_id: int) -> Self:  # type: ignore# type: ignore # pylint: disable=arguments-differ
        """Parse input binary chunk to the container object.

        :param data: Binary data with Container block to parse.
        :param parent: AHABImage object.
        :param container_id: AHAB container ID.
        :return: Object recreated from the binary data.
        """
        if parent is None:
            raise SPSDKValueError("Ahab Image must be specified.")
        (
            flags,
            sw_version,
            fuse_version,
            number_of_images,
            signature_block_offset,
        ) = AHABContainerBase._parse(data)

        parsed_container = cls(
            parent=parent,
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            container_offset=parent.ahab_address_map[container_id],
        )
        parsed_container.signature_block = SignatureBlock.parse(data[signature_block_offset:])

        for i in range(number_of_images):
            image_array_entry = ImageArrayEntry.parse(
                data[AHABContainer.fixed_length() + i * ImageArrayEntry.fixed_length() :],
                parsed_container,
            )
            parsed_container.image_array.append(image_array_entry)
        # Lock the parsed container to any updates of offsets
        parsed_container.lock = True
        return parsed_container

    def create_config(self, index: int, data_path: str) -> Dict[str, Any]:
        """Create configuration of the AHAB Image.

        :param index: Container index.
        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret_cfg = {}
        cfg = self._create_config(index, data_path)
        images_cfg = []

        for img_ix, image in enumerate(self.image_array):
            images_cfg.append(image.create_config(index, img_ix, data_path))
        cfg["images"] = images_cfg

        ret_cfg["container"] = cfg
        return ret_cfg

    @staticmethod
    def load_from_config(
        parent: "AHABImage", config: Dict[str, Any], container_ix: int
    ) -> "AHABContainer":
        """Converts the configuration option into an AHAB image object.

        "config" content of container configurations.

        :param parent: AHABImage object.
        :param config: array of AHAB containers configuration dictionaries.
        :param container_ix: Container index that is loaded.
        :return: AHAB Container object.
        """
        ahab_container = AHABContainer(parent)
        ahab_container.search_paths = parent.search_paths or []
        ahab_container.container_offset = parent.ahab_address_map[container_ix]
        ahab_container.load_from_config_generic(config)
        images = config.get("images")
        assert isinstance(images, list)
        for image in images:
            ahab_container.image_array.append(
                ImageArrayEntry.load_from_config(ahab_container, image)
            )

        return ahab_container

    def image_info(self) -> BinaryImage:
        """Get Image info object.

        :return: AHAB Container Info object.
        """
        ret = BinaryImage(
            name="AHAB Container",
            size=self.header_length(),
            offset=0,
            binary=self.export(),
            description=(f"AHAB Container for {self.flag_srk_set}" f"_SWver:{self.sw_version}"),
        )
        return ret


class AHABImage:
    """Class representing an AHAB image.

    The image consists of multiple AHAB containers.
    """

    TARGET_MEMORIES = [
        TARGET_MEMORY_SERIAL_DOWNLOADER,
        TARGET_MEMORY_NOR,
        TARGET_MEMORY_NAND_4K,
        TARGET_MEMORY_NAND_2K,
    ]

    def __init__(
        self,
        family: str,
        revision: str = "latest",
        target_memory: str = TARGET_MEMORY_NOR,
        ahab_containers: Optional[List[AHABContainer]] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """AHAB Image constructor.

        :param family: Name of device family.
        :param revision: Device silicon revision, defaults to "latest"
        :param target_memory: Target memory for AHAB image [serial_downloader, nor, nand], defaults to "nor"
        :param ahab_containers: _description_, defaults to None
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKValueError: Invalid input configuration.
        """
        if target_memory not in self.TARGET_MEMORIES:
            raise SPSDKValueError(
                f"Invalid AHAB target memory [{target_memory}]."
                f" The list of supported images: [{','.join(self.TARGET_MEMORIES)}]"
            )
        self.target_memory = target_memory
        self.family = family
        self.search_paths = search_paths
        self._database = get_db(family, revision)
        self.revision = self._database.name
        self.ahab_address_map: List[int] = self._database.get_list(DatabaseManager.AHAB, "ahab_map")
        self.start_image_address = (
            START_IMAGE_ADDRESS_NAND
            if target_memory in [TARGET_MEMORY_NAND_2K, TARGET_MEMORY_NAND_4K]
            else START_IMAGE_ADDRESS
        )
        self.containers_max_cnt = self._database.get_int(DatabaseManager.AHAB, "containers_max_cnt")
        self.images_max_cnt = self._database.get_int(DatabaseManager.AHAB, "oem_images_max_cnt")
        self.srkh_sha_supports: List[str] = self._database.get_list(
            DatabaseManager.AHAB, "srkh_sha_supports"
        )
        self.ahab_containers: List[AHABContainer] = ahab_containers or []

    def __repr__(self) -> str:
        return f"AHAB Image for {self.family}"

    def __str__(self) -> str:
        return (
            "AHAB Image:\n"
            f"  Family:             {self.family}\n"
            f"  Revision:           {self.revision}\n"
            f"  Target memory:      {self.target_memory}\n"
            f"  Max cont. count:    {self.containers_max_cnt}"
            f"  Max image. count:   {self.images_max_cnt}"
            f"  Containers count:   {len(self.ahab_containers)}"
        )

    def add_container(self, container: AHABContainer) -> None:
        """Add new container into AHAB Image.

        The order of the added images is important.
        :param container: New AHAB Container to be added.
        :raises SPSDKLengthError: The container count in image is overflowed.
        """
        if len(self.ahab_containers) >= self.containers_max_cnt:
            raise SPSDKLengthError(
                "Cannot add new container because the AHAB Image already reached"
                f" the maximum count: {self.containers_max_cnt}"
            )

        self.ahab_containers.append(container)

    def clear(self) -> None:
        """Clear list of containers."""
        self.ahab_containers.clear()

    def update_fields(self, update_offsets: bool = True) -> None:
        """Automatically updates all volatile fields in every AHAB container.

        :param update_offsets: Update also offsets for serial_downloader.
        """
        for ahab_container in self.ahab_containers:
            ahab_container.update_fields()

        if self.target_memory == TARGET_MEMORY_SERIAL_DOWNLOADER and update_offsets:
            # Update the Image offsets to be without gaps
            offset = self.start_image_address
            for ahab_container in self.ahab_containers:
                for image in ahab_container.image_array:
                    if ahab_container.lock:
                        offset = image.image_offset
                    else:
                        image.image_offset = offset
                    offset = image.get_valid_offset(offset + image.image_size)

                ahab_container.update_fields()

    def __len__(self) -> int:
        """Get maximal size of AHAB Image.

        :return: Size in Bytes of AHAB Image.
        """
        lengths = [0]
        for container in self.ahab_containers:
            lengths.append(len(container))
        return align(max(lengths), CONTAINER_ALIGNMENT)

    def get_containers_size(self) -> int:
        """Get maximal containers size.

        In fact get the offset where could be stored first data.

        :return: Size of containers.
        """
        if len(self.ahab_containers) == 0:
            return 0
        sizes = [
            container.header_length() + address
            for container, address in zip(self.ahab_containers, self.ahab_address_map)
        ]
        return align(max(sizes), CONTAINER_ALIGNMENT)

    def get_first_data_image_address(self) -> int:
        """Get first data image address.

        :return: Address of first data image.
        """
        addresses = []
        for container in self.ahab_containers:
            addresses.extend([x.image_offset for x in container.image_array])
        return min(addresses)

    def export(self) -> bytes:
        """Export AHAB Image.

        :raises SPSDKValueError: mismatch between number of containers and offsets.
        :raises SPSDKValueError: number of images mismatch.
        :return: bytes AHAB  Image.
        """
        self.update_fields()
        self.validate()
        return self.image_info().export()

    def image_info(self) -> BinaryImage:
        """Get Image info object."""
        ret = BinaryImage(
            name="AHAB Image",
            size=len(self),
            offset=0,
            description=f"AHAB Image for {self.family}_{self.revision}",
            pattern=BinaryPattern("0xCA"),
        )
        ahab_containers = BinaryImage(
            name="AHAB Containers",
            size=self.start_image_address,
            offset=0,
            description="AHAB Containers block",
            pattern=BinaryPattern("zeros"),
        )
        ret.add_image(ahab_containers)

        for cnt_ix, (container, address) in enumerate(
            zip(self.ahab_containers, self.ahab_address_map)
        ):
            container_image = container.image_info()
            container_image.name = container_image.name + f" {cnt_ix}"
            container_image.offset = address
            ahab_containers.add_image(container_image)

            # Add also all data images
            for img_ix, image_entry in enumerate(container.image_array):
                data_image = BinaryImage(
                    name=f"Container {cnt_ix} AHAB Data Image {img_ix}",
                    binary=image_entry.image,
                    size=image_entry.image_size,
                    offset=image_entry.image_offset,
                    description=(
                        f"AHAB {'encrypted ' if image_entry.flags_is_encrypted else ''}"
                        f"data block with {image_entry.flags_image_type} Image Type."
                    ),
                )

                ret.add_image(data_image)

        return ret

    def validate(self) -> None:
        """Validate object data.

        :raises SPSDKValueError: Invalid any value of Image Array entry.
        :raises SPSDKError: In case of Binary Image validation fail.
        """
        if self.ahab_containers is None or len(self.ahab_containers) == 0:
            raise SPSDKValueError("AHAB Image: Missing Containers.")
        if len(self.ahab_containers) > self.containers_max_cnt:
            raise SPSDKValueError(
                "AHAB Image: Too much AHAB containers in image."
                f" {len(self.ahab_containers)} > {self.containers_max_cnt}"
            )
        # prepare additional validation data
        data = {}
        data["srkh_sha_supports"] = self.srkh_sha_supports

        for cnt_ix, container in enumerate(self.ahab_containers):
            container.validate(data)
            if len(container.image_array) > self.images_max_cnt:
                raise SPSDKValueError(
                    f"AHAB Image: Too many binary images in AHAB Container [{cnt_ix}]."
                    f" {len(container.image_array)} > {self.images_max_cnt}"
                )
            if self.target_memory != TARGET_MEMORY_SERIAL_DOWNLOADER:
                for img_ix, image_entry in enumerate(container.image_array):
                    if image_entry.image_offset_real < self.start_image_address:
                        raise SPSDKValueError(
                            "AHAB Data Image: The offset of data image (container"
                            f"{cnt_ix}/image{img_ix}) is under minimal allowed value."
                            f" 0x{hex(image_entry.image_offset_real)} < {hex(self.start_image_address)}"
                        )

        # Validate correct data image offsets
        offset = self.start_image_address
        alignment = self.ahab_containers[0].image_array[0].get_valid_alignment()
        for container in self.ahab_containers:
            for image in container.image_array:
                if image.image_offset_real != align(image.image_offset_real, alignment):
                    raise SPSDKValueError(
                        f"Image Entry: Invalid Image Offset alignment for target memory '{self.target_memory}': "
                        f"{hex(image.image_offset_real)} "
                        f"should be with alignment {hex(alignment)}.\n"
                        f"For example: Bootable image offset ({hex(TARGET_MEMORY_BOOT_OFFSETS[self.target_memory])})"
                        " + offset ("
                        f"{hex(align(image.image_offset, alignment) - TARGET_MEMORY_BOOT_OFFSETS[self.target_memory])})"
                        "  is correctly aligned."
                    )
                if self.target_memory == TARGET_MEMORY_SERIAL_DOWNLOADER:
                    if offset != image.image_offset and not container.lock:
                        raise SPSDKValueError(
                            "Invalid image offset for Serial Downloader mode."
                            f"\n Expected {hex(offset)}, Used:{hex(image.image_offset_real)}"
                        )
                    else:
                        offset = image.image_offset
                    offset = image.get_valid_offset(offset + image.image_size)
                alignment = image.get_valid_alignment()

        # Validate also overlapped images
        try:
            self.image_info().validate()
        except SPSDKError as exc:
            logger.error(self.image_info().draw())
            raise SPSDKError("Validation failed") from exc

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "AHABImage":
        """Converts the configuration option into an AHAB image object.

        "config" content array of containers configurations.

        :param config: array of AHAB containers configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKValueError: if the count of AHAB containers is invalid.
        :raises SPSDKParsingError: Cannot parse input binary AHAB container.
        :return: Initialized AHAB Image.
        """
        containers_config: List[Dict[str, Any]] = config["containers"]
        family = config["family"]
        revision = config.get("revision", "latest")
        target_memory = config.get("target_memory")
        if target_memory is None:
            # backward compatible reading of obsolete image type
            image_type = config["image_type"]
            target_memory = {
                "xip": "nor",
                "non_xip": "nor",
                "nand": "nand_2k",
                "serial_downloader": "serial_downloader",
            }[image_type]
            logger.warning(
                f"The obsolete key 'image_type':{image_type} has been converted into 'target_memory':{target_memory}"
            )
        ahab = AHABImage(
            family=family, revision=revision, target_memory=target_memory, search_paths=search_paths
        )
        i = 0
        for container_config in containers_config:
            binary_container = container_config.get("binary_container")
            if binary_container:
                assert isinstance(binary_container, dict)
                path = binary_container.get("path")
                assert path
                ahab_bin = load_binary(path, search_paths=search_paths)
                for j in range(ahab.containers_max_cnt):
                    try:
                        ahab.add_container(
                            AHABContainer.parse(
                                ahab_bin[ahab.ahab_address_map[j] :], parent=ahab, container_id=i
                            )
                        )
                        i += 1
                    except SPSDKError as exc:
                        if j == 0:
                            raise SPSDKParsingError(
                                f"AHAB Binary Container parsing failed. ({str(exc)})"
                            ) from exc
                        else:
                            break

            else:
                ahab.add_container(
                    AHABContainer.load_from_config(ahab, container_config["container"], i)
                )
                i += 1

        return ahab

    def parse(self, binary: bytes) -> None:
        """Parse input binary chunk to the container object.

        :raises SPSDKError: No AHAB container found in binary data.
        """
        self.clear()

        for i, address in enumerate(self.ahab_address_map):
            try:
                container = AHABContainer.parse(binary[address:], parent=self, container_id=i)
                self.ahab_containers.append(container)
            except SPSDKParsingError as exc:
                logger.debug(f"AHAB Image parsing error:\n{str(exc)}")
            except SPSDKError as exc:
                raise SPSDKError(f"AHAB Container parsing failed: {str(exc)}.") from exc
        if len(self.ahab_containers) == 0:
            raise SPSDKError("No AHAB Container has been found in binary data.")

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get all supported families for AHAB container.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.AHAB)

    @staticmethod
    def get_validation_schemas() -> List[Dict[str, Any]]:
        """Get list of validation schemas.

        :return: Validation list of schemas.
        """
        sch = DatabaseManager().db.get_schema_file(DatabaseManager.AHAB)["whole_ahab_image"]
        sch["properties"]["family"]["enum"] = AHABImage.get_supported_families()
        return [sch]

    @staticmethod
    def generate_config_template(family: str) -> Dict[str, Any]:
        """Generate AHAB configuration template.

        :param family: Family for which the template should be generated.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        val_schemas = AHABImage.get_validation_schemas()
        val_schemas[0]["properties"]["family"]["template_value"] = family

        yaml_data = CommentedConfig(
            f"Advanced High-Assurance Boot Configuration template for {family}.", val_schemas
        ).get_template()

        return {f"{family}_ahab": yaml_data}

    def create_config(self, data_path: str) -> Dict[str, Any]:
        """Create configuration of the AHAB Image.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        cfg: Dict[str, Any] = {}
        cfg["family"] = self.family
        cfg["revision"] = self.revision
        cfg["target_memory"] = self.target_memory
        cfg["output"] = "N/A"
        cfg_containers = []
        for cnt_ix, container in enumerate(self.ahab_containers):
            cfg_containers.append(container.create_config(cnt_ix, data_path))
        cfg["containers"] = cfg_containers

        return cfg

    def create_srk_hash_blhost_script(self, container_ix: int = 0) -> str:
        """Create BLHOST script to load SRK hash into fuses.

        :param container_ix: Container index.
        :raises SPSDKValueError: Invalid input value - Non existing container or unsupported type.
        :raises SPSDKError: Invalid SRK hash.
        :return: Script used by BLHOST to load SRK hash.
        """
        if container_ix > len(self.ahab_containers):
            raise SPSDKValueError(f"Invalid Container index: {container_ix}.")
        container_type = self.ahab_containers[container_ix].flag_srk_set

        fuses_start = self._database.get_int(
            DatabaseManager.AHAB, f"{container_type}_srkh_fuses_start"
        )
        fuses_count = self._database.get_int(
            DatabaseManager.AHAB, f"{container_type}_srkh_fuses_count"
        )
        fuses_size = self._database.get_int(
            DatabaseManager.AHAB, f"{container_type}_srkh_fuses_size"
        )
        if fuses_start is None or fuses_count is None or fuses_size is None:
            raise SPSDKValueError(
                f"Unsupported container type({container_type}) to create BLHOST script"
            )

        srk_table = self.ahab_containers[container_ix].signature_block.srk_table
        if srk_table is None:
            raise SPSDKError("The selected AHAB container doesn't contain SRK table.")

        srkh = srk_table.compute_srk_hash()

        if len(srkh) != fuses_count * fuses_size:
            raise SPSDKError(
                f"The SRK hash length ({len(srkh)}) doesn't fit to fuses space ({fuses_count*fuses_size})."
            )
        ret = (
            "# BLHOST SRK Hash fuses programming script\n"
            f"# Generated by SPSDK {spsdk_version}\n"
            f"# Chip: {self.family} rev:{self.revision}\n"
            f"# SRK Hash(Big Endian): {srkh.hex()}\n\n"
        )
        srkh_rev = reverse_bytes_in_longs(srkh)
        for fuse_ix in range(fuses_count):
            value = srkh_rev[fuse_ix * 4 : fuse_ix * 4 + 4]
            ret += f"#  OEM SRKH{fuses_count-1-fuse_ix} fuses.\n"
            ret += f"efuse-program-once {hex(fuses_start+fuse_ix)} 0x{value.hex()}\n"

        return ret
