#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Image header."""

from datetime import datetime
from struct import calcsize, pack, unpack_from
from typing import Optional

from typing_extensions import Self

from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.misc import BcdVersion3, pack_timestamp, unpack_timestamp
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import swap16


########################################################################################################################
# Image Header Class (Version SB2)
########################################################################################################################
# pylint: disable=too-many-instance-attributes
class ImageHeaderV2(BaseClass):
    """Image Header V2 class."""

    FORMAT = "<16s4s4s2BH4I4H4sQ12HI4s"
    SIZE = calcsize(FORMAT)
    SIGNATURE1 = b"STMP"
    SIGNATURE2 = b"sgtl"

    def __init__(
        self,
        version: str = "2.0",
        product_version: str = "1.0.0",
        component_version: str = "1.0.0",
        build_number: int = 0,
        flags: int = 0x08,
        nonce: Optional[bytes] = None,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """Initialize Image Header Version 2.x.

        :param version: The image version value (default: 2.0)
        :param product_version: The product version (default: 1.0.0)
        :param component_version: The component version (default: 1.0.0)
        :param build_number: The build number value (default: 0)
        :param flags: The flags value (default: 0x08)
        :param nonce: The NONCE value; None if TODO ????
        :param timestamp: value requested in the test; None to use current value
        """
        self.nonce = nonce
        self.version = version
        self.flags = flags
        self.image_blocks = 0  # will be updated from boot image
        self.first_boot_tag_block = 0
        self.first_boot_section_id = 0
        self.offset_to_certificate_block = 0  # will be updated from boot image
        self.header_blocks = 0  # will be calculated in the BootImage later
        self.key_blob_block = 8
        self.key_blob_block_count = 5
        self.max_section_mac_count = 0  # will be calculated in the BootImage later
        self.timestamp = (
            timestamp
            if timestamp is not None
            else datetime.fromtimestamp(int(datetime.now().timestamp()))
        )
        self.product_version: BcdVersion3 = BcdVersion3.to_version(product_version)
        self.component_version: BcdVersion3 = BcdVersion3.to_version(component_version)
        self.build_number = build_number

    def __repr__(self) -> str:
        return f"Header: v{self.version}, {self.image_blocks}"

    def flags_desc(self) -> str:
        """Return flag description."""
        return "Signed" if self.flags == 0x8 else "Unsigned"

    def __str__(self) -> str:
        """Get info of Header as string."""
        nfo = str()
        nfo += f" Version:              {self.version}\n"
        if self.nonce is not None:
            nfo += f" Digest:               {self.nonce.hex().upper()}\n"
        nfo += f" Flag:                 0x{self.flags:X} ({self.flags_desc()})\n"
        nfo += f" Image Blocks:         {self.image_blocks}\n"
        nfo += f" First Boot Tag Block: {self.first_boot_tag_block}\n"
        nfo += f" First Boot SectionID: {self.first_boot_section_id}\n"
        nfo += f" Offset to Cert Block: {self.offset_to_certificate_block}\n"
        nfo += f" Key Blob Block:       {self.key_blob_block}\n"
        nfo += f" Header Blocks:        {self.header_blocks}\n"
        nfo += f" Sections MAC Count:   {self.max_section_mac_count}\n"
        nfo += f" Key Blob Block Count: {self.key_blob_block_count}\n"
        nfo += f" Timestamp:            {self.timestamp.strftime('%H:%M:%S (%d.%m.%Y)')}\n"
        nfo += f" Product Version:      {self.product_version}\n"
        nfo += f" Component Version:    {self.component_version}\n"
        nfo += f" Build Number:         {self.build_number}\n"
        return nfo

    def export(self, padding: Optional[bytes] = None) -> bytes:
        """Serialize object into bytes.

        :param padding: header padding 8 bytes (for testing purposes); None to use random value
        :return: binary representation
        :raises SPSDKError: Raised when format is incorrect
        :raises SPSDKError: Raised when length of padding is incorrect
        :raises SPSDKError: Raised when length of header is incorrect
        """
        if not isinstance(self.nonce, bytes) or len(self.nonce) != 16:
            raise SPSDKError("Format is incorrect")
        major_version, minor_version = [int(v) for v in self.version.split(".")]
        product_version_words = [swap16(v) for v in self.product_version.nums]
        component_version_words = [swap16(v) for v in self.product_version.nums]
        if padding is None:
            padding = random_bytes(8)
        else:
            if len(padding) != 8:
                raise SPSDKError("Invalid length of padding")

        result = pack(
            self.FORMAT,
            self.nonce,
            # padding 8 bytes
            padding,
            self.SIGNATURE1,
            # header version
            major_version,
            minor_version,
            self.flags,
            self.image_blocks,
            self.first_boot_tag_block,
            self.first_boot_section_id,
            self.offset_to_certificate_block,
            self.header_blocks,
            self.key_blob_block,
            self.key_blob_block_count,
            self.max_section_mac_count,
            self.SIGNATURE2,
            pack_timestamp(self.timestamp),
            # product version
            product_version_words[0],
            0,
            product_version_words[1],
            0,
            product_version_words[2],
            0,
            # component version
            component_version_words[0],
            0,
            component_version_words[1],
            0,
            component_version_words[2],
            0,
            self.build_number,
            # padding[4]
            padding[4:],
        )
        if len(result) != self.SIZE:
            raise SPSDKError("Invalid length of header")
        return result

    # pylint: disable=too-many-locals
    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialization from binary form.

        :param data: binary representation
        :return: parsed instance of the header
        :raises SPSDKError: Unable to parse data
        """
        if cls.SIZE > len(data):
            raise SPSDKError("Insufficient amount of data")
        (
            nonce,
            # padding0
            _,
            signature1,
            # header version
            major_version,
            minor_version,
            flags,
            image_blocks,
            first_boot_tag_block,
            first_boot_section_id,
            offset_to_certificate_block,
            header_blocks,
            key_blob_block,
            key_blob_block_count,
            max_section_mac_count,
            signature2,
            raw_timestamp,
            # product version
            pv0,
            _,
            pv1,
            _,
            pv2,
            _,
            # component version
            cv0,
            _,
            cv1,
            _,
            cv2,
            _,
            build_number,
            # padding1
            _,
        ) = unpack_from(cls.FORMAT, data)

        # check header signature 1
        if signature1 != cls.SIGNATURE1:
            raise SPSDKError("SIGNATURE #1 doesn't match")

        # check header signature 2
        if signature2 != cls.SIGNATURE2:
            raise SPSDKError("SIGNATURE #2 doesn't match")

        obj = cls(
            version=f"{major_version}.{minor_version}",
            flags=flags,
            product_version=f"{swap16(pv0):X}.{swap16(pv1):X}.{swap16(pv2):X}",
            component_version=f"{swap16(cv0):X}.{swap16(cv1):X}.{swap16(cv2):X}",
            build_number=build_number,
        )

        obj.nonce = nonce
        obj.image_blocks = image_blocks
        obj.first_boot_tag_block = first_boot_tag_block
        obj.first_boot_section_id = first_boot_section_id
        obj.offset_to_certificate_block = offset_to_certificate_block
        obj.header_blocks = header_blocks
        obj.key_blob_block = key_blob_block
        obj.key_blob_block_count = key_blob_block_count
        obj.max_section_mac_count = max_section_mac_count
        obj.timestamp = unpack_timestamp(raw_timestamp)

        return obj
