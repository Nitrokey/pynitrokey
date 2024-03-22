#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""The module provides support for On-The-Fly encoding for RTxxx devices."""

import logging
from struct import pack
from typing import Any, Dict, List, Optional, Union

from crcmod.predefined import mkPredefinedCrcFun

from ...crypto.rng import random_bytes
from ...crypto.symmetric import Counter, aes_ctr_encrypt, aes_key_wrap
from ...exceptions import SPSDKError, SPSDKValueError
from ...utils.misc import Endianness, align_block

logger = logging.getLogger(__name__)


class KeyBlob:
    """OTFAD KeyBlob: The class specifies AES key and counter initial value for specified address range.

    | typedef struct KeyBlob
    | {
    |     unsigned char key[kAesKeySizeBytes]; // 16 bytes, 128-bits, KEY[A15...A00]
    |     unsigned char ctr[kCtrSizeBytes];    // 8 bytes, 64-bits, CTR[C7...C0]
    |     unsigned int srtaddr;                // region start, SRTADDR[31 - 10]
    |     unsigned int endaddr;                // region end, ENDADDR[31 - 10]; lowest three bits are used as flags
    |     // end of 32-byte area covered by CRC
    |     unsigned int zero_fill;      // zeros
    |     unsigned int key_blob_crc32; // crc32 over 1st 32-bytes
    |     // end of 40 byte (5*64-bit) key blob data
    |     unsigned char expanded_wrap_data[8]; // 8 bytes, used for wrap expanded data
    |     // end of 48 byte (6*64-bit) wrap data
    |     unsigned char unused_filler[16]; // unused fill to 64 bytes
    | } keyblob_t;
    """

    _START_ADDR_MASK = 0x400 - 1
    # Region addresses are modulo 1024
    # The address ends with RO, ADE, VLD bits. From this perspective, only
    # bits [9:3] must be set to 1. The rest is configurable.
    _END_ADDR_MASK = 0x3F8

    # Key flags mask: RO, ADE, VLD
    _KEY_FLAG_MASK = 0x07
    # This field signals that the entire set of context registers (CTXn_KEY[0-3], CTXn_CTR[0-1],
    # CTXn_RGD_W[0-1] are read-only and cannot be modified. This field is sticky and remains
    # asserted until the next system reset. SR[RRAM] provides another level of register access
    # control and is independent of the RO indicator.
    KEY_FLAG_READ_ONLY = 0x4
    # AES Decryption Enable: For accesses hitting in a valid context, this bit indicates if the fetched data is to be
    # decrypted or simply bypassed.
    KEY_FLAG_ADE = 0x2
    # Valid: This field signals if the context is valid or not.
    KEY_FLAG_VLD = 0x1

    # key length in bytes
    KEY_SIZE = 16
    # counter length in bytes
    CTR_SIZE = 8
    # len of counter init value for export
    _EXPORT_CTR_IV_SIZE = 8
    # this constant seems to be fixed for SB2.1
    _EXPORT_NBLOCKS_5 = 5
    # binary export size
    _EXPORT_KEY_BLOB_SIZE = 64
    # QSPI image alignment length, 512 is supposed to be the safe alignment level for any QSPI device
    # this means that all QSPI images generated by this tool will be sizes of multiple 512
    _IMAGE_ALIGNMENT = 512
    # Encryption block size
    _ENCRYPTION_BLOCK_SIZE = 16

    def __init__(
        self,
        start_addr: int,
        end_addr: int,
        key: Optional[bytes] = None,
        counter_iv: Optional[bytes] = None,
        key_flags: int = KEY_FLAG_VLD | KEY_FLAG_ADE,
        # for testing
        zero_fill: Optional[bytes] = None,
        crc: Optional[bytes] = None,
    ):
        """Constructor.

        :param start_addr: start address of the region
        :param end_addr: end address of the region
        :param key_flags: see KEY_FLAG_xxx constants; default flags: RO = 0, ADE = 1, VLD = 1
        :param key: optional AES key; None to use random value
        :param counter_iv: optional counter init value for AES; None to use random value
        :param binaries: optional data chunks of this key blob
        :param zero_fill: optional value for zero_fill (for testing only); None to use random value (recommended)
        :param crc: optional value for unused CRC fill (for testing only); None to use random value (recommended)
        :raises SPSDKError: Start or end address are not aligned
        :raises SPSDKError: When there is invalid key
        :raises SPSDKError: When there is invalid start/end address
        :raises SPSDKError: When key_flags exceeds mask
        """
        if key is None:
            key = random_bytes(self.KEY_SIZE)
        if counter_iv is None:
            counter_iv = random_bytes(self.CTR_SIZE)
        if (len(key) != self.KEY_SIZE) and (len(counter_iv) != self.CTR_SIZE):
            raise SPSDKError("Invalid key")
        if start_addr < 0 or start_addr > end_addr or end_addr > 0xFFFFFFFF:
            raise SPSDKError("Invalid start/end address")
        if key_flags & ~self._KEY_FLAG_MASK != 0:
            raise SPSDKError(f"key_flags exceeds mask {hex(self._KEY_FLAG_MASK)}")
        if (start_addr & self._START_ADDR_MASK) != 0:
            raise SPSDKError(
                f"Start address must be aligned to {hex(self._START_ADDR_MASK + 1)} boundary"
            )
        # if (end_addr & self._END_ADDR_MASK) != self._END_ADDR_MASK:
        #     raise SPSDKError(f"End address must be aligned to {hex(self._END_ADDR_MASK)} boundary")
        self.key = key
        self.ctr_init_vector = counter_iv
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.key_flags = key_flags
        self.zero_fill = zero_fill
        self.crc_fill = crc

    def __str__(self) -> str:
        """Text info about the instance."""
        msg = ""
        msg += f"Key:        {self.key.hex()}\n"
        msg += f"Counter IV: {self.ctr_init_vector.hex()}\n"
        msg += f"Start Addr: {hex(self.start_addr)}\n"
        msg += f"End Addr:   {hex(self.end_addr)}\n"
        return msg

    def plain_data(self) -> bytes:
        """Plain data for selected key range.

        :return: key blob exported into binary form (serialization)
        :raises SPSDKError: Invalid value of zero fill parameter
        :raises SPSDKError: Invalid value crc
        :raises SPSDKError: Invalid length binary data
        """
        result = bytes()
        result += self.key
        result += self.ctr_init_vector
        result += pack("<I", self.start_addr)
        if self.end_addr or self.key_flags:
            end_addr_with_flags = (
                ((self.end_addr - 1) & ~self._KEY_FLAG_MASK)
                | self.key_flags
                | self._END_ADDR_MASK
            )
        else:
            end_addr_with_flags = 0
        result += pack("<I", end_addr_with_flags)
        header_crc: bytes = mkPredefinedCrcFun("crc-32-mpeg")(result).to_bytes(
            4, Endianness.LITTLE.value
        )
        # zero fill
        if self.zero_fill:
            if len(self.zero_fill) != 4:
                raise SPSDKError("Invalid value")
            result += self.zero_fill
        else:
            result += random_bytes(4)
        # CRC is not used, use random value
        if self.crc_fill:
            if len(self.crc_fill) != 4:
                raise SPSDKError("Invalid value crc")
            result += self.crc_fill
        else:
            result += header_crc
        result += bytes([0] * 8)  # expanded_wrap_data
        result += bytes([0] * 16)  # unused filler
        if len(result) != 64:
            raise SPSDKError("Invalid length binary data")
        return result

    # pylint: disable=invalid-name
    def export(
        self,
        kek: Union[bytes, str],
        iv: bytes = bytes([0xA6] * 8),
        byte_swap_cnt: int = 0,
    ) -> bytes:
        """Creates key wrap for the key blob.

        :param kek: key to encode; 16 bytes long
        :param iv: counter initialization vector; 8 bytes; optional, OTFAD uses empty init value
        :param byte_swap_cnt: Encrypted keyblob reverse byte count, 0 means NO reversing is enabled
        :return: Serialized key blob
        :raises SPSDKError: If any parameter is not valid
        :raises SPSDKError: If length of kek is not valid
        :raises SPSDKError: If length of data is not valid
        """
        if isinstance(kek, str):
            kek = bytes.fromhex(kek)
        if len(kek) != 16:
            raise SPSDKError("Invalid length of kek")
        if len(iv) != self._EXPORT_CTR_IV_SIZE:
            raise SPSDKError("Invalid length of initialization vector")
        n = self._EXPORT_NBLOCKS_5
        plaintext = self.plain_data()  # input data to be encrypted
        if len(plaintext) < n * 8:
            raise SPSDKError("Invalid length of data to be encrypted")

        blobs = bytes()
        wrap = aes_key_wrap(kek, plaintext[:40])
        if byte_swap_cnt > 0:
            for i in range(0, len(wrap), byte_swap_cnt):
                blobs += wrap[i : i + byte_swap_cnt][::-1]
        else:
            blobs += wrap

        return align_block(
            blobs, self._EXPORT_KEY_BLOB_SIZE, padding=0
        )  # align to 64 bytes (0 padding)

    def _get_ctr_nonce(self) -> bytes:
        """Get the counter initial value for image encryption.

        :return: counter bytes
        :raises SPSDKError: If length of counter is not valid
        """
        #  CTRn_x[127-0] = {CTR_W0_x[C0...C3],    // 32 bits of pre-programmed CTR
        #  CTR_W1_x[C4...C7],                     // another 32 bits of CTR
        #  CTR_W0_x[C0...C3] ^ CTR_W1_x[C4...C7], // exclusive-OR of CTR values
        #  systemAddress[31-4], 0000b             // 0-modulo-16 system address */

        if len(self.ctr_init_vector) != 8:
            raise SPSDKError("Invalid length of counter init")

        result = bytearray(16)
        result[:4] = self.ctr_init_vector[:4]
        result[4:8] = self.ctr_init_vector[4:]
        for i in range(0, 4):
            result[8 + i] = self.ctr_init_vector[0 + i] ^ self.ctr_init_vector[4 + i]

        # result[15:12] = start_addr as a counter; nonce has these bytes zero and value passes as counter init value

        return bytes(result)

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

    def encrypt_image(
        self,
        base_address: int,
        data: bytes,
        byte_swap: bool,
        counter_value: Optional[int] = None,
    ) -> bytes:
        """Encrypt specified data.

        :param base_address: of the data in target memory; must be >= self.start_addr
        :param data: to be encrypted (e.g. plain image); base_address + len(data) must be <= self.end_addr
        :param byte_swap: this probably depends on the flash device, how bytes are organized there
        :param counter_value: Optional counter value, if not specified start address of keyblob will be used
        :return: encrypted data
        :raises SPSDKError: If start address is not valid
        """
        if base_address % 16 != 0:
            raise SPSDKError(
                "Invalid start address"
            )  # Start address has to be 16 byte aligned
        data = align_block(data, self._ENCRYPTION_BLOCK_SIZE)  # align data length
        data_len = len(data)

        # check start and end addresses
        # Support dual image boot, do not raise exception
        if not self.matches_range(base_address, base_address + data_len - 1):
            logger.warning(
                f"Image address range is not within key blob: "
                f"{hex(self.start_addr)}-{hex(self.end_addr)}."
                " Ignore this if flash remap feature is used"
            )
        result = bytes()

        if not counter_value:
            counter_value = self.start_addr

        counter = Counter(
            self._get_ctr_nonce(),
            ctr_value=counter_value,
            ctr_byteorder_encoding=Endianness.BIG,
        )

        for index in range(0, data_len, 16):
            # prepare data in byte order
            if byte_swap:
                # swap 8 bytes + swap 8 bytes
                data_2_encr = (
                    data[-data_len + index + 7 : -data_len + index - 1 : -1]
                    + data[-data_len + index + 15 : -data_len + index + 7 : -1]
                )
            else:
                data_2_encr = data[index : index + 16]
            # encrypt
            encr_data = aes_ctr_encrypt(self.key, data_2_encr, counter.value)
            # fix byte order in result
            if byte_swap:
                result += (
                    encr_data[-9:-17:-1] + encr_data[-1:-9:-1]
                )  # swap 8 bytes + swap 8 bytes
            else:
                result += encr_data
            # update counter for encryption
            counter.increment(16)

        if len(result) != data_len:
            raise SPSDKError("Invalid length of encrypted data")
        return bytes(result)

    @property
    def is_encrypted(self) -> bool:
        """Get the required encryption or not.

        :return: True if blob is encrypted, False otherwise.
        """
        return (bool)(
            (self.key_flags & (self.KEY_FLAG_ADE | self.KEY_FLAG_VLD))
            == (self.KEY_FLAG_ADE | self.KEY_FLAG_VLD)
        )
