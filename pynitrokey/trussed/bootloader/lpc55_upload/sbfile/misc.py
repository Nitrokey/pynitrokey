#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Miscellaneous functions in SBFile module."""

from datetime import datetime, timezone
from typing import Any, Sequence, Union

from spsdk.exceptions import SPSDKError
from spsdk.utils import misc


class SecBootBlckSize:
    """Helper methods allowing to convert size to number of blocks and back.

    Note: The class is not intended to be instantiated
    """

    # Size of cipher block in bytes
    BLOCK_SIZE = 16

    @staticmethod
    def is_aligned(size: int) -> bool:
        """Whether size is aligned to cipher block size.

        :param size: given size in bytes
        :return: True if yes, False otherwise
        """
        return size % SecBootBlckSize.BLOCK_SIZE == 0

    @staticmethod
    def align(size: int) -> int:
        """Align given size to block size.

        :param size: in bytes
        :return: size aligned up to block size
        """
        return misc.align(size, SecBootBlckSize.BLOCK_SIZE)

    @staticmethod
    def to_num_blocks(size: int) -> int:
        """Converts size to number of cipher blocks.

        :param size: to be converted, the size must be aligned to block boundary
        :return: corresponding number of cipher blocks
        :raises SPSDKError: Raised when size is not aligned to block boundary
        """
        if not SecBootBlckSize.is_aligned(size):
            raise SPSDKError(
                f"Invalid size {size}, expected number aligned to BLOCK size {SecBootBlckSize.BLOCK_SIZE}"
            )
        return size // SecBootBlckSize.BLOCK_SIZE

    @staticmethod
    def align_block_fill_random(data: bytes) -> bytes:
        """Align block size to cipher block size.

        :param data: to be aligned
        :return: data aligned to cipher block size, filled with random values
        """
        return misc.align_block_fill_random(data, SecBootBlckSize.BLOCK_SIZE)


# the type represents input formats for BcdVersion3 value, see BcdVersion3.to_version
BcdVersion3Format = Union["BcdVersion3", str]


class BcdVersion3:
    """Version in format #.#.#, where # is BCD number (1-4 digits)."""

    # default value
    DEFAULT = "999.999.999"

    @staticmethod
    def _check_number(num: int) -> bool:
        """Check given number is a valid version number.

        :param num: to be checked
        :return: True if number format is valid
        :raises SPSDKError: If number format is not valid
        """
        if num < 0 or num > 0x9999:
            raise SPSDKError("Invalid number range")
        for index in range(4):
            if (num >> 4 * index) & 0xF > 0x9:
                raise SPSDKError("Invalid number, contains digit > 9")
        return True

    @staticmethod
    def _num_from_str(text: str) -> int:
        """Converts BCD number from text to int.

        :param text: given string to be converted to a version number
        :return: version number
        :raises SPSDKError: If format is not valid
        """
        if len(text) < 0 or len(text) > 4:
            raise SPSDKError("Invalid text length")
        result = int(text, 16)
        BcdVersion3._check_number(result)
        return result

    @staticmethod
    def from_str(text: str) -> "BcdVersion3":
        """Convert string to BcdVersion instance.

        :param text: version in format #.#.#, where # is 1-4 decimal digits
        :return: BcdVersion3 instance
        :raises SPSDKError: If format is not valid
        """
        parts = text.split(".")
        if len(parts) != 3:
            raise SPSDKError("Invalid length")
        major = BcdVersion3._num_from_str(parts[0])
        minor = BcdVersion3._num_from_str(parts[1])
        service = BcdVersion3._num_from_str(parts[2])
        return BcdVersion3(major, minor, service)

    @staticmethod
    def to_version(input_version: BcdVersion3Format) -> "BcdVersion3":
        """Convert different input formats into BcdVersion3 instance.

        :param input_version: either directly BcdVersion3 or string
        :raises SPSDKError: Raises when the format is unsupported
        :return: BcdVersion3 instance
        """
        if isinstance(input_version, BcdVersion3):
            return input_version
        if isinstance(input_version, str):
            return BcdVersion3.from_str(input_version)
        raise SPSDKError("unsupported format")

    def __init__(self, major: int = 1, minor: int = 0, service: int = 0):
        """Initialize BcdVersion3.

        :param major: number in BCD format, 1-4 decimal digits
        :param minor: number in BCD format, 1-4 decimal digits
        :param service: number in BCD format, 1-4 decimal digits
        :raises SPSDKError: Invalid version
        """
        if not all(
            [
                BcdVersion3._check_number(major),
                BcdVersion3._check_number(minor),
                BcdVersion3._check_number(service),
            ]
        ):
            raise SPSDKError("Invalid version")
        self.major = major
        self.minor = minor
        self.service = service

    def __str__(self) -> str:
        return f"{self.major:X}.{self.minor:X}.{self.service:X}"

    def __repr__(self) -> str:
        return self.__class__.__name__ + ": " + self.__str__()

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, BcdVersion3)
            and (self.major == other.major)
            and (self.minor == other.minor)
            and (self.service == other.service)
        )

    @property
    def nums(self) -> Sequence[int]:
        """Return array of version numbers: [major, minor, service]."""
        return [self.major, self.minor, self.service]


def pack_timestamp(value: datetime) -> int:
    """Converts datetime to millisecond since 1.1.2000.

    :param value: datetime to be converted
    :return: number of milliseconds since 1.1.2000  00:00:00; 64-bit integer
    :raises SPSDKError: When there is incorrect result of conversion
    """
    assert isinstance(value, datetime)
    start = datetime(2000, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc).timestamp()
    result = int((value.timestamp() - start) * 1000000)
    if result < 0 or result > 0xFFFFFFFFFFFFFFFF:
        raise SPSDKError("Incorrect result of conversion")
    return result


def unpack_timestamp(value: int) -> datetime:
    """Converts timestamp in milliseconds into datetime.

    :param value: number of milliseconds since 1.1.2000  00:00:00; 64-bit integer
    :return: corresponding datetime
    :raises SPSDKError: When there is incorrect result of conversion
    """
    assert isinstance(value, int)
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise SPSDKError("Incorrect result of conversion")
    start = int(datetime(2000, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc).timestamp() * 1000000)
    return datetime.fromtimestamp((start + value) / 1000000)
