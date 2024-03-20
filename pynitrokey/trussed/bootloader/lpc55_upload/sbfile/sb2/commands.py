#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands used by SBFile module."""
import math
from abc import abstractmethod
from struct import calcsize, pack, unpack_from
from typing import Mapping, Optional, Type

from crcmod.predefined import mkPredefinedCrcFun
from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.mboot.memories import ExtMemId
from spsdk.sbfile.misc import SecBootBlckSize
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum

########################################################################################################################
# Constants
########################################################################################################################

DEVICE_ID_MASK = 0xFF
DEVICE_ID_SHIFT = 0
GROUP_ID_MASK = 0xF00
GROUP_ID_SHIFT = 8


########################################################################################################################
# Enums
########################################################################################################################
class EnumCmdTag(SpsdkEnum):
    """Command tags."""

    NOP = (0x0, "NOP")
    TAG = (0x1, "TAG")
    LOAD = (0x2, "LOAD")
    FILL = (0x3, "FILL")
    JUMP = (0x4, "JUMP")
    CALL = (0x5, "CALL")
    ERASE = (0x7, "ERASE")
    RESET = (0x8, "RESET")
    MEM_ENABLE = (0x9, "MEM_ENABLE")
    PROG = (0xA, "PROG")
    FW_VERSION_CHECK = (0xB, "FW_VERSION_CHECK", "Check FW version fuse value")
    WR_KEYSTORE_TO_NV = (
        0xC,
        "WR_KEYSTORE_TO_NV",
        "Restore key-store restore to non-volatile memory",
    )
    WR_KEYSTORE_FROM_NV = (0xD, "WR_KEYSTORE_FROM_NV", "Backup key-store from non-volatile memory")


class EnumSectionFlag(SpsdkEnum):
    """Section flags."""

    BOOTABLE = (0x0001, "BOOTABLE")
    CLEARTEXT = (0x0002, "CLEARTEXT")
    LAST_SECT = (0x8000, "LAST_SECT")


########################################################################################################################
# Header Class
########################################################################################################################
class CmdHeader(BaseClass):
    """SBFile command header."""

    FORMAT = "<2BH3L"
    SIZE = calcsize(FORMAT)

    @property
    def crc(self) -> int:
        """Calculate CRC for the header data."""
        raw_data = self._raw_data(crc=0)
        checksum = 0x5A
        for i in range(1, self.SIZE):
            checksum = (checksum + raw_data[i]) & 0xFF
        return checksum

    def __init__(self, tag: int, flags: int = 0) -> None:
        """Initialize header."""
        if tag not in EnumCmdTag.tags():
            raise SPSDKError("Incorrect command tag")
        self.tag = tag
        self.flags = flags
        self.address = 0
        self.count = 0
        self.data = 0

    def __repr__(self) -> str:
        return f"SB2 Command header, TAG:{self.tag}"

    def __str__(self) -> str:
        tag = (
            EnumCmdTag.get_label(self.tag) if self.tag in EnumCmdTag.tags() else f"0x{self.tag:02X}"
        )
        return (
            f"tag={tag}, flags=0x{self.flags:04X}, "
            f"address=0x{self.address:08X}, count=0x{self.count:08X}, data=0x{self.data:08X}"
        )

    def _raw_data(self, crc: int) -> bytes:
        """Return raw data of the header with specified CRC.

        :param crc: value to be used
        :return: binary representation of the header
        """
        return pack(self.FORMAT, crc, self.tag, self.flags, self.address, self.count, self.data)

    def export(self) -> bytes:
        """Export command header as bytes."""
        return self._raw_data(self.crc)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command header from bytes.

        :param data: Input data as bytes
        :return: CMDHeader object
        :raises SPSDKError: raised when size is incorrect
        :raises SPSDKError: Raised when CRC is incorrect
        """
        if calcsize(cls.FORMAT) > len(data):
            raise SPSDKError("Incorrect size")
        obj = cls(EnumCmdTag.NOP.tag)
        (crc, obj.tag, obj.flags, obj.address, obj.count, obj.data) = unpack_from(cls.FORMAT, data)
        if crc != obj.crc:
            raise SPSDKError("CRC does not match")
        return obj


########################################################################################################################
# Commands Classes
########################################################################################################################
class CmdBaseClass(BaseClass):
    """Base class for all commands."""

    # bit mask for device ID inside flags
    ROM_MEM_DEVICE_ID_MASK = 0xFF00
    # shift for device ID inside flags
    ROM_MEM_DEVICE_ID_SHIFT = 8
    # bit mask for group ID inside flags
    ROM_MEM_GROUP_ID_MASK = 0xF0
    # shift for group ID inside flags
    ROM_MEM_GROUP_ID_SHIFT = 4

    def __init__(self, tag: EnumCmdTag) -> None:
        """Initialize CmdBase."""
        self._header = CmdHeader(tag.tag)

    @property
    def header(self) -> CmdHeader:
        """Return command header."""
        return self._header

    @property
    def raw_size(self) -> int:
        """Return size of the command in binary format (including header)."""
        return CmdHeader.SIZE  # this is default implementation

    def __repr__(self) -> str:
        return "Command: " + str(self._header)  # default implementation: use command name

    def __str__(self) -> str:
        """Return text info about the instance."""
        return repr(self) + "\n"  # default implementation is same as __repr__

    def export(self) -> bytes:
        """Return object serialized into bytes."""
        return self._header.export()  # default implementation


class CmdNop(CmdBaseClass):
    """Command NOP class."""

    def __init__(self) -> None:
        """Initialize Command Nop."""
        super().__init__(EnumCmdTag.NOP)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: CMD Nop object
        :raises SPSDKError: When there is incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.NOP:
            raise SPSDKError("Incorrect header tag")
        return cls()


class CmdTag(CmdBaseClass):
    """Command TAG class.

    It is also used as header for boot section for SB file 1.x.
    """

    def __init__(self) -> None:
        """Initialize Command Tag."""
        super().__init__(EnumCmdTag.TAG)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: parsed instance
        :raises SPSDKError: When there is incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.TAG:
            raise SPSDKError("Incorrect header tag")
        result = cls()
        result._header = header
        return result


class CmdLoad(CmdBaseClass):
    """Command Load. The load statement is used to store data into the memory."""

    @property
    def address(self) -> int:
        """Return address in target processor to load data."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Setter.

        :param value: address in target processor to load data
        :raises SPSDKError: When there is incorrect address
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def flags(self) -> int:
        """Return command's flag."""
        return self._header.flags

    @flags.setter
    def flags(self, value: int) -> None:
        """Set command's flag."""
        self._header.flags = value

    @property
    def raw_size(self) -> int:
        """Return aligned size of the command including header and data."""
        size = CmdHeader.SIZE + len(self.data)
        if size % CmdHeader.SIZE:
            size += CmdHeader.SIZE - (size % CmdHeader.SIZE)
        return size

    def __init__(self, address: int, data: bytes, mem_id: int = 0) -> None:
        """Initialize CMD Load."""
        super().__init__(EnumCmdTag.LOAD)
        assert isinstance(data, (bytes, bytearray))
        self.address = address
        self.data = bytes(data)
        self.mem_id = mem_id

        device_id = get_device_id(mem_id)
        group_id = get_group_id(mem_id)

        self.flags |= (self.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (device_id << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )

        self.flags |= (self.flags & ~self.ROM_MEM_GROUP_ID_MASK) | (
            (group_id << self.ROM_MEM_GROUP_ID_SHIFT) & self.ROM_MEM_GROUP_ID_MASK
        )

    def __str__(self) -> str:
        return (
            f"LOAD: Address=0x{self.address:08X}, DataLen={len(self.data)}, "
            f"Flags=0x{self.flags:08X}, MemId=0x{self.mem_id:08X}"
        )

    def export(self) -> bytes:
        """Export command as binary."""
        self._update_data()
        result = super().export()
        return result + self.data

    def _update_data(self) -> None:
        """Update command data."""
        # padding data
        self.data = SecBootBlckSize.align_block_fill_random(self.data)
        # update header
        self._header.count = len(self.data)
        crc32_function = mkPredefinedCrcFun("crc-32-mpeg")
        self._header.data = crc32_function(self.data, 0xFFFFFFFF)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: CMD Load object
        :raises SPSDKError: Raised when there is invalid CRC
        :raises SPSDKError: When there is incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.LOAD:
            raise SPSDKError("Incorrect header tag")
        header_count = SecBootBlckSize.align(header.count)
        cmd_data = data[CmdHeader.SIZE : CmdHeader.SIZE + header_count]
        crc32_function = mkPredefinedCrcFun("crc-32-mpeg")
        if header.data != crc32_function(cmd_data, 0xFFFFFFFF):
            raise SPSDKError("Invalid CRC in the command header")
        device_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        group_id = (header.flags & cls.ROM_MEM_GROUP_ID_MASK) >> cls.ROM_MEM_GROUP_ID_SHIFT
        mem_id = get_memory_id(device_id, group_id)
        obj = cls(header.address, cmd_data, mem_id)
        obj.header.data = header.data
        obj.header.flags = header.flags
        obj._update_data()
        return obj


class CmdFill(CmdBaseClass):
    """Command Fill class."""

    PADDING_VALUE = 0x00

    @property
    def address(self) -> int:
        """Return address of the command Fill."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set address for the command Fill."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def raw_size(self) -> int:
        """Calculate raw size of header."""
        size = CmdHeader.SIZE
        size += len(self._pattern) - 4
        if size % CmdHeader.SIZE:
            size += CmdHeader.SIZE - (size % CmdHeader.SIZE)
        return size

    def __init__(self, address: int, pattern: int, length: Optional[int] = None) -> None:
        """Initialize Command Fill.

        :param address: to write data
        :param pattern: data to be written
        :param length: length of data to be filled, defaults to 4
        :raises SPSDKError: Raised when size is not aligned to 4 bytes
        """
        super().__init__(EnumCmdTag.FILL)
        length = length or 4
        if length % 4:
            raise SPSDKError("Length of memory range to fill must be a multiple of 4")
        # if the pattern is a zero, the length is considered also as zero and the
        # conversion to bytes produces empty byte "array", which is wrong, as
        # zero should be converted to zero byte. Thus in case the pattern_len
        # evaluates to 0, we set it to 1.
        pattern_len = pattern.bit_length() / 8 or 1
        # We can get a number of 3 bytes, so we consider this as a word and set
        # the length to 4 bytes with the first byte being zero.
        if 3 == math.ceil(pattern_len):
            pattern_len = 4
        pattern_bytes = pattern.to_bytes(math.ceil(pattern_len), Endianness.BIG.value)
        # The pattern length is computed above, but as we transform the number
        # into bytes, compute the len again just in case - a bit paranoid
        # approach chosen.
        if len(pattern_bytes) not in [1, 2, 4]:
            raise SPSDKError("Pattern must be 1, 2 or 4 bytes long")
        replicate = 4 // len(pattern_bytes)
        final_pattern = replicate * pattern_bytes
        self.address = address
        self._pattern = final_pattern
        # update header
        self._header.data = unpack_from(">L", self._pattern)[0]
        self._header.count = length

    @property
    def pattern(self) -> bytes:
        """Return binary data to fill."""
        return self._pattern

    def __str__(self) -> str:
        return f"FILL: Address=0x{self.address:08X}, Pattern=" + " ".join(
            f"{byte:02X}" for byte in self._pattern
        )

    def export(self) -> bytes:
        """Return command in binary form (serialization)."""
        # export cmd
        data = super().export()
        # export additional data
        data = SecBootBlckSize.align_block_fill_random(data)
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: Command Fill object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.FILL:
            raise SPSDKError("Incorrect header tag")
        return cls(header.address, header.data, header.count)


class CmdJump(CmdBaseClass):
    """Command Jump class."""

    @property
    def address(self) -> int:
        """Return address of the command Jump."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set address of the command Jump."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def argument(self) -> int:
        """Return command's argument."""
        return self._header.data

    @argument.setter
    def argument(self, value: int) -> None:
        """Set command's argument."""
        self._header.data = value

    @property
    def spreg(self) -> Optional[int]:
        """Return command's Stack Pointer."""
        if self._header.flags == 2:
            return self._header.count

        return None

    @spreg.setter
    def spreg(self, value: Optional[int] = None) -> None:
        """Set command's Stack Pointer."""
        if value is None:
            self._header.flags = 0
            self._header.count = 0
        else:
            self._header.flags = 2
            self._header.count = value

    def __init__(self, address: int = 0, argument: int = 0, spreg: Optional[int] = None) -> None:
        """Initialize Command Jump."""
        super().__init__(EnumCmdTag.JUMP)
        self.address = address
        self.argument = argument
        self.spreg = spreg

    def __str__(self) -> str:
        nfo = f"JUMP: Address=0x{self.address:08X}, Argument=0x{self.argument:08X}"
        if self.spreg is not None:
            nfo += f", SP=0x{self.spreg:08X}"
        return nfo

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: Command Jump object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.JUMP:
            raise SPSDKError("Incorrect header tag")
        return cls(header.address, header.data, header.count if header.flags else None)


class CmdCall(CmdBaseClass):
    """Command Call.

    The call statement is used for inserting a bootloader command that executes a function
    from one of the files that are loaded into the memory.
    """

    @property
    def address(self) -> int:
        """Return command's address."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set command's address."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def argument(self) -> int:
        """Return command's argument."""
        return self._header.data

    @argument.setter
    def argument(self, value: int) -> None:
        """Set command's argument."""
        self._header.data = value

    def __init__(self, address: int = 0, argument: int = 0) -> None:
        """Initialize Command Call."""
        super().__init__(EnumCmdTag.CALL)
        self.address = address
        self.argument = argument

    def __str__(self) -> str:
        return f"CALL: Address=0x{self.address:08X}, Argument=0x{self.argument:08X}"

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: Command Call object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.CALL:
            raise SPSDKError("Incorrect header tag")
        return cls(header.address, header.data)


class CmdErase(CmdBaseClass):
    """Command Erase class."""

    @property
    def address(self) -> int:
        """Return command's address."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set command's address."""
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def length(self) -> int:
        """Return command's count."""
        return self._header.count

    @length.setter
    def length(self, value: int) -> None:
        """Set command's count."""
        self._header.count = value

    @property
    def flags(self) -> int:
        """Return command's flag."""
        return self._header.flags

    @flags.setter
    def flags(self, value: int) -> None:
        """Set command's flag."""
        self._header.flags = value

    def __init__(self, address: int = 0, length: int = 0, flags: int = 0, mem_id: int = 0) -> None:
        """Initialize Command Erase."""
        super().__init__(EnumCmdTag.ERASE)
        self.address = address
        self.length = length
        self.flags = flags
        self.mem_id = mem_id

        device_id = get_device_id(mem_id)
        group_id = get_group_id(mem_id)

        self.flags |= (self.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (device_id << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )

        self.flags |= (self.flags & ~self.ROM_MEM_GROUP_ID_MASK) | (
            (group_id << self.ROM_MEM_GROUP_ID_SHIFT) & self.ROM_MEM_GROUP_ID_MASK
        )

    def __str__(self) -> str:
        return (
            f"ERASE: Address=0x{self.address:08X}, Length={self.length}, Flags=0x{self.flags:08X}, "
            f"MemId=0x{self.mem_id:08X}"
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: Command Erase object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.ERASE:
            raise SPSDKError("Invalid header tag")
        device_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        group_id = (header.flags & cls.ROM_MEM_GROUP_ID_MASK) >> cls.ROM_MEM_GROUP_ID_SHIFT
        mem_id = get_memory_id(device_id, group_id)
        return cls(header.address, header.count, header.flags, mem_id)


class CmdReset(CmdBaseClass):
    """Command Reset class."""

    def __init__(self) -> None:
        """Initialize Command Reset."""
        super().__init__(EnumCmdTag.RESET)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: Cmd Reset object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.RESET:
            raise SPSDKError("Invalid header tag")
        return cls()


class CmdMemEnable(CmdBaseClass):
    """Command to configure certain memory."""

    @property
    def address(self) -> int:
        """Return command's address."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Set command's address."""
        self._header.address = value

    @property
    def size(self) -> int:
        """Return command's size."""
        return self._header.count

    @size.setter
    def size(self, value: int) -> None:
        """Set command's size."""
        self._header.count = value

    @property
    def flags(self) -> int:
        """Return command's flag."""
        return self._header.flags

    @flags.setter
    def flags(self, value: int) -> None:
        """Set command's flag."""
        self._header.flags = value

    def __init__(self, address: int, size: int, mem_id: int):
        """Initialize CmdMemEnable.

        :param address: source address with configuration data for memory initialization
        :param size: size of configuration data used for memory initialization
        :param mem_id: identification of memory
        """
        super().__init__(EnumCmdTag.MEM_ENABLE)
        self.address = address
        self.mem_id = mem_id
        self.size = size

        device_id = get_device_id(mem_id)
        group_id = get_group_id(mem_id)

        self.flags |= (self.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (device_id << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )

        self.flags |= (self.flags & ~self.ROM_MEM_GROUP_ID_MASK) | (
            (group_id << self.ROM_MEM_GROUP_ID_SHIFT) & self.ROM_MEM_GROUP_ID_MASK
        )

    def __str__(self) -> str:
        return (
            f"MEM-ENABLE: Address=0x{self.address:08X}, Size={self.size}, "
            f"Flags=0x{self.flags:08X}, MemId=0x{self.mem_id:08X}"
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: Command Memory Enable object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.MEM_ENABLE:
            raise SPSDKError("Invalid header tag")
        device_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        group_id = (header.flags & cls.ROM_MEM_GROUP_ID_MASK) >> cls.ROM_MEM_GROUP_ID_SHIFT
        mem_id = get_memory_id(device_id, group_id)
        return cls(header.address, header.count, mem_id)


class CmdProg(CmdBaseClass):
    """Command Program class."""

    @property
    def address(self) -> int:
        """Return address in target processor to program data."""
        return self._header.address

    @address.setter
    def address(self, value: int) -> None:
        """Setter.

        :param value: address in target processor to load data
        :raises SPSDKError: When there is incorrect address
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect address")
        self._header.address = value

    @property
    def flags(self) -> int:
        """Return command's flag."""
        return self._header.flags

    @flags.setter
    def flags(self, value: int) -> None:
        """Set command's flag."""
        self._header.flags = self.is_eight_byte
        self._header.flags |= value

    @property
    def data_word1(self) -> int:
        """Return data word 1."""
        return self._header.count

    @data_word1.setter
    def data_word1(self, value: int) -> None:
        """Setter.

        :param value: first data word
        :raises SPSDKError: When there is incorrect value
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect data word 1")
        self._header.count = value

    @property
    def data_word2(self) -> int:
        """Return data word 2."""
        return self._header.data

    @data_word2.setter
    def data_word2(self, value: int) -> None:
        """Setter.

        :param value: second data word
        :raises SPSDKError: When there is incorrect value
        """
        if value < 0x00000000 or value > 0xFFFFFFFF:
            raise SPSDKError("Incorrect data word 2")
        self._header.data = value

    def __init__(
        self, address: int, mem_id: int, data_word1: int, data_word2: int = 0, flags: int = 0
    ) -> None:
        """Initialize CMD Prog."""
        super().__init__(EnumCmdTag.PROG)

        if data_word2:
            self.is_eight_byte = 1
        else:
            self.is_eight_byte = 0

        if mem_id < 0 or mem_id > 0xFF:
            raise SPSDKError("Invalid ID of memory")

        self.address = address
        self.data_word1 = data_word1
        self.data_word2 = data_word2
        self.mem_id = mem_id
        self.flags = flags

        self.flags = (self.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (self.mem_id << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )

    def __str__(self) -> str:
        return (
            f"PROG: Index=0x{self.address:08X}, DataWord1=0x{self.data_word1:08X}, "
            f"DataWord2=0x{self.data_word2:08X}, Flags=0x{self.flags:08X}, MemId=0x{self.mem_id:08X}"
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: parsed command object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.PROG:
            raise SPSDKError("Invalid header tag")
        mem_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        return cls(header.address, mem_id, header.count, header.data, header.flags)


class VersionCheckType(SpsdkEnum):
    """Select type of the version check: either secure or non-secure firmware to be checked."""

    SECURE_VERSION = (0, "SECURE_VERSION")
    NON_SECURE_VERSION = (1, "NON_SECURE_VERSION")


class CmdVersionCheck(CmdBaseClass):
    """FW Version Check command class.

    Validates version of secure or non-secure firmware.
    The command fails if version is < expected.
    """

    def __init__(self, ver_type: VersionCheckType, version: int) -> None:
        """Initialize CmdVersionCheck.

        :param ver_type: version check type, see `VersionCheckType` enum
        :param version: to be checked
        :raises SPSDKError: If invalid version check type
        """
        super().__init__(EnumCmdTag.FW_VERSION_CHECK)
        if ver_type not in VersionCheckType:
            raise SPSDKError("Invalid version check type")
        self.header.address = ver_type.tag
        self.header.count = version

    @property
    def type(self) -> VersionCheckType:
        """Return type of the check version, see VersionCheckType enumeration."""
        return VersionCheckType.from_tag(self.header.address)

    @property
    def version(self) -> int:
        """Return minimal version expected."""
        return self.header.count

    def __str__(self) -> str:
        return (
            f"CVER: Type={self.type.label}, Version={str(self.version)}, "
            f"Flags=0x{self.header.flags:08X}"
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: parsed command object
        :raises SPSDKError: If incorrect header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != EnumCmdTag.FW_VERSION_CHECK:
            raise SPSDKError("Invalid header tag")
        ver_type = VersionCheckType.from_tag(header.address)
        version = header.count
        return cls(ver_type, version)


class CmdKeyStoreBackupRestore(CmdBaseClass):
    """Shared, abstract implementation for key-store backup and restore command."""

    # bit mask for controller ID inside flags
    ROM_MEM_DEVICE_ID_MASK = 0xFF00
    # shift for controller ID inside flags
    ROM_MEM_DEVICE_ID_SHIFT = 8

    @classmethod
    @abstractmethod
    def cmd_id(cls) -> EnumCmdTag:
        """Return command ID.

        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")

    def __init__(self, address: int, controller_id: ExtMemId):
        """Initialize CmdKeyStoreBackupRestore.

        :param address: where to backup key-store or source for restoring key-store
        :param controller_id: ID of the memory to backup key-store or source memory to load key-store back
        :raises SPSDKError: If invalid address
        :raises SPSDKError: If invalid id of memory
        """
        super().__init__(self.cmd_id())
        if address < 0 or address > 0xFFFFFFFF:
            raise SPSDKError("Invalid address")
        self.header.address = address
        if controller_id.tag < 0 or controller_id.tag > 0xFF:
            raise SPSDKError("Invalid ID of memory")
        self.header.flags = (self.header.flags & ~self.ROM_MEM_DEVICE_ID_MASK) | (
            (controller_id.tag << self.ROM_MEM_DEVICE_ID_SHIFT) & self.ROM_MEM_DEVICE_ID_MASK
        )
        self.header.count = (
            4  # this is useless, but it is kept for backward compatibility with elftosb
        )

    @property
    def address(self) -> int:
        """Return address where to backup key-store or source for restoring key-store."""
        return self.header.address

    @property
    def controller_id(self) -> int:
        """Return controller ID of the memory to backup key-store or source memory to load key-store back."""
        return (self.header.flags & self.ROM_MEM_DEVICE_ID_MASK) >> self.ROM_MEM_DEVICE_ID_SHIFT

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse command from bytes.

        :param data: Input data as bytes
        :return: CmdKeyStoreBackupRestore object
        :raises SPSDKError: When there is invalid header tag
        """
        header = CmdHeader.parse(data)
        if header.tag != cls.cmd_id():
            raise SPSDKError("Invalid header tag")
        address = header.address
        controller_id = (header.flags & cls.ROM_MEM_DEVICE_ID_MASK) >> cls.ROM_MEM_DEVICE_ID_SHIFT
        return cls(address, ExtMemId.from_tag(controller_id))


class CmdKeyStoreBackup(CmdKeyStoreBackupRestore):
    """Command to backup keystore from non-volatile memory."""

    @classmethod
    def cmd_id(cls) -> EnumCmdTag:
        """Return command ID for backup operation."""
        return EnumCmdTag.WR_KEYSTORE_FROM_NV


class CmdKeyStoreRestore(CmdKeyStoreBackupRestore):
    """Command to restore keystore into non-volatile memory."""

    @classmethod
    def cmd_id(cls) -> EnumCmdTag:
        """Return command ID for restore operation."""
        return EnumCmdTag.WR_KEYSTORE_TO_NV


########################################################################################################################
# Command parser from binary format
########################################################################################################################
_CMD_CLASS: Mapping[EnumCmdTag, Type[CmdBaseClass]] = {
    EnumCmdTag.NOP: CmdNop,
    EnumCmdTag.TAG: CmdTag,
    EnumCmdTag.LOAD: CmdLoad,
    EnumCmdTag.FILL: CmdFill,
    EnumCmdTag.JUMP: CmdJump,
    EnumCmdTag.CALL: CmdCall,
    EnumCmdTag.ERASE: CmdErase,
    EnumCmdTag.RESET: CmdReset,
    EnumCmdTag.MEM_ENABLE: CmdMemEnable,
    EnumCmdTag.PROG: CmdProg,
    EnumCmdTag.FW_VERSION_CHECK: CmdVersionCheck,
    EnumCmdTag.WR_KEYSTORE_TO_NV: CmdKeyStoreRestore,
    EnumCmdTag.WR_KEYSTORE_FROM_NV: CmdKeyStoreBackup,
}


def parse_command(data: bytes) -> CmdBaseClass:
    """Parse SB 2.x command from bytes.

    :param data: Input data as bytes
    :return: parsed command object
    :raises SPSDKError: Raised when there is unsupported command provided
    """
    header_tag = data[1]
    for cmd_tag, cmd in _CMD_CLASS.items():
        if cmd_tag.tag == header_tag:
            return cmd.parse(data)
    raise SPSDKError(f"Unsupported command: {str(header_tag)}")


def get_device_id(mem_id: int) -> int:
    """Get device ID from memory ID.

    :param mem_id: memory ID
    :return: device ID
    """
    return ((mem_id) & DEVICE_ID_MASK) >> DEVICE_ID_SHIFT


def get_group_id(mem_id: int) -> int:
    """Get group ID from memory ID.

    :param mem_id: memory ID
    :return: group ID
    """
    return ((mem_id) & GROUP_ID_MASK) >> GROUP_ID_SHIFT


def get_memory_id(device_id: int, group_id: int) -> int:
    """Get memory ID from device ID and group ID.

    :param device_id: device ID
    :param group_id: group ID
    :return: memory ID
    """
    return (((group_id) << GROUP_ID_SHIFT) & GROUP_ID_MASK) | (
        ((device_id) << DEVICE_ID_SHIFT) & DEVICE_ID_MASK
    )
