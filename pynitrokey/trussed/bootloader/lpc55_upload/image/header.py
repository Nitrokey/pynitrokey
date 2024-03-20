#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Header."""

from struct import calcsize, pack, unpack_from
from typing import Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.utils.abstract import BaseClass
from spsdk.utils.spsdk_enum import SpsdkEnum

########################################################################################################################
# Enums
########################################################################################################################


class SegTag(SpsdkEnum):
    """Segments Tag."""

    XMCD = (0xC0, "XMCD", "External Memory Configuration Data")
    DCD = (0xD2, "DCD", "Device Configuration Data")
    CSF = (0xD4, "CSF", "Command Sequence File Data")
    # i.MX6, i.MX7, i.MX8M
    IVT2 = (0xD1, "IVT2", "Image Vector Table (Version 2)")
    CRT = (0xD7, "CRT", "Certificate")
    SIG = (0xD8, "SIG", "Signature")
    EVT = (0xDB, "EVT", "Event")
    RVT = (0xDD, "RVT", "ROM Vector Table")
    WRP = (0x81, "WRP", "Wrapped Key")
    MAC = (0xAC, "MAC", "Message Authentication Code")
    # i.MX8QXP_A0, i.MX8QM_A0
    IVT3 = (0xDE, "IVT3", "Image Vector Table (Version 3)")
    # i.MX8QXP_B0, i.MX8QM_B0
    BIC1 = (0x87, "BIC1", "Boot Images Container")
    SIGB = (0x90, "SIGB", "Signature block")


class CmdTag(SpsdkEnum):
    """CSF/DCD Command Tag."""

    SET = (0xB1, "SET", "Set")
    INS_KEY = (0xBE, "INS_KEY", "Install Key")
    AUT_DAT = (0xCA, "AUT_DAT", "Authenticate Data")
    WRT_DAT = (0xCC, "WRT_DAT", "Write Data")
    CHK_DAT = (0xCF, "CHK_DAT", "Check Data")
    NOP = (0xC0, "NOP", "No Operation (NOP)")
    INIT = (0xB4, "INIT", "Initialize")
    UNLK = (0xB2, "UNLK", "Unlock")


########################################################################################################################
# Classes
########################################################################################################################


class Header(BaseClass):
    """Header element type."""

    FORMAT = ">BHB"
    SIZE = calcsize(FORMAT)

    @property
    def size(self) -> int:
        """Header size in bytes."""
        return self.SIZE

    def __init__(self, tag: int = 0, param: int = 0, length: Optional[int] = None) -> None:
        """Constructor.

        :param tag: section tag
        :param param: TODO
        :param length: length of the segment or command; if not specified, size of the header is used
        :raises SPSDKError: If invalid length
        """
        self._tag = tag
        self.param: int = param
        self.length: int = self.SIZE if length is None else length
        if self.SIZE > self.length or self.length >= 65536:
            raise SPSDKError("Invalid length")

    @property
    def tag(self) -> int:
        """:return: section tag: command tag or segment tag, ..."""
        return self._tag

    @property
    def tag_name(self) -> str:
        """Returns the header's tag name."""
        return SegTag.get_label(self.tag)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.tag_name}, {self.param}, {self.length})"

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} <TAG:{self.tag_name} 0x{self.tag:02X}, "
            f"PARAM:0x{self.param:02X}, LEN:{self.length}B>"
        )

    def export(self) -> bytes:
        """Binary representation of the header."""
        return pack(self.FORMAT, self.tag, self.length, self.param)

    @classmethod
    def parse(cls, data: bytes, required_tag: Optional[int] = None) -> Self:
        """Parse header.

        :param data: Raw data as bytes or bytearray
        :param required_tag: Check header TAG if specified value or ignore if is None
        :return: Header object
        :raises SPSDKParsingError: if required header tag does not match
        """
        tag, length, param = unpack_from(cls.FORMAT, data)
        if required_tag is not None and tag != required_tag:
            raise SPSDKParsingError(
                f" Invalid header tag: '0x{tag:02X}' expected '0x{required_tag:02X}' "
            )

        return cls(tag, param, length)


class CmdHeader(Header):
    """Command header."""

    def __init__(
        self, tag: Union[CmdTag, int], param: int = 0, length: Optional[int] = None
    ) -> None:
        """Constructor.

        :param tag: command tag
        :param param: TODO
        :param length: of the command binary section, in bytes
        :raises SPSDKError: If invalid command tag
        """
        tag = tag.tag if isinstance(tag, CmdTag) else tag
        super().__init__(tag, param, length)
        if tag not in CmdTag.tags():
            raise SPSDKError("Invalid command tag")

    @property
    def tag(self) -> int:
        """Command tag."""
        return self._tag

    @classmethod
    def parse(cls, data: bytes, required_tag: Optional[int] = None) -> Self:
        """Create Header from binary data.

        :param data: binary data to convert into header
        :param required_tag: CmdTag, None if not required
        :return: parsed instance
        :raises SPSDKParsingError: If required header tag does not match
        :raises SPSDKError: If invalid tag
        """
        if required_tag is not None:
            if required_tag not in CmdTag.tags():
                raise SPSDKError("Invalid tag")
        return super(CmdHeader, cls).parse(data, required_tag)


class Header2(Header):
    """Header element type."""

    FORMAT = "<BHB"

    def export(self) -> bytes:
        """Binary representation of the header."""
        return pack(self.FORMAT, self.param, self.length, self.tag)

    @classmethod
    def parse(cls, data: bytes, required_tag: Optional[int] = None) -> Self:
        """Parse header.

        :param data: Raw data as bytes or bytearray
        :param required_tag: Check header TAG if specified value or ignore if is None
        :raises SPSDKParsingError: Raises an error if required tag is empty or not valid
        :return: Header2 object
        """
        param, length, tag = unpack_from(cls.FORMAT, data)
        if required_tag is not None and tag != required_tag:
            raise SPSDKParsingError(
                f" Invalid header tag: '0x{tag:02X}' expected '0x{required_tag:02X}' "
            )

        return cls(tag, param, length)
