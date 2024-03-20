#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Misc."""
import io
from io import SEEK_CUR
from typing import Optional, Union

from spsdk.exceptions import SPSDKError
from spsdk.utils.registers import value_to_int

from .header import Header


class RawDataException(SPSDKError):
    """Raw data read failed."""


class StreamReadFailed(RawDataException):
    """Read_raw_data could not read stream."""


class NotEnoughBytesException(RawDataException):
    """Read_raw_data could not read enough data."""


def hexdump_fmt(data: bytes, tab: int = 4, length: int = 16, sep: str = ":") -> str:
    """Dump some potentially larger data in hex."""
    text = " " * tab
    for i, j in enumerate(data):
        text += f"{j:02x}{sep}"
        if ((i + 1) % length) == 0:
            text += "\n" + " " * tab
    return text


def modulus_fmt(modulus: bytes, tab: int = 4, length: int = 15, sep: str = ":") -> str:
    """Modulus format."""
    return hexdump_fmt(b"\0" + modulus, tab, length, sep)


def read_raw_data(
    stream: Union[io.BufferedReader, io.BytesIO],
    length: int,
    index: Optional[int] = None,
    no_seek: bool = False,
) -> bytes:
    """Read raw data."""
    if index is not None:
        if index < 0:
            raise SPSDKError(f" Index must be non-negative, found {index}")
        if index != stream.tell():
            stream.seek(index)

    if length < 0:
        raise SPSDKError(f" Length must be non-negative, found {length}")

    try:
        data = stream.read(length)
    except Exception as exc:
        raise StreamReadFailed(f" stream.read() failed, requested {length} bytes") from exc

    if len(data) != length:
        raise NotEnoughBytesException(
            f" Could not read enough bytes, expected {length}, found {len(data)}"
        )

    if no_seek:
        stream.seek(-length, SEEK_CUR)

    return data


def read_raw_segment(
    buffer: Union[io.BufferedReader, io.BytesIO], segment_tag: int, index: Optional[int] = None
) -> bytes:
    """Read raw segment."""
    hrdata = read_raw_data(buffer, Header.SIZE, index)
    length = Header.parse(hrdata, segment_tag).length - Header.SIZE
    return hrdata + read_raw_data(buffer, length)


def dict_diff(main: dict, mod: dict) -> dict:
    """Return a difference between two dictionaries if key is not present in main, it's skipped."""
    diff = {}
    for key, value in mod.items():
        if isinstance(value, dict):
            sub = dict_diff(main[key], value)
            if sub:
                diff[key] = sub
        else:
            if key not in main:
                continue
            main_value = main[key] if isinstance(main, dict) else main
            try:
                if value_to_int(main_value) != value_to_int(value):
                    diff[key] = value
            except (SPSDKError, TypeError):
                # Not a number!
                if main_value != value:
                    diff[key] = value
    return diff
