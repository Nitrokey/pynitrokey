# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from typing import Optional, Sequence, Tuple


def build_one(tag: int, data: bytes) -> bytes:
    data_len = len(data)
    out = bytearray()
    out += tag.to_bytes((tag.bit_length() + 7) // 8, byteorder="big")
    if data_len <= 0x7F:
        out.append(data_len)
    elif data_len <= 0xFF:
        out.append(0x81)
        out.append(data_len)
    else:
        assert data_len <= 0xFFFF
        out.append(0x82)
        out += data_len.to_bytes((data_len.bit_length() + 7) // 8, byteorder="big")

    return out + data


def take_tag(data: bytes) -> Tuple[int, bytes]:
    data_len = len(data)
    if data_len == 0:
        raise ValueError("Failed to parse TLV data: empty data when parsing tag")

    b1 = data[0]
    if (b1 & 0x1F) == 0x1F:
        if data_len < 2:
            raise ValueError("Failed to parse TLV data: partial tag")
        b2 = data[1]
        return (int.from_bytes([b1, b2], byteorder="big"), data[2:])
    else:
        return (int.from_bytes([0, b1], byteorder="big"), data[1:])


def take_len(data: bytes) -> Tuple[int, bytes]:
    data_len = len(data)
    if data_len == 0:
        raise ValueError("Failed to parse TLV data: empty data when parsing len")

    l1 = data[0]
    if l1 <= 0x7F:
        return (l1, data[1:])
    elif l1 == 0x81:
        if data_len < 2:
            raise ValueError("Failed to parse TLV data: partial len")
        return (data[1], data[2:])
    elif l1 == 0x82:
        if data_len < 3:
            raise ValueError("Failed to parse TLV data: partial len")
        l2 = data[1]
        l3 = data[2]
        return (int.from_bytes([l2, l3], byteorder="big"), data[3:])
    else:
        raise ValueError("Failed to parse TLV data: invalid len")


def take_do(data: bytes) -> Tuple[int, bytes, bytes]:
    tag, rem = take_tag(data)
    len, rem = take_len(rem)

    return tag, rem[:len], rem[len:]


class Tlv:
    @staticmethod
    def build(input: Sequence[Tuple[int, bytes]]) -> bytes:
        out = bytearray()
        for tag, data in input:
            out += build_one(tag, data)
        return out

    @staticmethod
    def parse(data: bytes) -> Sequence[Tuple[int, bytes]]:
        res = []
        current = data
        while len(current) != 0:
            tag, value, rem = take_do(current)
            res.append((tag, value))
            current = rem
        return res
