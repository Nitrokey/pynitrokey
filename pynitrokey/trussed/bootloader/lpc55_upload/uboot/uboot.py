#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Simple Uboot serial console implementation."""

import logging

from crcmod.predefined import mkPredefinedCrcFun
from hexdump import restore
from serial import Serial

from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import align, change_endianness, split_data

logger = logging.getLogger(__name__)


class Uboot:
    """Class for encapsulation of Uboot CLI interface."""

    LINE_FEED = "\n"
    ENCODING = "ascii"
    READ_ALIGNMENT = 16
    DATA_BYTES_SPLIT = 4
    PROMPT = b"u-boot=> "

    def __init__(
        self, port: str, timeout: int = 1, baudrate: int = 115200, crc: bool = True
    ) -> None:
        """Uboot constructor.

        :param port: TTY port
        :param timeout: timeout in seconds, defaults to 1
        :param baudrate: baudrate, defaults to 115200
        :param crc: True if crc will be calculated, defaults to True
        """
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.is_opened = False
        self.open()
        self.crc = crc

    def calc_crc(self, data: bytes, address: int, count: int) -> None:
        """Calculate CRC from the data.

        :param data: data to calculate CRC from
        :param address: address from where the data should be calculated
        :param count: count of bytes
        :raises SPSDKError: Invalid CRC of data
        """
        if not self.crc:
            return
        crc_command = f"crc32 {hex(address)} {hex(count)}"
        self.write(crc_command)
        hexdump_str = self.LINE_FEED.join(self.read_output().splitlines()[1:-1])
        crc_obtained = "0x" + hexdump_str[-8:]
        logger.debug(f"CRC command:\n{crc_command}\n{crc_obtained}")
        crc_function = mkPredefinedCrcFun("crc-32")
        calculated_crc = hex(crc_function(data))
        logger.debug(f"Calculated CRC {calculated_crc}")
        if calculated_crc != crc_obtained:
            raise SPSDKError(f"Invalid CRC of data {calculated_crc} != {crc_obtained}")

    def open(self) -> None:
        """Open uboot device."""
        self._device = Serial(port=self.port, timeout=self.timeout, baudrate=self.baudrate)
        self.is_opened = True

    def close(self) -> None:
        """Close uboot device."""
        self._device.close()
        self.is_opened = False

    def read(self, length: int) -> str:
        """Read specified number of charactrs from uboot CLI.

        :param length: count of read characters
        :return: encoded string
        """
        output = self._device.read(length)
        return output.decode(encoding=self.ENCODING)

    def read_output(self) -> str:
        """Read CLI output until prompt.

        :return: ASCII encoded output
        """
        return self._device.read_until(expected=self.PROMPT).decode(self.ENCODING)

    def write(self, data: str) -> None:
        """Write ASCII decoded data to CLI. Append LINE FEED if not present.

        :param data: ASCII decoded data
        """
        if self.LINE_FEED not in data:
            data += self.LINE_FEED
        data_bytes = bytes(data, encoding=self.ENCODING)
        self._device.write(data_bytes)

    def read_memory(self, address: int, count: int) -> bytes:
        """Read memory using the md command. Optionally calculate CRC.

        :param address: Address in memory
        :param count: Count of bytes
        :return: data as bytes
        """
        count = align(count, self.READ_ALIGNMENT)
        md_command = f"md.b {hex(address)} {hex(count)}"
        self.write(md_command)
        hexdump_str = self.LINE_FEED.join(self.read_output().splitlines()[1:-1])
        logger.debug(f"read_memory:\n{md_command}\n{hexdump_str}")
        data = restore(hexdump_str)
        self.calc_crc(data, address, count)

        return data

    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory and optionally calculate CRC.

        :param address: Address in memory
        :param data: data as bytes
        """
        start_address = address
        for splitted_data in split_data(data, self.DATA_BYTES_SPLIT):
            mw_command = f"mw.l {hex(address)} {change_endianness(splitted_data).hex()}"
            logger.debug(f"write_memory: {mw_command}")
            self.write(mw_command)
            address += len(splitted_data)
            self.read_output()

        self.calc_crc(data, start_address, len(data))
