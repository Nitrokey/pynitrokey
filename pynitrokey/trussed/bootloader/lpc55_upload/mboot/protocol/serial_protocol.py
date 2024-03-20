#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Mboot serial implementation."""
import logging
import struct
import time
from contextlib import contextmanager
from typing import Generator, NamedTuple, Optional, Tuple, Union

from crcmod.predefined import mkPredefinedCrcFun
from typing_extensions import Self

from spsdk.exceptions import SPSDKAttributeError
from spsdk.mboot.commands import CmdResponse, parse_cmd_response
from spsdk.mboot.exceptions import McuBootConnectionError, McuBootDataAbortError
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.interfaces.commands import CmdPacketBase
from spsdk.utils.misc import Endianness, Timeout
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class PingResponse(NamedTuple):
    """Special type of response for Ping Command."""

    version: int
    options: int
    crc: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse raw data into PingResponse object.

        :param data: bytes to be unpacked to PingResponse object
            4B version, 2B data, 2B CRC16
        :raises McuBootConnectionError: Received invalid ping response
        :return: PingResponse
        """
        try:
            version, options, crc = struct.unpack("<I2H", data)
        except struct.error as err:
            raise McuBootConnectionError("Received invalid ping response") from err
        return cls(version, options, crc)


class FPType(SpsdkEnum):
    """Type of frames used in serial communication."""

    ACK = (0xA1, "ACK")
    NACK = (0xA2, "NACK")
    ABORT = (0xA3, "ABORT")
    CMD = (0xA4, "CMD")
    DATA = (0xA5, "DATA")
    PING = (0xA6, "PING")
    PINGR = (0xA7, "PINGR")


def to_int(data: bytes, little_endian: bool = True) -> int:
    """Convert bytes into single integer.

    :param data: bytes to convert
    :param little_endian: indicate byte ordering in data, defaults to True
    :return: integer
    """
    byte_order = Endianness.LITTLE if little_endian else Endianness.BIG
    return int.from_bytes(data, byteorder=byte_order.value)


class MbootSerialProtocol(MbootProtocolBase):
    """Mboot Serial protocol."""

    FRAME_START_BYTE = 0x5A
    FRAME_START_NOT_READY_LIST = [0x00]
    PING_TIMEOUT_MS = 500
    MAX_PING_RESPONSE_DUMMY_BYTES = 50
    MAX_UART_OPEN_ATTEMPTS = 3
    protocol_version: int = 0
    options: int = 0

    def open(self) -> None:
        """Open the interface.

        :raises McuBootConnectionError: In any case of fail of UART open operation.
        """
        for i in range(self.MAX_UART_OPEN_ATTEMPTS):
            try:
                self.device.open()
                self._ping()
                logger.debug(f"Interface opened after {i + 1} attempts.")
                return
            except TimeoutError as e:
                # Closing may take up 30-40 seconds
                self.close()
                logger.debug(f"Timeout when pinging the device: {repr(e)}")
            except McuBootConnectionError as e:
                self.close()
                logger.debug(f"Opening interface failed with: {repr(e)}")
            except Exception as exc:
                self.close()
                raise McuBootConnectionError("UART Interface open operation fails.") from exc
        raise McuBootConnectionError(
            f"Cannot open UART interface after {self.MAX_UART_OPEN_ATTEMPTS} attempts."
        )

    def close(self) -> None:
        """Close the interface."""
        self.device.close()

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""
        return self.device.is_opened

    def write_data(self, data: bytes) -> None:
        """Encapsulate data into frames and send them to device.

        :param data: Data to be sent
        """
        frame = self._create_frame(data, FPType.DATA)
        self._send_frame(frame)

    def write_command(self, packet: CmdPacketBase) -> None:
        """Encapsulate command into frames and send them to device.

        :param packet: Command packet object to be sent
        :raises SPSDKAttributeError: Command packed contains no data to be sent
        """
        data = packet.to_bytes(padding=False)
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        frame = self._create_frame(data, FPType.CMD)
        self._send_frame(frame)

    def read(self, length: Optional[int] = None) -> Union[CmdResponse, bytes]:
        """Read data from device.

        :return: read data
        :raises McuBootDataAbortError: Indicates data transmission abort
        :raises McuBootConnectionError: When received invalid CRC
        """
        _, frame_type = self._read_frame_header()
        _length = to_int(self._read(2))
        crc = to_int(self._read(2))
        if not _length:
            self._send_ack()
            raise McuBootDataAbortError()
        data = self._read(_length)
        self._send_ack()
        calculated_crc = self._calc_frame_crc(data, frame_type)
        if crc != calculated_crc:
            raise McuBootConnectionError("Received invalid CRC")
        if frame_type == FPType.CMD:
            return parse_cmd_response(data)
        return data

    def _read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Internal read, done mainly due BUSPAL, where this is overriden."""
        return self.device.read(length, timeout)

    def _send_ack(self) -> None:
        """Send ACK command."""
        ack_frame = struct.pack("<BB", self.FRAME_START_BYTE, FPType.ACK.tag)
        self._send_frame(ack_frame, wait_for_ack=False)

    def _send_frame(self, frame: bytes, wait_for_ack: bool = True) -> None:
        """Write frame to the device and wait for ack.

        :param data: Data to be send
        """
        self.device.write(frame)
        if wait_for_ack:
            self._read_frame_header(FPType.ACK)

    def _create_frame(self, data: bytes, frame_type: FPType) -> bytes:
        """Encapsulate data into frame."""
        crc = self._calc_frame_crc(data, frame_type.tag)
        frame = struct.pack(
            f"<BBHH{len(data)}B",
            self.FRAME_START_BYTE,
            frame_type.tag,
            len(data),
            crc,
            *data,
        )
        return frame

    def _calc_frame_crc(self, data: bytes, frame_type: int) -> int:
        """Calculate the CRC of a frame.

        :param data: frame data
        :param frame_type: frame type
        :return: calculated CRC
        """
        crc_data = struct.pack(
            f"<BBH{len(data)}B", self.FRAME_START_BYTE, frame_type, len(data), *data
        )
        return self._calc_crc(crc_data)

    @staticmethod
    def _calc_crc(data: bytes) -> int:
        """Calculate CRC from the data.

        :param data: data to calculate CRC from
        :return: calculated CRC
        """
        crc_function = mkPredefinedCrcFun("xmodem")
        return crc_function(data)

    def _read_frame_header(self, expected_frame_type: Optional[FPType] = None) -> Tuple[int, int]:
        """Read frame header and frame type. Return them as tuple of integers.

        :param expected_frame_type: Check if the frame_type is exactly as expected
        :return: Tuple of integers representing frame header and frame type
        :raises McuBootDataAbortError: Target sens Data Abort frame
        :raises McuBootConnectionError: Unexpected frame header or frame type (if specified)
        :raises McuBootConnectionError: When received invalid ACK
        """
        assert isinstance(self.device.timeout, int)
        timeout = Timeout(self.device.timeout, "ms")
        while not timeout.overflow():
            header = to_int(self._read(1))
            if header not in self.FRAME_START_NOT_READY_LIST:
                break
        # This is workaround addressing SPI ISP issue on RT5/6xx when sometimes
        # ACK frames and START BYTE frames are swapped, see SPSDK-1824 for more details
        if header not in [self.FRAME_START_BYTE, FPType.ACK]:
            raise McuBootConnectionError(
                f"Received invalid frame header '{header:#X}' expected '{self.FRAME_START_BYTE:#X}'"
                + "\nTry increasing the timeout, some operations might take longer"
            )
        if header == FPType.ACK:
            frame_type: int = header
        else:
            frame_type = to_int(self._read(1))
        if frame_type == FPType.ABORT:
            raise McuBootDataAbortError()
        if expected_frame_type:
            if frame_type == self.FRAME_START_BYTE:
                frame_type = header
            if frame_type != expected_frame_type:
                raise McuBootConnectionError(
                    f"received invalid ACK '{frame_type:#X}' expected '{expected_frame_type.tag:#X}'"
                )
        return header, frame_type

    def _ping(self) -> None:
        """Ping the target device, retrieve protocol version.

        :raises McuBootConnectionError: If the target device doesn't respond to ping
        :raises McuBootConnectionError: If the start frame is not received
        :raises McuBootConnectionError: If the header is invalid
        :raises McuBootConnectionError: If the frame type is invalid
        :raises McuBootConnectionError: If the ping response is not received
        :raises McuBootConnectionError: If crc does not match
        """
        with self.ping_timeout(timeout=self.PING_TIMEOUT_MS):
            ping = struct.pack("<BB", self.FRAME_START_BYTE, FPType.PING.tag)

            self._send_frame(ping, wait_for_ack=False)

            # after power cycle, MBoot v 3.0+ may respond to first command with a leading dummy data
            # we read data from UART until the FRAME_START_BYTE byte
            start_byte = b""
            for i in range(self.MAX_PING_RESPONSE_DUMMY_BYTES):
                start_byte = self._read(1)
                if start_byte is None:
                    raise McuBootConnectionError("Failed to receive initial byte")

                if start_byte == self.FRAME_START_BYTE.to_bytes(
                    length=1, byteorder=Endianness.LITTLE.value
                ):
                    logger.debug(f"FRAME_START_BYTE received in {i + 1}. attempt.")
                    break
            else:
                raise McuBootConnectionError("Failed to receive FRAME_START_BYTE")

            header = to_int(start_byte)
            if header != self.FRAME_START_BYTE:
                raise McuBootConnectionError("Header is invalid")
            frame_type = to_int(self._read(1))
            if FPType.from_tag(frame_type) != FPType.PINGR:
                raise McuBootConnectionError("Frame type is invalid")

            response_data = self._read(8)
            if response_data is None:
                raise McuBootConnectionError("Failed to receive ping response")
            response = PingResponse.parse(response_data)

            # ping response has different crc computation than the other responses
            # that's why we can't use calc_frame_crc method
            # crc data for ping excludes the last 2B of response data, which holds the CRC from device
            crc_data = struct.pack(
                f"<BB{len(response_data) -2}B", header, frame_type, *response_data[:-2]
            )
            crc = self._calc_crc(crc_data)
            if crc != response.crc:
                raise McuBootConnectionError("Received CRC doesn't match")

            self.protocol_version = response.version
            self.options = response.options

    @contextmanager
    def ping_timeout(self, timeout: int = PING_TIMEOUT_MS) -> Generator[None, None, None]:
        """Context manager for changing UART's timeout.

        :param timeout: New temporary timeout in milliseconds, defaults to PING_TIMEOUT_MS (500ms)
        :return: Generator[None, None, None]
        """
        assert isinstance(self.device.timeout, int)
        context_timeout = min(timeout, self.device.timeout)
        original_timeout = self.device.timeout
        self.device.timeout = context_timeout
        logger.debug(f"Setting timeout to {context_timeout} ms")
        # driver needs to be reconfigured after timeout change, wait for a little while
        time.sleep(0.005)

        yield

        self.device.timeout = original_timeout
        logger.debug(f"Restoring timeout to {original_timeout} ms")
        time.sleep(0.005)
