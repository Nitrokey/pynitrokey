#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Mboot bulk implementation."""
import logging
from struct import pack, unpack_from
from typing import Optional, Union

from spsdk.exceptions import SPSDKAttributeError
from spsdk.mboot.commands import CmdResponse, parse_cmd_response
from spsdk.mboot.exceptions import McuBootConnectionError, McuBootDataAbortError
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.commands import CmdPacketBase
from spsdk.utils.spsdk_enum import SpsdkEnum


class ReportId(SpsdkEnum):
    """Report ID enum."""

    CMD_OUT = (0x01, "CMD_OUT")
    CMD_IN = (0x03, "CMD_IN")
    DATA_OUT = (0x02, "DATA_OUT")
    DATA_IN = (0x04, "DATA_IN")


logger = logging.getLogger(__name__)


class MbootBulkProtocol(MbootProtocolBase):
    """Mboot Bulk protocol."""

    def open(self) -> None:
        """Open the interface."""
        self.device.open()

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
        frame = self._create_frame(data, ReportId.DATA_OUT)
        if self.allow_abort:
            try:
                abort_data = self.device.read(1024, timeout=10)
                logger.debug(f"Read {len(abort_data)} bytes of abort data")
            except Exception as e:
                raise McuBootConnectionError(str(e)) from e
            if abort_data:
                logger.debug(f"{', '.join(f'{b:02X}' for b in abort_data)}")
                raise McuBootDataAbortError()
        self.device.write(frame)

    def write_command(self, packet: CmdPacketBase) -> None:
        """Encapsulate command into frames and send them to device.

        :param packet: Command packet object to be sent
        :raises SPSDKAttributeError: Command packed contains no data to be sent
        """
        data = packet.to_bytes(padding=False)
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        frame = self._create_frame(data, ReportId.CMD_OUT)
        self.device.write(frame)

    def read(self, length: Optional[int] = None) -> Union[CmdResponse, bytes]:
        """Read data from device.

        :return: read data
        :raises SPSDKTimeoutError: Timeout occurred
        """
        data = self.device.read(1024)
        if not data:
            logger.error("Cannot read from HID device")
            raise SPSDKTimeoutError()
        return self._parse_frame(bytes(data))

    def _create_frame(self, data: bytes, report_id: ReportId) -> bytes:
        """Encode the USB packet.

        :param report_id: ID of the report (see: HID_REPORT)
        :param data: Data to send
        :return: Encoded bytes and length of the final report frame
        """
        raw_data = pack("<2BH", report_id.tag, 0x00, len(data))
        raw_data += data
        logger.debug(f"OUT[{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return raw_data

    @staticmethod
    def _parse_frame(raw_data: bytes) -> Union[CmdResponse, bytes]:
        """Decodes the data read on USB interface.

        :param raw_data: Data received
        :return: CmdResponse object or data read
        :raises McuBootDataAbortError: Transaction aborted by target
        """
        logger.debug(f"IN [{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        report_id, _, plen = unpack_from("<2BH", raw_data)
        if plen == 0:
            raise McuBootDataAbortError()
        data = raw_data[4 : 4 + plen]
        if report_id == ReportId.CMD_IN:
            return parse_cmd_response(data)
        return data
