#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Sdio Mboot interface implementation."""
import logging
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

from typing_extensions import Self

from ...mboot.commands import CmdResponse, parse_cmd_response
from ...mboot.exceptions import McuBootConnectionError, McuBootDataAbortError
from ...mboot.protocol.serial_protocol import FPType, MbootSerialProtocol
from ...utils.interfaces.device.sdio_device import SdioDevice

logger = logging.getLogger(__name__)

SDIO_DEVICES = {
    # NAME   | VID   | PID
    "RW61x": (0x0471, 0x0209),
}


@dataclass
class ScanArgs:
    """Scan arguments dataclass."""

    device_path: str

    @classmethod
    def parse(cls, params: str) -> Self:
        """Parse given scanning parameters into ScanArgs class.

        :param params: Parameters as a string
        """
        return cls(device_path=params)


class MbootSdioInterface(MbootSerialProtocol):
    """Sdio interface."""

    identifier = "sdio"
    device: SdioDevice
    sdio_devices = SDIO_DEVICES

    def __init__(self, device: SdioDevice) -> None:
        """Initialize the MbootSdioInterface object.

        :param device: The device instance
        """
        super().__init__(device=device)

    @property
    def name(self) -> str:
        """Get the name of the device.

        :return: Name of the device.
        """
        assert isinstance(self.device, SdioDevice)
        for name, value in self.sdio_devices.items():
            if value[0] == self.device.vid and value[1] == self.device.pid:
                return name
        return "Unknown"

    @classmethod
    def scan_from_args(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> List[Self]:
        """Scan connected USB devices.

        :param params: Params as a configuration string
        :param extra_params: Extra params configuration string
        :param timeout: Interface timeout
        :return: list of matching RawHid devices
        """
        scan_args = ScanArgs.parse(params)
        interfaces = cls.scan(device_path=scan_args.device_path, timeout=timeout)
        return interfaces

    @classmethod
    def scan(
        cls,
        device_path: str,
        timeout: Optional[int] = None,
    ) -> List[Self]:
        """Scan connected SDIO devices.

        :param device_path: device path string
        :param timeout: Interface timeout
        :return: matched SDIO device
        """
        devices = SdioDevice.scan(device_path=device_path, timeout=timeout)
        return [cls(device) for device in devices]

    def open(self) -> None:
        """Open the interface."""
        self.device.open()

    def read(self, length: Optional[int] = None) -> Union[CmdResponse, bytes]:
        """Read data on the IN endpoint associated to the HID interface.

        :return: Return CmdResponse object.
        :raises McuBootConnectionError: Raises an error if device is not opened for reading
        :raises McuBootConnectionError: Raises if device is not available
        :raises McuBootDataAbortError: Raises if reading fails
        :raises TimeoutError: When timeout occurs
        """
        raw_data = self._read(1024)
        if not raw_data:
            logger.error("Cannot read from SDIO device")
            raise TimeoutError()

        _, frame_type = self._parse_frame_header(raw_data)
        _length, crc = struct.unpack_from("<HH", raw_data, 2)
        if not _length:
            self._send_ack()
            raise McuBootDataAbortError()
        data = raw_data[6 : 6 + _length]
        self._send_ack()
        calculated_crc = self._calc_frame_crc(data, frame_type)
        if crc != calculated_crc:
            raise McuBootConnectionError("Received invalid CRC")
        if frame_type == FPType.CMD:
            return parse_cmd_response(data)
        return data

    def _read_frame_header(self, expected_frame_type: Optional[FPType] = None) -> Tuple[int, int]:
        """Read frame header and frame type. Return them as tuple of integers.

        :param expected_frame_type: Check if the frame_type is exactly as expected
        :return: Tuple of integers representing frame header and frame type
        :raises McuBootDataAbortError: Target sens Data Abort frame
        :raises McuBootConnectionError: Unexpected frame header or frame type (if specified)
        :raises McuBootConnectionError: When received invalid ACK
        """
        data = self._read(2)
        return self._parse_frame_header(data, FPType.ACK)

    def _parse_frame_header(
        self, frame: bytes, expected_frame_type: Optional[FPType] = None
    ) -> Tuple[int, int]:
        """Read frame header and frame type. Return them as tuple of integers.

        :param expected_frame_type: Check if the frame_type is exactly as expected
        :return: Tuple of integers representing frame header and frame type
        :raises McuBootDataAbortError: Target sens Data Abort frame
        :raises McuBootConnectionError: Unexpected frame header or frame type (if specified)
        :raises McuBootConnectionError: When received invalid ACK
        """
        header, frame_type = struct.unpack_from("<BB", frame, 0)
        if header != self.FRAME_START_BYTE:
            raise McuBootConnectionError(
                f"Received invalid frame header '{header:#X}' expected '{self.FRAME_START_BYTE:#X}'"
            )
        if frame_type == FPType.ABORT:
            raise McuBootDataAbortError()
        if expected_frame_type:
            if frame_type != expected_frame_type:
                raise McuBootConnectionError(
                    f"received invalid ACK '{frame_type:#X}' expected '{expected_frame_type.tag:#X}'"
                )
        return header, frame_type
