#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Buspal Mboot device implementation."""
import datetime
import logging
import struct
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from serial import SerialException
from serial.tools.list_ports import comports
from typing_extensions import Self

from ...exceptions import SPSDKError
from ...mboot.exceptions import McuBootConnectionError, McuBootDataAbortError
from ...mboot.protocol.serial_protocol import FPType, MbootSerialProtocol, to_int
from ...utils.interfaces.device.serial_device import SerialDevice

logger = logging.getLogger(__name__)


@dataclass
class ScanArgs:
    """Scan arguments dataclass."""

    port: Optional[str]
    props: Optional[List[str]]

    @classmethod
    def parse(cls, params: str, extra_params: Optional[str] = None) -> Self:
        """Parse given scanning parameters and extra parameters into ScanArgs class.

        :param params: Parameters as a string
        :param extra_params: Optional extra parameters as a string
        """
        props = []
        if extra_params:
            props = extra_params.split(",")
        target = props.pop(0)
        if target not in ["spi", "i2c"]:
            raise SPSDKError(f"Target must be either 'spi' or 'ic2', not {target}")
        port_parts = params.split(",")
        return cls(port=port_parts.pop(0), props=props)


class SpiModeCommand(Enum):
    """Spi mode commands."""

    exit = 0x00  # 00000000 - Exit to bit bang mode
    version = 0x01  # 00000001 - Enter raw SPI mode, display version string
    chip_select = 0x02  # 0000001x - CS high (1) or low (0)
    sniff = 0x0C  # 000011XX - Sniff SPI traffic when CS low(10)/all(01)
    bulk_transfer = 0x10  # 0001xxxx - Bulk SPI transfer, send/read 1-16 bytes (0=1byte!)
    config_periph = 0x40  # 0100wxyz - Configure peripherals w=power, x=pull-ups, y=AUX, z=CS
    set_speed = 0x60  # 01100xxx - SPI speed
    config_spi = 0x80  # 1000wxyz - SPI config, w=HiZ/3.3v, x=CKP idle, y=CKE edge, z=SMP sample
    write_then_read = 0x04  # 00000100 - Write then read extended command


# pylint: disable=invalid-name
class SpiConfigShift(Enum):
    """Spi configuration shifts for the mask."""

    direction = 0
    phase = 1
    polarity = 2


# pylint: disable=invalid-name
class SpiClockPolarity(Enum):
    """SPI clock polarity configuration."""

    active_high = 0  # Active-high SPI clock (idles low).
    active_low = 1  # Active-low SPI clock (idles high).


# pylint: disable=invalid-name
class SpiClockPhase(Enum):
    """SPI clock phase configuration."""

    # First edge on SPSCK occurs at the middle of the first cycle of a data transfer.
    first_edge = 0
    # First edge on SPSCK occurs at the start of the first cycle of a data transfer.
    second_edge = 1


# pylint: disable=invalid-name
class SpiShiftDirection(Enum):
    """SPI clock phase configuration."""

    msb_first = 0  # Data transfers start with most significant bit.
    lsb_first = 1  # Data transfers start with least significant bit.


class SpiConfiguration:
    """Dataclass to store SPI configuration."""

    speed: int
    polarity: SpiClockPolarity
    phase: SpiClockPhase
    direction: SpiShiftDirection


# pylint: disable=invalid-name
class BBConstants(Enum):
    """Constants."""

    reset_count = 20  # Max number of nulls to send to enter BBIO mode
    response_ok = 0x01  # Successful command response
    bulk_transfer_max = 4096  # Max number of bytes per bulk transfer
    packet_timeout_ms = 10  # Packet timeout in milliseconds


class Response(str, Enum):
    """Response to enter bit bang mode."""

    BITBANG = "BBIO1"
    SPI = "SPI1"
    I2C = "I2C1"


class BuspalMode(Enum):
    """Bit Bang mode command."""

    RESET = 0x00  # Reset, responds "BBIO1"
    SPI = 0x01  # Enter binary SPI mode, responds "SPI1"
    I2C = 0x02  # Enter binary I2C mode, responds "I2C1"


MODE_COMMANDS_RESPONSES = {
    BuspalMode.RESET: Response.BITBANG,
    BuspalMode.SPI: Response.SPI,
    BuspalMode.I2C: Response.I2C,
}


class MbootBuspalProtocol(MbootSerialProtocol):
    """Mboot Serial protocol."""

    default_baudrate = 57600
    default_timeout = 5000
    device: SerialDevice
    mode: BuspalMode

    def __init__(self, device: SerialDevice) -> None:
        """Initialize the MbootBuspalProtocol object.

        :param device: The device instance
        """
        super().__init__(device)

    def open(self) -> None:
        """Open the interface."""
        self.device.open()
        # reset first, send bit-bang command
        self._enter_mode(BuspalMode.RESET)
        logger.debug("Entered BB mode")
        self._enter_mode(self.mode)

    @classmethod
    def scan(
        cls,
        port: Optional[str] = None,
        props: Optional[List[str]] = None,
        timeout: Optional[int] = None,
    ) -> List[SerialDevice]:
        """Scan connected serial ports and set BUSPAL properties.

        Returns list of serial ports with devices that respond to BUSPAL communication protocol.
        If 'port' is specified, only that serial port is checked
        If no devices are found, return an empty list.

        :param port: name of preferred serial port, defaults to None
        :param timeout: timeout in milliseconds
        :param props: buspal target properties
        :return: list of available interfaces
        """
        timeout = timeout or cls.default_timeout
        if port:
            device = cls._check_port_buspal(port, timeout, props)
            devices = [device] if device else []
        else:
            all_ports = [
                cls._check_port_buspal(comport.device, timeout, props)
                for comport in comports(include_links=True)
            ]
            devices = list(filter(None, all_ports))
        return devices

    @classmethod
    def _check_port_buspal(
        cls, port: str, timeout: int, props: Optional[List[str]] = None
    ) -> Optional[SerialDevice]:
        """Check if device on comport 'port' can connect using BUSPAL communication protocol.

        :param port: name of port to check
        :param timeout: timeout in milliseconds
        :param props: buspal settings
        :return: None if device doesn't respond to PING, instance of Interface if it does
        """
        props = props if props is not None else []
        try:
            device = SerialDevice(port=port, timeout=timeout, baudrate=cls.default_baudrate)
            interface = cls(device)
            interface.open()
            interface._configure(props)
            interface._ping()
            return device
        except (AssertionError, SerialException, McuBootConnectionError) as e:
            logger.error(str(e))
            return None

    def _send_frame(self, frame: bytes, wait_for_ack: bool = True) -> None:
        """Send frame method to be implemented by child class."""
        raise NotImplementedError()

    def _read(self, size: int, timeout: Optional[int] = None) -> bytes:
        """Implementation done by child class."""
        raise NotImplementedError()

    def _configure(self, props: List[str]) -> None:
        """Configure the BUSPAL interface.

        :param props: buspal settings
        """
        raise NotImplementedError()

    def _enter_mode(self, mode: BuspalMode) -> None:
        """Enter BUSPAL mode.

        :param mode: buspal mode
        """
        response = MODE_COMMANDS_RESPONSES[mode]
        self._send_command_check_response(
            bytes([mode.value]), bytes(response.value.encode("utf-8"))
        )

    def _send_command_check_response(self, command: bytes, response: bytes) -> None:
        """Send a command and check if expected response is received.

        :param command: command to send
        :param response: expected response
        """
        self.device.write(command)
        data_recvd = self.device.read(len(response))
        format_received = " ".join(hex(x) for x in data_recvd)
        format_expected = " ".join(hex(x) for x in response)
        assert (
            format_received == format_expected
        ), f"Received data '{format_received}' but expected '{format_expected}'"

    def _read_frame_header(self, expected_frame_type: Optional[FPType] = None) -> Tuple[int, int]:
        """Read frame header and frame type. Return them as tuple of integers.

        :param expected_frame_type: Check if the frame_type is exactly as expected
        :return: Tuple of integers representing frame header and frame type
        :raises AssertionError: Unexpected frame header or frame type (if specified)
        :raises McuBootDataAbortError: Abort frame received
        """
        header = None
        time_start = datetime.datetime.now()
        time_end = time_start + datetime.timedelta(milliseconds=self.device.timeout)

        # read uart until start byte is equal to FRAME_START_BYTE, max. 'retry_count' times
        while header != self.FRAME_START_BYTE and datetime.datetime.now() < time_end:
            header = to_int(self._read(1))
            if header == FPType.ABORT:
                raise McuBootDataAbortError()
            if header != self.FRAME_START_BYTE:
                time.sleep(BBConstants.packet_timeout_ms.value / 1000)
        assert (
            header == self.FRAME_START_BYTE
        ), f"Received invalid frame header '{header:#X}' expected '{self.FRAME_START_BYTE:#X}'"

        frame_type = to_int(self._read(1))

        if frame_type == FPType.ABORT:
            raise McuBootDataAbortError()
        return header, frame_type


class MbootBuspalSPIInterface(MbootBuspalProtocol):
    """BUSPAL SPI interface."""

    TARGET_SETTINGS = ["speed", "polarity", "phase", "direction"]

    HDR_FRAME_RETRY_CNT = 3
    ACK_WAIT_DELAY = 0.01  # in seconds
    device: SerialDevice
    identifier = "buspal_spi"

    def __init__(self, device: SerialDevice):
        """Initialize the BUSPAL SPI interface.

        :param port: name of the serial port, defaults to None
        :param timeout: read/write timeout in milliseconds
        """
        self.mode = BuspalMode.SPI
        super().__init__(device)

    @classmethod
    def scan_from_args(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> List[Self]:
        """Scan connected Buspal devices.

        :param params: Params as a configuration string
        :param extra_params: Extra params configuration string
        :param timeout: Timeout for the scan
        :return: list of matching RawHid devices
        """
        scan_args = ScanArgs.parse(params, extra_params)
        devices = cls.scan(port=scan_args.port, props=scan_args.props, timeout=timeout)
        interfaces = []
        for device in devices:
            interfaces.append(cls(device))
        return interfaces

    def _configure(self, props: List[str]) -> None:
        """Configure the BUSPAL SPI interface.

        :param props: buspal settings
        """
        spi_props: Dict[str, Any] = dict(zip(self.TARGET_SETTINGS, props))

        speed = int(spi_props.get("speed", 100))
        polarity = SpiClockPolarity(spi_props.get("polarity", SpiClockPolarity.active_low))
        phase = SpiClockPhase(spi_props.get("phase", SpiClockPhase.second_edge))
        direction = SpiShiftDirection(spi_props.get("direction", SpiShiftDirection.msb_first))

        # set SPI config
        logger.debug("Set SPI config")
        spi_data = polarity.value << SpiConfigShift.polarity.value
        spi_data |= phase.value << SpiConfigShift.phase.value
        spi_data |= direction.value << SpiConfigShift.direction.value
        spi_data |= SpiModeCommand.config_spi.value
        self._send_command_check_response(bytes([spi_data]), bytes([BBConstants.response_ok.value]))

        # set SPI speed
        logger.debug(f"Set SPI speed to {speed}bps")
        spi_speed = struct.pack("<BI", SpiModeCommand.set_speed.value, speed)
        self._send_command_check_response(spi_speed, bytes([BBConstants.response_ok.value]))

    def _send_frame(self, data: bytes, wait_for_ack: bool = True) -> None:
        """Send data to BUSPAL I2C device.

        :param data: Data to send
        """
        self._send_frame_retry(data, wait_for_ack, self.HDR_FRAME_RETRY_CNT)

    def _send_frame_retry(
        self, data: bytes, wait_for_ack: bool = True, retry_cnt: int = HDR_FRAME_RETRY_CNT
    ) -> None:
        """Send a frame to BUSPAL SPI device.

        :param data: Data to send
        :param wait_for_ack: Wait for ACK frame from device, defaults to True
        :param retry_cnt: Number of retry in case the header frame is incorrect
        :raises AssertionError: Unexpected frame header or frame type (if specified)
        """
        size = min(len(data), BBConstants.bulk_transfer_max.value)
        command = struct.pack("<BHH", SpiModeCommand.write_then_read.value, size, 0)
        self.device.write(command)
        self._send_command_check_response(data, bytes([BBConstants.response_ok.value]))
        if wait_for_ack:
            try:
                # minimum delay between ack and response is 5-7ms
                time.sleep(self.ACK_WAIT_DELAY)
                self._read_frame_header()
            except AssertionError as error:
                # retry reading the SPI header frame in case check has failed
                if retry_cnt > 0:
                    logger.error(
                        f"{error} (retry {self.HDR_FRAME_RETRY_CNT-retry_cnt+1}/{self.HDR_FRAME_RETRY_CNT})"
                    )
                    retry_cnt -= 1
                    self._send_frame_retry(data, wait_for_ack, retry_cnt)
                else:
                    raise SPSDKError("Failed retrying reading the SPI header frame") from error

    def _read(self, size: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount of bytes from BUSPAL SPI device.

        :return: Data read from the device
        """
        size = min(size, BBConstants.bulk_transfer_max.value)
        command = struct.pack("<BHH", SpiModeCommand.write_then_read.value, 0, size)
        self._send_command_check_response(command, bytes([BBConstants.response_ok.value]))
        return self.device.read(size, timeout)


class I2cModeCommand(Enum):
    """I2c mode commands."""

    exit = 0x00  # 00000000 - Exit to bit bang mode
    version = 0x01  # 00000001 - Display mode version string, responds "I2Cx"
    start_bit = 0x02  # 00000010 - I2C start bit
    stop_bit = 0x03  # 00000011 - I2C stop bit
    read_byte = 0x04  # 00000100 - I2C read byte
    ack_bit = 0x06  # 00000110 - ACK bit
    nack_bit = 0x07  # 00000111 - NACK bit
    bus_sniff = 0x0F  # 00001111 - Start bus sniffer
    bulk_write = 0x10  # 0001xxxx - Bulk I2C write, send 1-16 bytes (0=1byte!)
    configure_periph = 0x40  # 0100wxyz - Configure peripherals w=power, x=pullups, y=AUX, z=CS
    pull_up_select = 0x50  # 010100xy - Pull up voltage select (BPV4 only)- x=5v y=3.3v
    set_speed = 0x60  # 011000xx - Set I2C speed, 3=~400kHz, 2=~100kHz, 1=~50kHz, 0=~5kHz (updated in v4.2 firmware)
    set_address = 0x70  # 11100000 - Set I2C address
    write_then_read = 0x08  # Write then read


class MbootBuspalI2CInterface(MbootBuspalProtocol):
    """BUSPAL I2C interface."""

    TARGET_SETTINGS = ["speed", "address"]

    HDR_FRAME_RETRY_CNT = 3
    device: SerialDevice
    identifier = "buspal_i2c"

    def __init__(self, device: SerialDevice):
        """Initialize the BUSPAL I2C interface.

        :param port: name of the serial port, defaults to None
        :param timeout: read/write timeout in milliseconds
        """
        self.mode = BuspalMode.I2C
        super().__init__(device)

    @classmethod
    def scan_from_args(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> List[Self]:
        """Scan connected Buspal devices.

        :param params: Params as a configuration string
        :param extra_params: Extra params configuration string
        :param timeout: Timeout for the scan
        :return: list of matching RawHid devices
        """
        scan_args = ScanArgs.parse(params, extra_params)
        devices = cls.scan(port=scan_args.port, props=scan_args.props, timeout=timeout)
        interfaces = []
        for device in devices:
            interfaces.append(cls(device))
        return interfaces

    def _configure(self, props: List[str]) -> None:
        """Initialize the BUSPAL I2C interface.

        :param props: buspal settings
        """
        i2c_props: Dict[str, Any] = dict(zip(self.TARGET_SETTINGS, props))

        # get I2C configuration values, use default values if settings are not defined in input string)
        speed = int(i2c_props.get("speed", 100))
        address = int(i2c_props.get("address", 0x10))

        # set I2C address
        logger.debug(f"Set I2C address to {address}")
        i2c_data = struct.pack("<BB", I2cModeCommand.set_address.value, address)
        self._send_command_check_response(i2c_data, bytes([BBConstants.response_ok.value]))

        # set I2C speed."""
        logger.debug(f"Set I2C speed to {speed}bps")
        i2c_data = struct.pack("<BI", I2cModeCommand.set_speed.value, speed)
        self._send_command_check_response(i2c_data, bytes([BBConstants.response_ok.value]))

    def _send_frame(
        self,
        data: bytes,
        wait_for_ack: bool = True,
    ) -> None:
        """Send data to BUSPAL I2C device.

        :param data: Data to send
        """
        self._send_frame_retry(data, wait_for_ack, self.HDR_FRAME_RETRY_CNT)

    def _send_frame_retry(
        self, data: bytes, wait_for_ack: bool = True, retry_cnt: int = HDR_FRAME_RETRY_CNT
    ) -> None:
        """Send data to BUSPAL I2C device.

        :param data: Data to send
        :param wait_for_ack: Wait for ACK frame from device, defaults to True
        :param retry_cnt: Number of retry in case the header frame is incorrect
        :raises AssertionError: Unexpected frame header or frame type (if specified)
        """
        retry_cnt = self.HDR_FRAME_RETRY_CNT
        size = min(len(data), BBConstants.bulk_transfer_max.value)
        command = struct.pack("<BHH", I2cModeCommand.write_then_read.value, size, 0)
        self.device.write(command)
        self._send_command_check_response(data, bytes([BBConstants.response_ok.value]))
        if wait_for_ack:
            try:
                self._read_frame_header()
            except AssertionError as error:
                # retry reading the I2C header frame in case check has failed
                if retry_cnt > 0:
                    logger.error(
                        f"{error} (retry {self.HDR_FRAME_RETRY_CNT-retry_cnt+1}/{self.HDR_FRAME_RETRY_CNT})"
                    )
                    retry_cnt -= 1
                    self._send_frame_retry(data, wait_for_ack, retry_cnt)
                else:
                    raise SPSDKError("Failed retrying reading the I2C header frame") from error

    def _read(self, size: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount of bytes from BUSPAL I2C device.

        :return: Data read from the device
        """
        size = min(size, BBConstants.bulk_transfer_max.value)
        command = struct.pack("<BHH", I2cModeCommand.write_then_read.value, 0, size)
        self._send_command_check_response(command, bytes([BBConstants.response_ok.value]))
        return self.device.read(size, timeout)
