#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for communication with the bootloader."""

import logging
import struct
import time
from types import TracebackType
from typing import Callable, Dict, List, Optional, Sequence, Type

from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.interfaces.device.usb_device import UsbDevice

from .commands import (
    CmdPacket,
    CmdResponse,
    CommandFlag,
    CommandTag,
    FlashReadOnceResponse,
    FlashReadResourceResponse,
    GenerateKeyBlobSelect,
    GenericResponse,
    GetPropertyResponse,
    KeyProvisioningResponse,
    KeyProvOperation,
    NoResponse,
    ReadMemoryResponse,
    TrustProvDevHsmDsc,
    TrustProvisioningResponse,
    TrustProvOperation,
    TrustProvWpc,
)
from .error_codes import StatusCode, stringify_status_code
from .exceptions import (
    McuBootCommandError,
    McuBootConnectionError,
    McuBootDataAbortError,
    McuBootError,
    SPSDKError,
)
from .memories import ExtMemId, ExtMemRegion, FlashRegion, MemoryRegion, RamRegion
from .properties import PropertyTag, PropertyValueBase, Version, parse_property_value

logger = logging.getLogger(__name__)


########################################################################################################################
# McuBoot Class
########################################################################################################################
class McuBoot:  # pylint: disable=too-many-public-methods
    """Class for communication with the bootloader."""

    DEFAULT_MAX_PACKET_SIZE = 32

    @property
    def status_code(self) -> int:
        """Return status code of the last operation."""
        return self._status_code

    @property
    def status_string(self) -> str:
        """Return status string."""
        return stringify_status_code(self._status_code)

    @property
    def is_opened(self) -> bool:
        """Return True if the device is open."""
        return self._interface.is_opened

    def __init__(self, interface: MbootProtocolBase, cmd_exception: bool = False) -> None:
        """Initialize the McuBoot object.

        :param interface: The instance of communication interface class
        :param cmd_exception: True to throw McuBootCommandError on any error;
                False to set status code only
                Note: some operation might raise McuBootCommandError is all cases

        """
        self._cmd_exception = cmd_exception
        self._status_code = StatusCode.SUCCESS.tag
        self._interface = interface
        self.reopen = False
        self.enable_data_abort = False
        self._pause_point: Optional[int] = None

    def __enter__(self) -> "McuBoot":
        self.reopen = True
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        self.close()

    def _process_cmd(self, cmd_packet: CmdPacket) -> CmdResponse:
        """Process Command.

        :param cmd_packet: Command Packet
        :return: command response derived from the CmdResponse
        :raises McuBootConnectionError: Timeout Error
        :raises McuBootCommandError: Error during command execution on the target
        """
        if not self.is_opened:
            logger.info("TX: Device not opened")
            raise McuBootConnectionError("Device not opened")

        logger.debug(f"TX-PACKET: {str(cmd_packet)}")

        try:
            self._interface.write_command(cmd_packet)
            response = self._interface.read()
        except TimeoutError:
            self._status_code = StatusCode.NO_RESPONSE.tag
            logger.debug("RX-PACKET: No Response, Timeout Error !")
            response = NoResponse(cmd_tag=cmd_packet.header.tag)

        assert isinstance(response, CmdResponse)
        logger.debug(f"RX-PACKET: {str(response)}")
        self._status_code = response.status

        if self._cmd_exception and self._status_code != StatusCode.SUCCESS:
            raise McuBootCommandError(CommandTag.get_label(cmd_packet.header.tag), response.status)
        logger.info(f"CMD: Status: {self.status_string}")
        return response

    def _read_data(
        self,
        cmd_tag: CommandTag,
        length: int,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> bytes:
        """Read data from device.

        :param cmd_tag: Tag indicating the read command.
        :param length: Length of data to read
        :param progress_callback: Callback for updating the caller about the progress
        :raises McuBootConnectionError: Timeout error or a problem opening the interface
        :raises McuBootCommandError: Error during command execution on the target
        :return: Data read from the device
        """
        data = b""

        if not self.is_opened:
            logger.error("RX: Device not opened")
            raise McuBootConnectionError("Device not opened")
        while True:
            try:
                response = self._interface.read()
            except McuBootDataAbortError as e:
                logger.error(f"RX: {e}")
                logger.info("Try increasing the timeout value")
                response = self._interface.read()
            except TimeoutError:
                self._status_code = StatusCode.NO_RESPONSE.tag
                logger.error("RX: No Response, Timeout Error !")
                response = NoResponse(cmd_tag=cmd_tag.tag)
                break

            if isinstance(response, bytes):
                data += response
                if progress_callback:
                    progress_callback(len(data), length)

            elif isinstance(response, GenericResponse):
                logger.debug(f"RX-PACKET: {str(response)}")
                self._status_code = response.status
                if response.cmd_tag == cmd_tag:
                    break

        if len(data) < length or self.status_code != StatusCode.SUCCESS:
            status_info = (
                StatusCode.get_label(self._status_code)
                if self._status_code in StatusCode.tags()
                else f"0x{self._status_code:08X}"
            )
            logger.debug(f"CMD: Received {len(data)} from {length} Bytes, {status_info}")
            if self._cmd_exception:
                assert isinstance(response, CmdResponse)
                raise McuBootCommandError(cmd_tag.label, response.status)
        else:
            logger.info(f"CMD: Successfully Received {len(data)} from {length} Bytes")

        return data[:length] if len(data) > length else data

    def _send_data(
        self,
        cmd_tag: CommandTag,
        data: List[bytes],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> bool:
        """Send Data part of specific command.

        :param cmd_tag: Tag indicating the command
        :param data: List of data chunks to send
        :param progress_callback: Callback for updating the caller about the progress
        :raises McuBootConnectionError: Timeout error
        :raises McuBootCommandError: Error during command execution on the target
        :return: True if the operation is successful
        """
        if not self.is_opened:
            logger.info("TX: Device Disconnected")
            raise McuBootConnectionError("Device Disconnected !")

        total_sent = 0
        total_to_send = sum(len(chunk) for chunk in data)
        # this difference is applicable for load-image and program-aeskey commands
        expect_response = cmd_tag != CommandTag.NO_COMMAND
        self._interface.allow_abort = self.enable_data_abort
        try:
            for data_chunk in data:
                self._interface.write_data(data_chunk)
                total_sent += len(data_chunk)
                if progress_callback:
                    progress_callback(total_sent, total_to_send)
                if self._pause_point and total_sent > self._pause_point:
                    time.sleep(0.1)
                    self._pause_point = None

            if expect_response:
                response = self._interface.read()
        except TimeoutError as e:
            self._status_code = StatusCode.NO_RESPONSE.tag
            logger.error("RX: No Response, Timeout Error !")
            raise McuBootConnectionError("No Response from Device") from e
        except SPSDKError as e:
            logger.error(f"RX: {e}")
            if expect_response:
                response = self._interface.read()
            else:
                self._status_code = StatusCode.SENDING_OPERATION_CONDITION_ERROR.tag

        if expect_response:
            assert isinstance(response, CmdResponse)
            logger.debug(f"RX-PACKET: {str(response)}")
            self._status_code = response.status
            if response.status != StatusCode.SUCCESS:
                status_info = (
                    StatusCode.get_label(self._status_code)
                    if self._status_code in StatusCode.tags()
                    else f"0x{self._status_code:08X}"
                )
                logger.debug(f"CMD: Send Error, {status_info}")
                if self._cmd_exception:
                    raise McuBootCommandError(cmd_tag.label, response.status)
                return False

        logger.info(f"CMD: Successfully Send {total_sent} out of {total_to_send} Bytes")
        return total_sent == total_to_send

    def _get_max_packet_size(self) -> int:
        """Get max packet size.

        :return int: max packet size in B
        """
        packet_size_property = None
        try:
            packet_size_property = self.get_property(prop_tag=PropertyTag.MAX_PACKET_SIZE)
        except McuBootError:
            pass
        if packet_size_property is None:
            packet_size_property = [self.DEFAULT_MAX_PACKET_SIZE]
            logger.warning(
                f"CMD: Unable to get MAX PACKET SIZE, using: {self.DEFAULT_MAX_PACKET_SIZE}"
            )
        return packet_size_property[0]

    def _split_data(self, data: bytes) -> List[bytes]:
        """Split data to send if necessary.

        :param data: Data to send
        :return: List of data splices
        """
        if not self._interface.need_data_split:
            return [data]
        max_packet_size = self._get_max_packet_size()
        logger.info(f"CMD: Max Packet Size = {max_packet_size}")
        return [data[i : i + max_packet_size] for i in range(0, len(data), max_packet_size)]

    def open(self) -> None:
        """Connect to the device."""
        logger.info(f"Connect: {str(self._interface)}")
        self._interface.open()

    def close(self) -> None:
        """Disconnect from the device."""
        logger.info(f"Closing: {str(self._interface)}")
        self._interface.close()

    def get_property_list(self) -> List[PropertyValueBase]:
        """Get a list of available properties.

        :return: List of available properties.
        :raises McuBootCommandError: Failure to read properties list
        """
        property_list: List[PropertyValueBase] = []
        for property_tag in PropertyTag:
            try:
                values = self.get_property(property_tag)
            except McuBootCommandError:
                continue

            if values:
                prop = parse_property_value(property_tag.tag, values)
                assert prop is not None, "Property values cannot be parsed"
                property_list.append(prop)

        self._status_code = StatusCode.SUCCESS.tag
        if not property_list:
            self._status_code = StatusCode.FAIL.tag
            if self._cmd_exception:
                raise McuBootCommandError("GetPropertyList", self.status_code)

        return property_list

    def _get_internal_flash(self) -> List[FlashRegion]:
        """Get information about the internal flash.

        :return: list of FlashRegion objects
        """
        index = 0
        mdata: List[FlashRegion] = []
        start_address = 0
        while True:
            try:
                values = self.get_property(PropertyTag.FLASH_START_ADDRESS, index)
                if not values:
                    break
                if index == 0:
                    start_address = values[0]
                elif start_address == values[0]:
                    break
                region_start = values[0]
                values = self.get_property(PropertyTag.FLASH_SIZE, index)
                if not values:
                    break
                region_size = values[0]
                values = self.get_property(PropertyTag.FLASH_SECTOR_SIZE, index)
                if not values:
                    break
                region_sector_size = values[0]
                mdata.append(
                    FlashRegion(
                        index=index,
                        start=region_start,
                        size=region_size,
                        sector_size=region_sector_size,
                    )
                )
                index += 1
            except McuBootCommandError:
                break

        return mdata

    def _get_internal_ram(self) -> List[RamRegion]:
        """Get information about the internal RAM.

        :return: list of RamRegion objects
        """
        index = 0
        mdata: List[RamRegion] = []
        start_address = 0
        while True:
            try:
                values = self.get_property(PropertyTag.RAM_START_ADDRESS, index)
                if not values:
                    break
                if index == 0:
                    start_address = values[0]
                elif start_address == values[0]:
                    break
                start = values[0]
                values = self.get_property(PropertyTag.RAM_SIZE, index)
                if not values:
                    break
                size = values[0]
                mdata.append(RamRegion(index=index, start=start, size=size))
                index += 1
            except McuBootCommandError:
                break

        return mdata

    def _get_ext_memories(self) -> List[ExtMemRegion]:
        """Get information about the external memories.

        :return: list of ExtMemRegion objects supported by the device
        :raises SPSDKError: If no response to get property command
        :raises SPSDKError: Other Error
        """
        ext_mem_list: List[ExtMemRegion] = []
        ext_mem_ids: Sequence[int] = ExtMemId.tags()
        try:
            values = self.get_property(PropertyTag.CURRENT_VERSION)
        except McuBootCommandError:
            values = None

        if not values and self._status_code == StatusCode.UNKNOWN_PROPERTY:
            self._status_code = StatusCode.SUCCESS.tag
            return ext_mem_list

        if not values:
            raise SPSDKError("No response to get property command")

        if Version(values[0]) <= Version("2.0.0"):
            # old versions mboot support only Quad SPI memory
            ext_mem_ids = [ExtMemId.QUAD_SPI0.tag]

        for mem_id in ext_mem_ids:
            try:
                values = self.get_property(PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, mem_id)
            except McuBootCommandError:
                values = None

            if not values:  # pragma: no cover  # corner-cases are currently untestable without HW
                if self._status_code == StatusCode.UNKNOWN_PROPERTY:
                    break

                if self._status_code in [
                    StatusCode.QSPI_NOT_CONFIGURED,
                    StatusCode.INVALID_ARGUMENT,
                ]:
                    continue

                if self._status_code == StatusCode.MEMORY_NOT_CONFIGURED:
                    ext_mem_list.append(ExtMemRegion(mem_id=mem_id))

                if self._status_code == StatusCode.SUCCESS:
                    raise SPSDKError("Other Error")

            else:
                ext_mem_list.append(ExtMemRegion(mem_id=mem_id, raw_values=values))
        return ext_mem_list

    def get_memory_list(self) -> dict:
        """Get list of embedded memories.

        :return: dict, with the following keys: internal_flash (optional) - list ,
                internal_ram (optional) - list, external_mems (optional) - list
        :raises McuBootCommandError: Error reading the memory list
        """
        memory_list: Dict[str, Sequence[MemoryRegion]] = {}

        # Internal FLASH
        mdata = self._get_internal_flash()
        if mdata:
            memory_list["internal_flash"] = mdata

        # Internal RAM
        ram_data = self._get_internal_ram()
        if mdata:
            memory_list["internal_ram"] = ram_data

        # External Memories
        ext_mem_list = self._get_ext_memories()
        if ext_mem_list:
            memory_list["external_mems"] = ext_mem_list

        self._status_code = StatusCode.SUCCESS.tag
        if not memory_list:
            self._status_code = StatusCode.FAIL.tag
            if self._cmd_exception:
                raise McuBootCommandError("GetMemoryList", self.status_code)

        return memory_list

    def flash_erase_all(self, mem_id: int = 0) -> bool:
        """Erase complete flash memory without recovering flash security section.

        :param mem_id: Memory ID
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: FlashEraseAll(mem_id={mem_id})")
        cmd_packet = CmdPacket(CommandTag.FLASH_ERASE_ALL, CommandFlag.NONE.tag, mem_id)
        response = self._process_cmd(cmd_packet)
        return response.status == StatusCode.SUCCESS

    def flash_erase_region(self, address: int, length: int, mem_id: int = 0) -> bool:
        """Erase specified range of flash.

        :param address: Start address
        :param length: Count of bytes
        :param mem_id: Memory ID
        :return: False in case of any problem; True otherwise
        """
        logger.info(
            f"CMD: FlashEraseRegion(address=0x{address:08X}, length={length}, mem_id={mem_id})"
        )
        mem_id = _clamp_down_memory_id(memory_id=mem_id)
        cmd_packet = CmdPacket(
            CommandTag.FLASH_ERASE_REGION, CommandFlag.NONE.tag, address, length, mem_id
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def read_memory(
        self,
        address: int,
        length: int,
        mem_id: int = 0,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        fast_mode: bool = False,
    ) -> Optional[bytes]:
        """Read data from MCU memory.

        :param address: Start address
        :param length: Count of bytes
        :param mem_id: Memory ID
        :param fast_mode: Fast mode for USB-HID data transfer, not reliable !!!
        :param progress_callback: Callback for updating the caller about the progress
        :return: Data read from the memory; None in case of a failure
        """
        logger.info(f"CMD: ReadMemory(address=0x{address:08X}, length={length}, mem_id={mem_id})")
        mem_id = _clamp_down_memory_id(memory_id=mem_id)

        # workaround for better USB-HID reliability
        if isinstance(self._interface.device, UsbDevice) and not fast_mode:
            payload_size = self._get_max_packet_size()
            packets = length // payload_size
            remainder = length % payload_size
            if remainder:
                packets += 1

            data = b""

            for idx in range(packets):
                if idx == packets - 1 and remainder:
                    data_len = remainder
                else:
                    data_len = payload_size

                cmd_packet = CmdPacket(
                    CommandTag.READ_MEMORY,
                    CommandFlag.NONE.tag,
                    address + idx * payload_size,
                    data_len,
                    mem_id,
                )
                cmd_response = self._process_cmd(cmd_packet)
                if cmd_response.status == StatusCode.SUCCESS:
                    data += self._read_data(CommandTag.READ_MEMORY, data_len)
                    if progress_callback:
                        progress_callback(len(data), length)
                    if self._status_code == StatusCode.NO_RESPONSE:
                        logger.warning(f"CMD: NO RESPONSE, received {len(data)}/{length} B")
                        return data
                else:
                    return b""

            return data

        cmd_packet = CmdPacket(
            CommandTag.READ_MEMORY, CommandFlag.NONE.tag, address, length, mem_id
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, ReadMemoryResponse)
            return self._read_data(CommandTag.READ_MEMORY, cmd_response.length, progress_callback)
        return None

    def write_memory(
        self,
        address: int,
        data: bytes,
        mem_id: int = 0,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> bool:
        """Write data into MCU memory.

        :param address: Start address
        :param data: List of bytes
        :param progress_callback: Callback for updating the caller about the progress
        :param mem_id: Memory ID, see ExtMemId; additionally use `0` for internal memory
        :return: False in case of any problem; True otherwise
        """
        logger.info(
            f"CMD: WriteMemory(address=0x{address:08X}, length={len(data)}, mem_id={mem_id})"
        )
        data_chunks = self._split_data(data=data)
        mem_id = _clamp_down_memory_id(memory_id=mem_id)
        cmd_packet = CmdPacket(
            CommandTag.WRITE_MEMORY, CommandFlag.HAS_DATA_PHASE.tag, address, len(data), mem_id
        )
        if self._process_cmd(cmd_packet).status == StatusCode.SUCCESS:
            return self._send_data(CommandTag.WRITE_MEMORY, data_chunks, progress_callback)
        return False

    def fill_memory(self, address: int, length: int, pattern: int = 0xFFFFFFFF) -> bool:
        """Fill MCU memory with specified pattern.

        :param address: Start address (must be word aligned)
        :param length: Count of words (must be word aligned)
        :param pattern: Count of wrote bytes
        :return: False in case of any problem; True otherwise
        """
        logger.info(
            f"CMD: FillMemory(address=0x{address:08X}, length={length}, pattern=0x{pattern:08X})"
        )
        cmd_packet = CmdPacket(
            CommandTag.FILL_MEMORY, CommandFlag.NONE.tag, address, length, pattern
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def flash_security_disable(self, backdoor_key: bytes) -> bool:
        """Disable flash security by using of backdoor key.

        :param backdoor_key: The key value as array of 8 bytes
        :return: False in case of any problem; True otherwise
        :raises McuBootError: If the backdoor_key is not 8 bytes long
        """
        if len(backdoor_key) != 8:
            raise McuBootError("Backdoor key must by 8 bytes long")
        logger.info(f"CMD: FlashSecurityDisable(backdoor_key={backdoor_key!r})")
        key_high = backdoor_key[0:4][::-1]
        key_low = backdoor_key[4:8][::-1]
        cmd_packet = CmdPacket(
            CommandTag.FLASH_SECURITY_DISABLE, CommandFlag.NONE.tag, data=key_high + key_low
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def get_property(self, prop_tag: PropertyTag, index: int = 0) -> Optional[List[int]]:
        """Get specified property value.

        :param prop_tag: Property TAG (see Properties Enum)
        :param index: External memory ID or internal memory region index (depends on property type)
        :return: list integers representing the property; None in case no response from device
        :raises McuBootError: If received invalid get-property response
        """
        logger.info(f"CMD: GetProperty({prop_tag.label}, index={index!r})")
        cmd_packet = CmdPacket(CommandTag.GET_PROPERTY, CommandFlag.NONE.tag, prop_tag.tag, index)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            if isinstance(cmd_response, GetPropertyResponse):
                return cmd_response.values
            raise McuBootError(f"Received invalid get-property response: {str(cmd_response)}")
        return None

    def set_property(self, prop_tag: PropertyTag, value: int) -> bool:
        """Set value of specified property.

        :param  prop_tag: Property TAG (see Property enumerator)
        :param  value: The value of selected property
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: SetProperty({prop_tag.label}, value=0x{value:08X})")
        cmd_packet = CmdPacket(CommandTag.SET_PROPERTY, CommandFlag.NONE.tag, prop_tag.tag, value)
        cmd_response = self._process_cmd(cmd_packet)
        return cmd_response.status == StatusCode.SUCCESS

    def receive_sb_file(
        self,
        data: bytes,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        check_errors: bool = False,
    ) -> bool:
        """Receive SB file.

        :param  data: SB file data
        :param progress_callback: Callback for updating the caller about the progress
        :param check_errors: Check for ABORT_FRAME (and related errors) on USB interface between data packets.
            When this parameter is set to `False` significantly improves USB transfer speed (cca 20x)
            However, the final status code might be misleading (original root cause may get overridden)
            In case `receive-sb-file` fails, re-run the operation with this flag set to `True`
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: ReceiveSBfile(data_length={len(data)})")
        data_chunks = self._split_data(data=data)
        cmd_packet = CmdPacket(
            CommandTag.RECEIVE_SB_FILE, CommandFlag.HAS_DATA_PHASE.tag, len(data)
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            self.enable_data_abort = check_errors
            if isinstance(self._interface.device, UsbDevice):
                try:
                    # pylint: disable=import-outside-toplevel   # import only if needed to save time
                    from spsdk.sbfile.sb2.images import ImageHeaderV2

                    sb2_header = ImageHeaderV2.parse(data=data)
                    self._pause_point = sb2_header.first_boot_tag_block * 16
                except SPSDKError:
                    pass
                try:
                    # pylint: disable=import-outside-toplevel   # import only if needed to save time
                    from spsdk.sbfile.sb31.images import SecureBinary31Header

                    sb3_header = SecureBinary31Header.parse(data=data)
                    self._pause_point = sb3_header.image_total_length
                except SPSDKError:
                    pass
            result = self._send_data(CommandTag.RECEIVE_SB_FILE, data_chunks, progress_callback)
            self.enable_data_abort = False
            return result
        return False

    def execute(self, address: int, argument: int, sp: int) -> bool:  # pylint: disable=invalid-name
        """Execute program on a given address using the stack pointer.

        :param address: Jump address (must be word aligned)
        :param argument: Function arguments address
        :param sp: Stack pointer address
        :return: False in case of any problem; True otherwise
        """
        logger.info(
            f"CMD: Execute(address=0x{address:08X}, argument=0x{argument:08X}, SP=0x{sp:08X})"
        )
        cmd_packet = CmdPacket(CommandTag.EXECUTE, CommandFlag.NONE.tag, address, argument, sp)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def call(self, address: int, argument: int) -> bool:
        """Fill MCU memory with specified pattern.

        :param address: Call address (must be word aligned)
        :param argument: Function arguments address
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: Call(address=0x{address:08X}, argument=0x{argument:08X})")
        cmd_packet = CmdPacket(CommandTag.CALL, CommandFlag.NONE.tag, address, argument)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def reset(self, timeout: int = 2000, reopen: bool = True) -> bool:
        """Reset MCU and reconnect if enabled.

        :param timeout: The maximal waiting time in [ms] for reopen connection
        :param reopen: True for reopen connection after HW reset else False
        :return: False in case of any problem; True otherwise
        :raises McuBootError: if reopen is not supported
        :raises McuBootConnectionError: Failure to reopen the device
        """
        logger.info("CMD: Reset MCU")
        cmd_packet = CmdPacket(CommandTag.RESET, CommandFlag.NONE.tag)
        ret_val = False
        status = self._process_cmd(cmd_packet).status
        self.close()
        ret_val = True

        if status not in [StatusCode.NO_RESPONSE, StatusCode.SUCCESS]:
            ret_val = False
            if self._cmd_exception:
                raise McuBootConnectionError("Reset command failed")

        if status == StatusCode.NO_RESPONSE:
            logger.warning("Did not receive response from reset command, ignoring it")
            self._status_code = StatusCode.SUCCESS.tag

        if reopen:
            if not self.reopen:
                raise McuBootError("reopen is not supported")
            time.sleep(timeout / 1000)
            try:
                self.open()
            except SPSDKError as e:
                ret_val = False
                if self._cmd_exception:
                    raise McuBootConnectionError("reopen failed") from e

        return ret_val

    def flash_erase_all_unsecure(self) -> bool:
        """Erase complete flash memory and recover flash security section.

        :return: False in case of any problem; True otherwise
        """
        logger.info("CMD: FlashEraseAllUnsecure")
        cmd_packet = CmdPacket(CommandTag.FLASH_ERASE_ALL_UNSECURE, CommandFlag.NONE.tag)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def efuse_read_once(self, index: int) -> Optional[int]:
        """Read from MCU flash program once region.

        :param index: Start index
        :return: read value (32-bit int); None if operation failed
        """
        logger.info(f"CMD: FlashReadOnce(index={index})")
        cmd_packet = CmdPacket(CommandTag.FLASH_READ_ONCE, CommandFlag.NONE.tag, index, 4)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, FlashReadOnceResponse)
            return cmd_response.values[0]
        return None

    def efuse_program_once(self, index: int, value: int, verify: bool = False) -> bool:
        """Write into MCU once program region (OCOTP).

        :param index: Start index
        :param value: Int value (4 bytes long)
        :param verify: Verify that data were written (by comparing value as bitmask)
        :return: False in case of any problem; True otherwise
        """
        logger.info(
            f"CMD: FlashProgramOnce(index={index}, value=0x{value:X}) "
            f"with{'' if verify else 'out'} verification."
        )
        cmd_packet = CmdPacket(CommandTag.FLASH_PROGRAM_ONCE, CommandFlag.NONE.tag, index, 4, value)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status != StatusCode.SUCCESS:
            return False
        if verify:
            read_value = self.efuse_read_once(index=index & ((1 << 24) - 1))
            if read_value is None:
                return False
            # We check only a bitmask, because OTP allows to burn individual bits separately
            # Some other bits may have been already written
            if read_value & value == value:
                return True
            # It may happen that ROM will not report error when attempting to write into locked OTP
            # In such case we substitute the original SUCCESS code with custom-made OTP_VERIFY_FAIL
            self._status_code = StatusCode.OTP_VERIFY_FAIL.tag
            return False
        return cmd_response.status == StatusCode.SUCCESS

    def flash_read_once(self, index: int, count: int = 4) -> Optional[bytes]:
        """Read from MCU flash program once region (max 8 bytes).

        :param index: Start index
        :param count: Count of bytes
        :return: Data read; None in case of an failure
        :raises SPSDKError: When invalid count of bytes. Must be 4 or 8
        """
        if count not in (4, 8):
            raise SPSDKError("Invalid count of bytes. Must be 4 or 8")
        logger.info(f"CMD: FlashReadOnce(index={index}, bytes={count})")
        cmd_packet = CmdPacket(CommandTag.FLASH_READ_ONCE, CommandFlag.NONE.tag, index, count)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, FlashReadOnceResponse)
            return cmd_response.data
        return None

    def flash_program_once(self, index: int, data: bytes) -> bool:
        """Write into MCU flash program once region (max 8 bytes).

        :param index: Start index
        :param data: Input data aligned to 4 or 8 bytes
        :return: False in case of any problem; True otherwise
        :raises SPSDKError: When invalid length of data. Must be aligned to 4 or 8 bytes
        """
        if len(data) not in (4, 8):
            raise SPSDKError("Invalid length of data. Must be aligned to 4 or 8 bytes")
        logger.info(f"CMD: FlashProgramOnce(index={index!r}, data={data!r})")
        cmd_packet = CmdPacket(
            CommandTag.FLASH_PROGRAM_ONCE, CommandFlag.NONE.tag, index, len(data), data=data
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def flash_read_resource(self, address: int, length: int, option: int = 1) -> Optional[bytes]:
        """Read resource of flash module.

        :param address: Start address
        :param length: Number of bytes
        :param option: Area to be read. 0 means Flash IFR, 1 means Flash Firmware ID
        :raises McuBootError: when the length is not aligned to 4 bytes
        :return: Data from the resource; None in case of an failure
        """
        if length % 4:
            raise McuBootError("The number of bytes to read is not aligned to the 4 bytes")
        logger.info(
            f"CMD: FlashReadResource(address=0x{address:08X}, length={length}, option={option})"
        )
        cmd_packet = CmdPacket(
            CommandTag.FLASH_READ_RESOURCE, CommandFlag.NONE.tag, address, length, option
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, FlashReadResourceResponse)
            return self._read_data(CommandTag.FLASH_READ_RESOURCE, cmd_response.length)
        return None

    def configure_memory(self, address: int, mem_id: int) -> bool:
        """Configure memory.

        :param address: The address in memory where are locating configuration data
        :param mem_id: Memory ID
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: ConfigureMemory({mem_id}, address=0x{address:08X})")
        cmd_packet = CmdPacket(CommandTag.CONFIGURE_MEMORY, CommandFlag.NONE.tag, mem_id, address)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def reliable_update(self, address: int) -> bool:
        """Reliable Update.

        :param address: Address where new the firmware is stored
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: ReliableUpdate(address=0x{address:08X})")
        cmd_packet = CmdPacket(CommandTag.RELIABLE_UPDATE, CommandFlag.NONE.tag, address)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def generate_key_blob(
        self,
        dek_data: bytes,
        key_sel: int = GenerateKeyBlobSelect.OPTMK.tag,
        count: int = 72,
    ) -> Optional[bytes]:
        """Generate Key Blob.

        :param dek_data: Data Encryption Key as bytes
        :param key_sel: select the BKEK used to wrap the BK (default: OPTMK/FUSES)
        :param count: Key blob count (default: 72 - AES128bit)
        :return: Key blob; None in case of an failure
        """
        logger.info(
            f"CMD: GenerateKeyBlob(dek_len={len(dek_data)}, key_sel={key_sel}, count={count})"
        )
        data_chunks = self._split_data(data=dek_data)
        cmd_response = self._process_cmd(
            CmdPacket(
                CommandTag.GENERATE_KEY_BLOB,
                CommandFlag.HAS_DATA_PHASE.tag,
                key_sel,
                len(dek_data),
                0,
            )
        )
        if cmd_response.status != StatusCode.SUCCESS:
            return None
        if not self._send_data(CommandTag.GENERATE_KEY_BLOB, data_chunks):
            return None
        cmd_response = self._process_cmd(
            CmdPacket(CommandTag.GENERATE_KEY_BLOB, CommandFlag.NONE.tag, key_sel, count, 1)
        )
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, ReadMemoryResponse)
            return self._read_data(CommandTag.GENERATE_KEY_BLOB, cmd_response.length)
        return None

    def kp_enroll(self) -> bool:
        """Key provisioning: Enroll Command (start PUF).

        :return: False in case of any problem; True otherwise
        """
        logger.info("CMD: [KeyProvisioning] Enroll")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING, CommandFlag.NONE.tag, KeyProvOperation.ENROLL.tag
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def kp_set_intrinsic_key(self, key_type: int, key_size: int) -> bool:
        """Key provisioning: Generate Intrinsic Key.

        :param key_type: Type of the key
        :param key_size: Size of the key
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: [KeyProvisioning] SetIntrinsicKey(type={key_type}, key_size={key_size})")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.NONE.tag,
            KeyProvOperation.SET_INTRINSIC_KEY.tag,
            key_type,
            key_size,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def kp_write_nonvolatile(self, mem_id: int = 0) -> bool:
        """Key provisioning: Write the key to a nonvolatile memory.

        :param mem_id: The memory ID (default: 0)
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: [KeyProvisioning] WriteNonVolatileMemory(mem_id={mem_id})")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.NONE.tag,
            KeyProvOperation.WRITE_NON_VOLATILE.tag,
            mem_id,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def kp_read_nonvolatile(self, mem_id: int = 0) -> bool:
        """Key provisioning: Load the key from a nonvolatile memory to bootloader.

        :param mem_id: The memory ID (default: 0)
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: [KeyProvisioning] ReadNonVolatileMemory(mem_id={mem_id})")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.NONE.tag,
            KeyProvOperation.READ_NON_VOLATILE.tag,
            mem_id,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def kp_set_user_key(self, key_type: int, key_data: bytes) -> bool:
        """Key provisioning: Send the user key specified by <key_type> to bootloader.

        :param key_type: type of the user key, see enumeration for details
        :param key_data: binary content of the user key
        :return: False in case of any problem; True otherwise
        """
        logger.info(
            f"CMD: [KeyProvisioning] SetUserKey(key_type={key_type}, " f"key_len={len(key_data)})"
        )
        data_chunks = self._split_data(data=key_data)
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.HAS_DATA_PHASE.tag,
            KeyProvOperation.SET_USER_KEY.tag,
            key_type,
            len(key_data),
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            return self._send_data(CommandTag.KEY_PROVISIONING, data_chunks)
        return False

    def kp_write_key_store(self, key_data: bytes) -> bool:
        """Key provisioning: Write key data into key store area.

        :param key_data: key store binary content to be written to processor
        :return: result of the operation; True means success
        """
        logger.info(f"CMD: [KeyProvisioning] WriteKeyStore(key_len={len(key_data)})")
        data_chunks = self._split_data(data=key_data)
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.HAS_DATA_PHASE.tag,
            KeyProvOperation.WRITE_KEY_STORE.tag,
            0,
            len(key_data),
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            return self._send_data(CommandTag.KEY_PROVISIONING, data_chunks)
        return False

    def kp_read_key_store(self) -> Optional[bytes]:
        """Key provisioning: Read key data from key store area."""
        logger.info("CMD: [KeyProvisioning] ReadKeyStore")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING, CommandFlag.NONE.tag, KeyProvOperation.READ_KEY_STORE.tag
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, KeyProvisioningResponse)
            return self._read_data(CommandTag.KEY_PROVISIONING, cmd_response.length)
        return None

    def load_image(
        self, data: bytes, progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> bool:
        """Load a boot image to the device.

        :param data: boot image
        :param progress_callback: Callback for updating the caller about the progress
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: LoadImage(length={len(data)})")
        data_chunks = self._split_data(data)
        # there's no command in this case
        self._status_code = StatusCode.SUCCESS.tag
        return self._send_data(CommandTag.NO_COMMAND, data_chunks, progress_callback)

    def tp_prove_genuinity(self, address: int, buffer_size: int) -> Optional[int]:
        """Start the process of proving genuinity.

        :param address: Address where to prove genuinity request (challenge) container
        :param buffer_size: Maximum size of the response package (limit 0xFFFF)
        :raises McuBootError: Invalid input parameters
        :return: True if prove_genuinity operation is successfully completed
        """
        logger.info(
            f"CMD: [TrustProvisioning] ProveGenuinity(address={hex(address)}, "
            f"buffer_size={buffer_size})"
        )
        if buffer_size > 0xFFFF:
            raise McuBootError("buffer_size must be less than 0xFFFF")
        address_msb = (address >> 32) & 0xFFFF_FFFF
        address_lsb = address & 0xFFFF_FFFF
        sentinel_cmd = _tp_sentinel_frame(
            TrustProvOperation.PROVE_GENUINITY.tag, args=[address_msb, address_lsb, buffer_size]
        )
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING, CommandFlag.NONE.tag, data=sentinel_cmd
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, TrustProvisioningResponse)
            return cmd_response.values[0]
        return None

    def tp_set_wrapped_data(self, address: int, stage: int = 0x4B, control: int = 1) -> bool:
        """Start the process of setting OEM data.

        :param address: Address where the wrapped data container on target
        :param control: 1 - use the address, 2 - use container within the firmware, defaults to 1
        :param stage: Stage of TrustProvisioning flow, defaults to 0x4B
        :return: True if set_wrapped_data operation is successfully completed
        """
        logger.info(f"CMD: [TrustProvisioning] SetWrappedData(address={hex(address)})")
        if address == 0:
            control = 2

        address_msb = (address >> 32) & 0xFFFF_FFFF
        address_lsb = address & 0xFFFF_FFFF
        stage_control = control << 8 | stage
        sentinel_cmd = _tp_sentinel_frame(
            TrustProvOperation.ISP_SET_WRAPPED_DATA.tag,
            args=[stage_control, address_msb, address_lsb],
        )
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING, CommandFlag.NONE.tag, data=sentinel_cmd
        )
        cmd_response = self._process_cmd(cmd_packet)
        return cmd_response.status == StatusCode.SUCCESS

    def fuse_program(self, address: int, data: bytes, mem_id: int = 0) -> bool:
        """Program fuse.

        :param address: Start address
        :param data: List of bytes
        :param mem_id: Memory ID
        :return: False in case of any problem; True otherwise
        """
        logger.info(
            f"CMD: FuseProgram(address=0x{address:08X}, length={len(data)}, mem_id={mem_id})"
        )
        data_chunks = self._split_data(data=data)
        mem_id = _clamp_down_memory_id(memory_id=mem_id)
        cmd_packet = CmdPacket(
            CommandTag.FUSE_PROGRAM, CommandFlag.HAS_DATA_PHASE.tag, address, len(data), mem_id
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:  # pragma: no cover
            # command is not supported in any device, thus we can't measure coverage
            return self._send_data(CommandTag.FUSE_PROGRAM, data_chunks)
        return False

    def fuse_read(self, address: int, length: int, mem_id: int = 0) -> Optional[bytes]:
        """Read fuse.

        :param address: Start address
        :param length: Count of bytes
        :param mem_id: Memory ID
        :return: Data read from the fuse; None in case of a failure
        """
        logger.info(f"CMD: ReadFuse(address=0x{address:08X}, length={length}, mem_id={mem_id})")
        mem_id = _clamp_down_memory_id(memory_id=mem_id)
        cmd_packet = CmdPacket(CommandTag.FUSE_READ, CommandFlag.NONE.tag, address, length, mem_id)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:  # pragma: no cover
            # command is not supported in any device, thus we can't measure coverage
            assert isinstance(cmd_response, ReadMemoryResponse)
            return self._read_data(CommandTag.FUSE_READ, cmd_response.length)
        return None

    def update_life_cycle(self, life_cycle: int) -> bool:
        """Update device life cycle.

        :param life_cycle: New life cycle value.
        :return: False in case of any problems, True otherwise.
        """
        logger.info(f"CMD: UpdateLifeCycle (life cycle=0x{life_cycle:02X})")
        cmd_packet = CmdPacket(CommandTag.UPDATE_LIFE_CYCLE, CommandFlag.NONE.tag, life_cycle)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def ele_message(
        self, cmdMsgAddr: int, cmdMsgCnt: int, respMsgAddr: int, respMsgCnt: int
    ) -> bool:
        """Send EdgeLock Enclave message.

        :param cmdMsgAddr: Address in RAM where is prepared the command message words
        :param cmdMsgCnt: Count of 32bits command words
        :param respMsgAddr: Address in RAM where the command store the response
        :param respMsgCnt: Count of 32bits response words

        :return: False in case of any problems, True otherwise.
        """
        logger.info(
            f"CMD: EleMessage Command (cmdMsgAddr=0x{cmdMsgAddr:08X}, cmdMsgCnt={cmdMsgCnt})"
        )
        if respMsgCnt:
            logger.info(
                f"CMD: EleMessage Response (respMsgAddr=0x{respMsgAddr:08X}, respMsgCnt={respMsgCnt})"
            )
        cmd_packet = CmdPacket(
            CommandTag.ELE_MESSAGE,
            CommandFlag.NONE.tag,
            0,  # reserved for future use as a sub command ID or anything else
            cmdMsgAddr,
            cmdMsgCnt,
            respMsgAddr,
            respMsgCnt,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def tp_hsm_gen_key(
        self,
        key_type: int,
        reserved: int,
        key_blob_output_addr: int,
        key_blob_output_size: int,
        ecdsa_puk_output_addr: int,
        ecdsa_puk_output_size: int,
    ) -> Optional[List[int]]:
        """Trust provisioning: OEM generate common keys.

        :param key_type: Key to generate (MFW_ISK, MFW_ENCK, GEN_SIGNK, GET_CUST_MK_SK)
        :param reserved: Reserved, must be zero
        :param key_blob_output_addr: The output buffer address where ROM writes the key blob to
        :param key_blob_output_size: The output buffer size in byte
        :param ecdsa_puk_output_addr: The output buffer address where ROM writes the public key to
        :param ecdsa_puk_output_size: The output buffer size in byte
        :return: Return byte count of the key blob + byte count of the public key from the device;
            None in case of an failure
        """
        logger.info("CMD: [TrustProvisioning] OEM generate common keys")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.HSM_GEN_KEY.tag,
            key_type,
            reserved,
            key_blob_output_addr,
            key_blob_output_size,
            ecdsa_puk_output_addr,
            ecdsa_puk_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values
        return None

    def tp_oem_gen_master_share(
        self,
        oem_share_input_addr: int,
        oem_share_input_size: int,
        oem_enc_share_output_addr: int,
        oem_enc_share_output_size: int,
        oem_enc_master_share_output_addr: int,
        oem_enc_master_share_output_size: int,
        oem_cust_cert_puk_output_addr: int,
        oem_cust_cert_puk_output_size: int,
    ) -> Optional[List[int]]:
        """Takes the entropy seed provided by the OEM as input.

        :param oem_share_input_addr: The input buffer address
            where the OEM Share(entropy seed) locates at
        :param oem_share_input_size: The byte count of the OEM Share
        :param oem_enc_share_output_addr: The output buffer address
            where ROM writes the Encrypted OEM Share to
        :param oem_enc_share_output_size: The output buffer size in byte
        :param oem_enc_master_share_output_addr: The output buffer address
            where ROM writes the Encrypted OEM Master Share to
        :param oem_enc_master_share_output_size: The output buffer size in byte.
        :param oem_cust_cert_puk_output_addr: The output buffer address where
            ROM writes the OEM Customer Certificate Public Key to
        :param oem_cust_cert_puk_output_size: The output buffer size in byte
        :return: Sizes of two encrypted blobs(the Encrypted OEM Share and the Encrypted OEM Master Share)
            and a public key(the OEM Customer Certificate Public Key).
        """
        logger.info("CMD: [TrustProvisioning] OEM generate master share")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.OEM_GEN_MASTER_SHARE.tag,
            oem_share_input_addr,
            oem_share_input_size,
            oem_enc_share_output_addr,
            oem_enc_share_output_size,
            oem_enc_master_share_output_addr,
            oem_enc_master_share_output_size,
            oem_cust_cert_puk_output_addr,
            oem_cust_cert_puk_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values
        return None

    def tp_oem_set_master_share(
        self,
        oem_share_input_addr: int,
        oem_share_input_size: int,
        oem_enc_master_share_input_addr: int,
        oem_enc_master_share_input_size: int,
    ) -> bool:
        """Takes the entropy seed and the Encrypted OEM Master Share.

        :param oem_share_input_addr: The input buffer address
            where the OEM Share(entropy seed) locates at
        :param oem_share_input_size: The byte count of the OEM Share
        :param oem_enc_master_share_input_addr: The input buffer address
            where the Encrypted OEM Master Share locates at
        :param oem_enc_master_share_input_size: The byte count of the Encrypted OEM Master Share
        :return: False in case of any problem; True otherwise
        """
        logger.info(
            "CMD: [TrustProvisioning] Takes the entropy seed and the Encrypted OEM Master Share."
        )
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.OEM_SET_MASTER_SHARE.tag,
            oem_share_input_addr,
            oem_share_input_size,
            oem_enc_master_share_input_addr,
            oem_enc_master_share_input_size,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def tp_oem_get_cust_cert_dice_puk(
        self,
        oem_rkth_input_addr: int,
        oem_rkth_input_size: int,
        oem_cust_cert_dice_puk_output_addr: int,
        oem_cust_cert_dice_puk_output_size: int,
    ) -> Optional[int]:
        """Creates the initial trust provisioning keys.

        :param oem_rkth_input_addr: The input buffer address where the OEM RKTH locates at
        :param oem_rkth_input_size: The byte count of the OEM RKTH
        :param oem_cust_cert_dice_puk_output_addr: The output buffer address where ROM writes the OEM Customer
            Certificate Public Key for DICE to
        :param oem_cust_cert_dice_puk_output_size: The output buffer size in byte
        :return: The byte count of the OEM Customer Certificate Public Key for DICE
        """
        logger.info("CMD: [TrustProvisioning] Creates the initial trust provisioning keys")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.OEM_GET_CUST_CERT_DICE_PUK.tag,
            oem_rkth_input_addr,
            oem_rkth_input_size,
            oem_cust_cert_dice_puk_output_addr,
            oem_cust_cert_dice_puk_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def tp_hsm_store_key(
        self,
        key_type: int,
        key_property: int,
        key_input_addr: int,
        key_input_size: int,
        key_blob_output_addr: int,
        key_blob_output_size: int,
    ) -> Optional[List[int]]:
        """Trust provisioning: OEM generate common keys.

        :param key_type: Key to generate (CKDFK, HKDFK, HMACK, CMACK, AESK, KUOK)
        :param key_property: Bit 0: Key Size, 0 for 128bit, 1 for 256bit.
            Bits 30-31: set key protection CSS mode.
        :param key_input_addr: The input buffer address where the key locates at
        :param key_input_size: The byte count of the key
        :param key_blob_output_addr: The output buffer address where ROM writes the key blob to
        :param key_blob_output_size: The output buffer size in byte
        :return: Return header of the key blob + byte count of the key blob
            (header is not included) from the device; None in case of an failure
        """
        logger.info("CMD: [TrustProvisioning] OEM generate common keys")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.HSM_STORE_KEY.tag,
            key_type,
            key_property,
            key_input_addr,
            key_input_size,
            key_blob_output_addr,
            key_blob_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values
        return None

    def tp_hsm_enc_blk(
        self,
        mfg_cust_mk_sk_0_blob_input_addr: int,
        mfg_cust_mk_sk_0_blob_input_size: int,
        kek_id: int,
        sb3_header_input_addr: int,
        sb3_header_input_size: int,
        block_num: int,
        block_data_addr: int,
        block_data_size: int,
    ) -> bool:
        """Trust provisioning: Encrypt the given SB3 data block.

        :param mfg_cust_mk_sk_0_blob_input_addr: The input buffer address
            where the CKDF Master Key Blob locates at
        :param mfg_cust_mk_sk_0_blob_input_size: The byte count of the CKDF Master Key Blob
        :param kek_id: The CKDF Master Key Encryption Key ID
            (0x10: NXP_CUST_KEK_INT_SK, 0x11: NXP_CUST_KEK_EXT_SK)
        :param sb3_header_input_addr: The input buffer address,
            where the SB3 Header(block0) locates at
        :param sb3_header_input_size: The byte count of the SB3 Header
        :param block_num: The index of the block. Due to SB3 Header(block 0) is always unencrypted,
            the index starts from block1
        :param block_data_addr: The buffer address where the SB3 data block locates at
        :param block_data_size: The byte count of the SB3 data block
        :return: False in case of any problem; True otherwise
        """
        logger.info("CMD: [TrustProvisioning] Encrypt the given SB3 data block")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.HSM_ENC_BLOCK.tag,
            mfg_cust_mk_sk_0_blob_input_addr,
            mfg_cust_mk_sk_0_blob_input_size,
            kek_id,
            sb3_header_input_addr,
            sb3_header_input_size,
            block_num,
            block_data_addr,
            block_data_size,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def tp_hsm_enc_sign(
        self,
        key_blob_input_addr: int,
        key_blob_input_size: int,
        block_data_input_addr: int,
        block_data_input_size: int,
        signature_output_addr: int,
        signature_output_size: int,
    ) -> Optional[int]:
        """Signs the given data.

        :param key_blob_input_addr: The input buffer address where signing key blob locates at
        :param key_blob_input_size: The byte count of the signing key blob
        :param block_data_input_addr: The input buffer address where the data locates at
        :param block_data_input_size: The byte count of the data
        :param signature_output_addr: The output buffer address where ROM writes the signature to
        :param signature_output_size: The output buffer size in byte
        :return: Return signature size; None in case of an failure
        """
        logger.info("CMD: [TrustProvisioning] HSM ENC SIGN")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.HSM_ENC_SIGN.tag,
            key_blob_input_addr,
            key_blob_input_size,
            block_data_input_addr,
            block_data_input_size,
            signature_output_addr,
            signature_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def wpc_get_id(
        self,
        wpc_id_blob_addr: int,
        wpc_id_blob_size: int,
    ) -> Optional[int]:
        """Command used for harvesting device ID blob.

        :param wpc_id_blob_addr: Buffer address
        :param wpc_id_blob_size: Buffer size
        """
        logger.info("CMD: [TrustProvisioning] WPC GET ID")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvWpc.WPC_GET_ID.tag,
            wpc_id_blob_addr,
            wpc_id_blob_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def nxp_get_id(
        self,
        id_blob_addr: int,
        id_blob_size: int,
    ) -> Optional[int]:
        """Command used for harvesting device ID blob during wafer test as part of RTS flow.

        :param id_blob_addr: address of ID blob defined by Round-trip trust provisioning specification.
        :param id_blob_size: length of buffer in bytes
        """
        logger.info("CMD: [TrustProvisioning] NXP GET ID")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvWpc.NXP_GET_ID.tag,
            id_blob_addr,
            id_blob_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def wpc_insert_cert(
        self,
        wpc_cert_addr: int,
        wpc_cert_len: int,
        ec_id_offset: int,
        wpc_puk_offset: int,
    ) -> Optional[int]:
        """Command used for certificate validation before it is written into flash.

        This command does following things:
            Extracts ECID and WPC PUK from certificate
            Validates ECID and WPC PUK. If both are OK it returns success. Otherwise returns fail

        :param wpc_cert_addr: address of inserted certificate
        :param wpc_cert_len: length in bytes of inserted certificate
        :param ec_id_offset: offset to 72-bit ECID
        :param wpc_puk_offset: WPC PUK offset from beginning of inserted certificate
        """
        logger.info("CMD: [TrustProvisioning] WPC INSERT CERT")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvWpc.WPC_INSERT_CERT.tag,
            wpc_cert_addr,
            wpc_cert_len,
            ec_id_offset,
            wpc_puk_offset,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            return 0
        return None

    def wpc_sign_csr(
        self,
        csr_tbs_addr: int,
        csr_tbs_len: int,
        signature_addr: int,
        signature_len: int,
    ) -> Optional[int]:
        """Command used sign CSR data (TBS portion).

        :param csr_tbs_addr: address of CSR-TBS data
        :param csr_tbs_len: length in bytes of CSR-TBS data
        :param signature_addr: address where to store signature
        :param signature_len: expected length of signature
        :return: actual signature length
        """
        logger.info("CMD: [TrustProvisioning] WPC SIGN CSR-TBS DATA")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvWpc.WPC_SIGN_CSR.tag,
            csr_tbs_addr,
            csr_tbs_len,
            signature_addr,
            signature_len,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def dsc_hsm_create_session(
        self,
        oem_seed_input_addr: int,
        oem_seed_input_size: int,
        oem_share_output_addr: int,
        oem_share_output_size: int,
    ) -> Optional[int]:
        """Command used by OEM to provide it share to create the initial trust provisioning keys.

        :param oem_seed_input_addr: address of 128-bit entropy seed value provided by the OEM.
        :param oem_seed_input_size: OEM seed size in bytes
        :param oem_share_output_addr: A 128-bit encrypted token.
        :param oem_share_output_size: size in bytes
        """
        logger.info("CMD: [TrustProvisioning] DSC HSM CREATE SESSION")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvDevHsmDsc.DSC_HSM_CREATE_SESSION.tag,
            oem_seed_input_addr,
            oem_seed_input_size,
            oem_share_output_addr,
            oem_share_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def dsc_hsm_enc_blk(
        self,
        sbx_header_input_addr: int,
        sbx_header_input_size: int,
        block_num: int,
        block_data_addr: int,
        block_data_size: int,
    ) -> Optional[int]:
        """Command used to encrypt the given block sliced by the nxpimage.

        This command is only supported after issuance of dsc_hsm_create_session.

        :param sbx_header_input_addr: SBx header containing file size, Firmware version and Timestamp data.
            Except for hash digest of block 0, all other fields should be valid.
        :param sbx_header_input_size: size of the header in bytes
        :param block_num: Number of block
        :param block_data_addr: Address of data block
        :param block_data_size: Size of data block
        """
        logger.info("CMD: [TrustProvisioning] DSC HSM ENC BLK")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvDevHsmDsc.DSC_HSM_ENC_BLK.tag,
            sbx_header_input_addr,
            sbx_header_input_size,
            block_num,
            block_data_addr,
            block_data_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def dsc_hsm_enc_sign(
        self,
        block_data_input_addr: int,
        block_data_input_size: int,
        signature_output_addr: int,
        signature_output_size: int,
    ) -> Optional[int]:
        """Command used for signing the data buffer provided.

        This command is only supported after issuance of dsc_hsm_create_session.

        :param block_data_input_addr: Address of data buffer to be signed
        :param block_data_input_size: Size of data buffer in bytes
        :param signature_output_addr: Address to output signature data
        :param signature_output_size: Size of the output signature data in bytes
        """
        logger.info("CMD: [TrustProvisioning] DSC HSM ENC SIGN")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvDevHsmDsc.DSC_HSM_ENC_SIGN.tag,
            block_data_input_addr,
            block_data_input_size,
            signature_output_addr,
            signature_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None


####################
# Helper functions #
####################


def _tp_sentinel_frame(command: int, args: List[int], tag: int = 0x17, version: int = 0) -> bytes:
    """Prepare frame used by sentinel."""
    data = struct.pack("<4B", command, len(args), version, tag)
    for item in args:
        data += struct.pack("<I", item)
    return data


def _clamp_down_memory_id(memory_id: int) -> int:
    if memory_id > 255 or memory_id == 0:
        return memory_id
    logger.warning("Note: memoryId is not required when accessing mapped external memory")
    return 0
