#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""EdgeLock Enclave Message handler."""

import logging
import re
from abc import abstractmethod
from types import TracebackType
from typing import List, Optional, Tuple, Type, Union

from spsdk.ele.ele_constants import ResponseStatus
from spsdk.ele.ele_message import EleMessage
from spsdk.exceptions import SPSDKError, SPSDKLengthError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.uboot.uboot import Uboot
from spsdk.utils.database import DatabaseManager, get_db, get_families
from spsdk.utils.misc import value_to_bytes

logger = logging.getLogger(__name__)


class EleMessageHandler:
    """Base class for ELE message handling."""

    def __init__(
        self, device: Union[McuBoot, Uboot], family: str, revision: str = "latest"
    ) -> None:
        """Class object initialized.

        :param device: Communication interface.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        """
        self.device = device
        self.database = get_db(device=family, revision=revision)
        self.family = family
        self.revision = revision
        self.comm_buff_addr = self.database.get_int(DatabaseManager.COMM_BUFFER, "address")
        self.comm_buff_size = self.database.get_int(DatabaseManager.COMM_BUFFER, "size")
        logger.info(
            f"ELE communicator is using {self.comm_buff_size} B size buffer at "
            f"{self.comm_buff_addr:08X} address in {family} target."
        )

    @staticmethod
    def get_supported_families() -> List[str]:
        """Get list of supported target families.

        :return: List of supported families.
        """
        return get_families(DatabaseManager.ELE)

    @staticmethod
    def get_ele_device(device: str) -> str:
        """Get default ELE device from DB."""
        return get_db(device, "latest").get_str(DatabaseManager.ELE, "ele_device")

    @abstractmethod
    def send_message(self, msg: EleMessage) -> None:
        """Send message and receive response.

        :param msg: EdgeLock Enclave message
        """

    def __enter__(self) -> None:
        """Enter function of ELE handler."""
        if not self.device.is_opened:
            self.device.open()

    def __exit__(
        self,
        exception_type: Optional[Type[BaseException]] = None,
        exception_value: Optional[BaseException] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        """Close function of ELE handler."""
        if self.device.is_opened:
            self.device.close()


class EleMessageHandlerMBoot(EleMessageHandler):
    """EdgeLock Enclave Message Handler over MCUBoot.

    This class can send the ELE message into target over mBoot and decode the response.
    """

    def __init__(self, device: McuBoot, family: str, revision: str = "latest") -> None:
        """Class object initialized.

        :param device: mBoot device.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        """
        if not isinstance(device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        super().__init__(device, family, revision)

    def send_message(self, msg: EleMessage) -> None:
        """Send message and receive response.

        :param msg: EdgeLock Enclave message
        :raises SPSDKError: Invalid response status detected.
        :raises SPSDKLengthError: Invalid read back length detected.
        """
        if not isinstance(self.device, McuBoot):
            raise SPSDKError("Wrong instance of device, must be MCUBoot")
        msg.set_buffer_params(self.comm_buff_addr, self.comm_buff_size)
        try:
            # 1. Prepare command in target memory
            self.device.write_memory(msg.command_address, msg.export())

            # 1.1. Prepare command data in target memory if required
            if msg.has_command_data:
                self.device.write_memory(msg.command_data_address, msg.command_data)

            # 2. Execute ELE message on target
            self.device.ele_message(
                msg.command_address,
                msg.command_words_count,
                msg.response_address,
                msg.response_words_count,
            )
            if msg.response_words_count == 0:
                return
            # 3. Read back the response
            response = self.device.read_memory(msg.response_address, 4 * msg.response_words_count)
        except SPSDKError as exc:
            raise SPSDKError(f"ELE Communication failed with mBoot: {str(exc)}") from exc

        if not response or len(response) != 4 * msg.response_words_count:
            raise SPSDKLengthError("ELE Message - Invalid response read-back operation.")
        # 4. Decode the response
        msg.decode_response(response)

        # 4.1 Check the response status
        if msg.status != ResponseStatus.ELE_SUCCESS_IND:
            raise SPSDKError(f"ELE Message failed. \n{msg.info()}")

        # 4.2 Read back the response data from target memory if required
        if msg.has_response_data:
            try:
                response_data = self.device.read_memory(
                    msg.response_data_address, msg.response_data_size
                )
            except SPSDKError as exc:
                raise SPSDKError(f"ELE Communication failed with mBoot: {str(exc)}") from exc

            if not response_data or len(response_data) != msg.response_data_size:
                raise SPSDKLengthError("ELE Message - Invalid response data read-back operation.")

            msg.decode_response_data(response_data)

        logger.info(f"Sent message information:\n{msg.info()}")


class EleMessageHandlerUBoot(EleMessageHandler):
    """EdgeLock Enclave Message Handler over UBoot.

    This class can send the ELE message into target over UBoot and decode the response.
    """

    def __init__(self, device: Uboot, family: str, revision: str = "latest") -> None:
        """Class object initialized.

        :param device: UBoot device.
        :param family: Target family name.
        :param revision: Target revision, default is use 'latest' revision.
        """
        if not isinstance(device, Uboot):
            raise SPSDKError("Wrong instance of device, must be UBoot")
        super().__init__(device, family, revision)

    def extract_error_values(self, error_message: str) -> Tuple[int, int, int]:
        """Extract error values from error_mesage.

        :param error_message: Error message containing ret and response
        :return: abort_code, status and indication
        """
        # Define regular expressions to extract values
        ret_pattern = re.compile(r"ret (0x[0-9a-fA-F]+),")
        response_pattern = re.compile(r"response (0x[0-9a-fA-F]+)")

        # Find matches in the error message
        ret_match = ret_pattern.search(error_message)
        response_match = response_pattern.search(error_message)

        if not ret_match or not response_match:
            logger.error(f"Cannot decode error message from ELE!\n{error_message}")
            abort_code = 0
            status = 0
            indication = 0
        else:
            abort_code = int(ret_match.group(1), 16)
            status_all = int(response_match.group(1), 16)
            indication = status_all >> 8
            status = status_all & 0xFF
        return abort_code, status, indication

    def send_message(self, msg: EleMessage) -> None:
        """Send message and receive response.

        :param msg: EdgeLock Enclave message
        :raises SPSDKError: Invalid response status detected.
        :raises SPSDKLengthError: Invalid read back length detected.
        """
        if not isinstance(self.device, Uboot):
            raise SPSDKError("Wrong instance of device, must be UBoot")
        msg.set_buffer_params(self.comm_buff_addr, self.comm_buff_size)

        try:
            logger.debug(f"ELE msg {hex(msg.buff_addr)} {hex(msg.buff_size)} {msg.export().hex()}")

            # 0. Prepare command data in target memory if required
            if msg.has_command_data:
                self.device.write_memory(msg.command_data_address, msg.command_data)

            # 1. Execute ELE message on target
            self.device.write(
                f"ele_message {hex(msg.buff_addr)} {hex(msg.buff_size)} {msg.export().hex()}"
            )
            output = self.device.read_output()
            logger.debug(f"Raw ELE message output:\n{output}")

            if msg.response_words_count == 0:
                return

            if "Error" in output:
                msg.abort_code, msg.status, msg.indication = self.extract_error_values(output)
            else:
                # 2. Read back the response
                stripped_output = output.splitlines()[-1].replace("u-boot=> ", "")
                logger.debug(f"Stripped output {stripped_output}")
                response = value_to_bytes("0x" + stripped_output)
        except (SPSDKError, IndexError) as exc:
            raise SPSDKError(f"ELE Communication failed with UBoot: {str(exc)}") from exc

        if not "Error" in output:
            if not response or len(response) != 4 * msg.response_words_count:
                raise SPSDKLengthError("ELE Message - Invalid response read-back operation.")
            # 3. Decode the response
            msg.decode_response(response)

        # 3.1 Check the response status
        if msg.status != ResponseStatus.ELE_SUCCESS_IND:
            raise SPSDKError(f"ELE Message failed. \n{msg.info()}")

        # 3.2 Read back the response data from target memory if required
        if msg.has_response_data:
            try:
                response_data = self.device.read_memory(
                    msg.response_data_address, msg.response_data_size
                )
                self.device.read_output()
            except SPSDKError as exc:
                raise SPSDKError(f"ELE Communication failed with mBoot: {str(exc)}") from exc

            if not response_data or len(response_data) != msg.response_data_size:
                raise SPSDKLengthError("ELE Message - Invalid response data read-back operation.")

            msg.decode_response_data(response_data)

        logger.info(f"Sent message information:\n{msg.info()}")
