#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of raw AHAB container support.

This module represents a generic AHAB container implementation. You can set the
containers values at will. From this perspective, consult with your reference
manual of your device for allowed values.
"""
import datetime
import logging
from abc import abstractmethod
from inspect import isclass
from struct import calcsize, pack, unpack
from typing import Any, Dict, List, Optional, Tuple, Type

from typing_extensions import Self

from ...exceptions import SPSDKError, SPSDKValueError
from ...image.ahab.ahab_abstract_interfaces import LITTLE_ENDIAN, Container
from ...image.ahab.ahab_container import (
    CONTAINER_ALIGNMENT,
    RESERVED,
    UINT8,
    UINT16,
    UINT32,
    AHABContainerBase,
    AHABImage,
    SignatureBlock,
)
from ...utils.database import DatabaseManager
from ...utils.images import BinaryImage
from ...utils.misc import Endianness, align_block, check_range, load_hex_string, value_to_int
from ...utils.schema_validator import CommentedConfig
from ...utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class SignedMessageTags(SpsdkEnum):
    """Signed message container related tags."""

    SIGNED_MSG = (0x89, "SIGNED_MSG", "Signed message.")


class MessageCommands(SpsdkEnum):
    """Signed messages commands."""

    KEYSTORE_REPROVISIONING_ENABLE_REQ = (
        0x3F,
        "KEYSTORE_REPROVISIONING_ENABLE_REQ",
        "Key store reprovisioning enable",
    )

    KEY_EXCHANGE_REQ = (
        0x47,
        "KEY_EXCHANGE_REQ",
        "Key exchange signed message content",
    )

    RETURN_LIFECYCLE_UPDATE_REQ = (
        0xA0,
        "RETURN_LIFECYCLE_UPDATE_REQ",
        "Return lifecycle update request.",
    )
    WRITE_SEC_FUSE_REQ = (0x91, "WRITE_SEC_FUSE_REQ", "Write secure fuse request.")


class Message(Container):
    """Class representing the Signed message.

    Message::
        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |                      Message header                           |
        +-----+---------------------------------------------------------------+
        |0x10 |                      Message payload                          |
        +-----+---------------------------------------------------------------+


    Message header::
        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 | Cert version |  Permission  |           Issue date            |
        +-----+--------------+--------------+---------------------------------+
        |0x04 |   Reserved   |    Command   |             Reserved            |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |                 Unique ID (Lower 32 bits)                     |
        +-----+---------------------------------------------------------------+
        |0x0c |                 Unique ID (Upper 32 bits)                     |
        +-----+---------------------------------------------------------------+

        The message header is common for all signed messages.

    """

    UNIQUE_ID_LEN = 8
    TAG = 0
    PAYLOAD_LENGTH = 0

    def __init__(
        self,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        cmd: int = 0,
        unique_id: Optional[bytes] = None,
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param cmd: Message command ID, defaults to 0
        :param unique_id: UUID of device (least 64 bits is used), defaults to None
        """
        self.cert_ver = cert_ver
        self.permissions = permissions
        now = datetime.datetime.now()
        self.issue_date = issue_date or (now.month << 12 | now.year)
        self.cmd = cmd
        self.unique_id = unique_id or b""

    def __repr__(self) -> str:
        return f"Message, {MessageCommands.get_description(self.TAG, 'Base Class')}"

    def __str__(self) -> str:
        ret = repr(self) + ":\n"
        ret += (
            f"  Certificate version:{self.cert_ver}\n"
            f"  Permissions:        {hex(self.permissions)}\n"
            f"  Issue date:         {hex(self.issue_date)}\n"
            f"  UUID:               {self.unique_id.hex() if self.unique_id else 'Not Available'}"
        )
        return ret

    def __len__(self) -> int:
        """Returns the total length of a container.

        The length includes the fixed as well as the variable length part.
        """
        return self.fixed_length() + self.payload_len

    @property
    def payload_len(self) -> int:
        """Message payload length in bytes."""
        return self.PAYLOAD_LENGTH

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()
            + UINT16  # Issue Date
            + UINT8  # Permission
            + UINT8  # Certificate version
            + UINT16  # Reserved to zero
            + UINT8  # Command
            + UINT8  # Reserved
            + "4s"  # Unique ID (Lower 32 bits)
            + "4s"  # Unique ID (Upper 32 bits)
        )

    def validate(self) -> None:
        """Validate general message properties."""
        if self.cert_ver is None or not check_range(self.cert_ver, end=(1 << 8) - 1):
            raise SPSDKValueError(
                f"Message: Invalid certificate version: {hex(self.cert_ver) if self.cert_ver else 'None'}"
            )

        if self.permissions is None or not check_range(self.permissions, end=(1 << 8) - 1):
            raise SPSDKValueError(
                f"Message: Invalid certificate permission: {hex(self.permissions) if self.permissions else 'None'}"
            )

        if self.issue_date is None or not check_range(self.issue_date, start=1, end=(1 << 16) - 1):
            raise SPSDKValueError(
                f"Message: Invalid issue date: {hex(self.issue_date) if self.issue_date else 'None'}"
            )

        if self.cmd is None or self.cmd not in MessageCommands.tags():
            raise SPSDKValueError(
                f"Message: Invalid command: {hex(self.cmd) if self.cmd else 'None'}"
            )

        if self.unique_id is None or len(self.unique_id) < Message.UNIQUE_ID_LEN:
            raise SPSDKValueError(
                f"Message: Invalid unique ID: {self.unique_id.hex() if self.unique_id else 'None'}"
            )

    def export(self) -> bytes:
        """Exports message into to bytes array.

        :return: Bytes representation of message object.
        """
        msg = pack(
            self.format(),
            self.issue_date,
            self.permissions,
            self.cert_ver,
            RESERVED,
            self.cmd,
            RESERVED,
            self.unique_id[:4],
            self.unique_id[4:8],
        )
        msg += self.export_payload()
        return msg

    @abstractmethod
    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "Message":
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Message object.
        """
        command = config.get("command")
        assert command and len(command) == 1
        msg_cls = Message.get_message_class(list(command.keys())[0])
        return msg_cls.load_from_config(config, search_paths=search_paths)

    @staticmethod
    def load_from_config_generic(config: Dict[str, Any]) -> Tuple[int, int, Optional[int], bytes]:
        """Converts the general configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :return: Message object.
        """
        cert_ver = value_to_int(config.get("cert_version", 0))
        permission = value_to_int(config.get("cert_permission", 0))
        issue_date_raw = config.get("issue_date", None)
        if issue_date_raw:
            assert isinstance(issue_date_raw, str)
            year, month = issue_date_raw.split("-")
            issue_date = max(min(12, int(month)), 1) << 12 | int(year)
        else:
            issue_date = None

        uuid = bytes.fromhex(config.get("uuid", bytes(Message.UNIQUE_ID_LEN).hex()))
        return (cert_ver, permission, issue_date, uuid)

    def _create_general_config(self) -> Dict[str, Any]:
        """Create configuration of the general parts of  Message.

        :return: Configuration dictionary.
        """
        assert self.unique_id
        cfg: Dict[str, Any] = {}
        cfg["cert_version"] = self.cert_ver
        cfg["cert_permission"] = self.permissions
        cfg["issue_date"] = f"{(self.issue_date & 0xfff)}-{(self.issue_date>>12) & 0xf}"
        cfg["uuid"] = self.unique_id.hex()

        return cfg

    @abstractmethod
    def create_config(self) -> Dict[str, Any]:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """

    @classmethod
    def get_message_class(cls, cmd: str) -> Type[Self]:
        """Get the dedicated message class for command."""
        for var in globals():
            obj = globals()[var]
            if isclass(obj) and issubclass(obj, Message) and obj is not Message:
                assert issubclass(obj, Message)
                if MessageCommands.from_label(cmd) == obj.TAG:
                    return obj  # type: ignore

        raise SPSDKValueError(f"Command {cmd} is not supported.")

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary to the signed message object.

        :param data: Binary data with Container block to parse.
        :return: Object recreated from the binary data.
        """
        (
            issue_date,  # issue Date
            permission,  # permission
            certificate_version,  # certificate version
            _,  # Reserved to zero
            command,  # Command
            _,  # Reserved
            uuid_lower,  # Unique ID (Lower 32 bits)
            uuid_upper,  # Unique ID (Upper 32 bits)
        ) = unpack(Message.format(), data[: Message.fixed_length()])

        cmd_name = MessageCommands.get_label(command)
        msg_cls = Message.get_message_class(cmd_name)
        parsed_msg = msg_cls(
            cert_ver=certificate_version,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid_lower + uuid_upper,
        )
        parsed_msg.parse_payload(data[Message.fixed_length() :])
        return parsed_msg  # type: ignore

    @abstractmethod
    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """


class MessageReturnLifeCycle(Message):
    """Return life cycle request message class representation."""

    TAG = MessageCommands.RETURN_LIFECYCLE_UPDATE_REQ.tag
    PAYLOAD_LENGTH = 4

    def __init__(
        self,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        life_cycle: int = 0,
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device (least 64 bits is used), defaults to None
        :param life_cycle: Requested life cycle, defaults to 0
        """
        super().__init__(
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
        )
        self.life_cycle = life_cycle

    def __str__(self) -> str:
        ret = super().__str__()
        ret += f"  Life Cycle:         {hex(self.life_cycle)}"
        return ret

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        return self.life_cycle.to_bytes(length=4, byteorder=Endianness.LITTLE.value)

    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """
        self.life_cycle = int.from_bytes(data[:4], byteorder=Endianness.LITTLE.value)

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "Message":
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get("command", {})
        if not isinstance(command, dict) or len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.from_label(command_name) != MessageReturnLifeCycle.TAG:
            raise SPSDKError("Invalid configuration for Return Life Cycle Request command.")

        cert_ver, permission, issue_date, uuid = Message.load_from_config_generic(config)

        life_cycle = command.get("RETURN_LIFECYCLE_UPDATE_REQ")
        assert isinstance(life_cycle, int)

        return MessageReturnLifeCycle(
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            life_cycle=life_cycle,
        )

    def create_config(self) -> Dict[str, Any]:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        cmd_cfg = {}
        cmd_cfg[MessageCommands.get_label(self.TAG)] = self.life_cycle
        cfg["command"] = cmd_cfg

        return cfg

    def validate(self) -> None:
        """Validate general message properties."""
        super().validate()
        if self.life_cycle is None:
            raise SPSDKValueError("Message Return Life Cycle request: Invalid life cycle")


class MessageWriteSecureFuse(Message):
    """Write secure fuse request message class representation."""

    TAG = MessageCommands.WRITE_SEC_FUSE_REQ.tag
    PAYLOAD_FORMAT = LITTLE_ENDIAN + UINT16 + UINT8 + UINT8

    def __init__(
        self,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        fuse_id: int = 0,
        length: int = 0,
        flags: int = 0,
        data: Optional[List[int]] = None,
    ) -> None:
        """Message used to sign and send to device with EdgeLock.

        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device (least 64 bits is used), defaults to None
        :param fuse_id: Fuse ID, defaults to 0
        :param length: Fuse length, defaults to 0
        :param flags: Fuse flags, defaults to 0
        :param data: List of fuse values
        """
        super().__init__(
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
        )
        self.fuse_id = fuse_id
        self.length = length
        self.flags = flags
        self.fuse_data: List[int] = data or []

    def __str__(self) -> str:
        ret = super().__str__()
        ret += f"  Fuse Index:         {hex(self.fuse_id)}, {self.fuse_id}\n"
        ret += f"  Fuse Length:        {self.length}\n"
        ret += f"  Fuse Flags:         {hex(self.flags)}\n"
        for i, data in enumerate(self.fuse_data):
            ret += f"    Fuse{i} Value:         0x{data:08X}"
        return ret

    @property
    def payload_len(self) -> int:
        """Message payload length in bytes."""
        return 4 + len(self.fuse_data) * 4

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        payload = pack(self.PAYLOAD_FORMAT, self.fuse_id, self.length, self.flags)
        for data in self.fuse_data:
            payload += data.to_bytes(4, Endianness.LITTLE.value)
        return payload

    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """
        self.fuse_id, self.length, self.flags = unpack(self.PAYLOAD_FORMAT, data[:4])
        self.fuse_data.clear()
        for i in range(self.length):
            self.fuse_data.append(
                int.from_bytes(data[4 + i * 4 : 8 + i * 4], Endianness.LITTLE.value)
            )

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "Message":
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get("command", {})
        if not isinstance(command, dict) or len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.from_label(command_name) != MessageWriteSecureFuse.TAG:
            raise SPSDKError("Invalid configuration for Write secure fuse Request command.")

        cert_ver, permission, issue_date, uuid = Message.load_from_config_generic(config)

        secure_fuse = command.get("WRITE_SEC_FUSE_REQ")
        assert isinstance(secure_fuse, dict)
        fuse_id = secure_fuse.get("id")
        assert isinstance(fuse_id, int)
        flags: int = secure_fuse.get("flags", 0)
        data_list: List = secure_fuse.get("data", [])
        data = []
        for x in data_list:
            data.append(value_to_int(x))
        length = len(data_list)
        return MessageWriteSecureFuse(
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            fuse_id=fuse_id,
            length=length,
            flags=flags,
            data=data,
        )

    def create_config(self) -> Dict[str, Any]:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        write_fuse_cfg: Dict[str, Any] = {}
        cmd_cfg = {}
        write_fuse_cfg["id"] = self.fuse_id
        write_fuse_cfg["flags"] = self.flags
        write_fuse_cfg["data"] = [f"0x{x:08X}" for x in self.fuse_data]

        cmd_cfg[MessageCommands.get_label(self.TAG)] = write_fuse_cfg
        cfg["command"] = cmd_cfg

        return cfg

    def validate(self) -> None:
        """Validate general message properties."""
        super().validate()
        if self.fuse_data is None:
            raise SPSDKValueError("Message Write secure fuse request: Missing fuse data")
        if len(self.fuse_data) != self.length:
            raise SPSDKValueError(
                "Message Write secure fuse request: The fuse value list "
                f"has invalid length: ({len(self.fuse_data)} != {self.length})"
            )

        for i, val in enumerate(self.fuse_data):
            if val >= 1 << 32:
                raise SPSDKValueError(
                    f"Message Write secure fuse request: The fuse value({i}) is bigger than 32 bit: ({val})"
                )


class MessageKeyStoreReprovisioningEnable(Message):
    """Key store reprovisioning enable request message class representation."""

    TAG = MessageCommands.KEYSTORE_REPROVISIONING_ENABLE_REQ.tag
    PAYLOAD_LENGTH = 12
    PAYLOAD_FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT16 + UINT32 + UINT32

    FLAGS = 0  # 0 : HSM storage.
    TARGET = 0  # Target ELE

    def __init__(
        self,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        monotonic_counter: int = 0,
        user_sab_id: int = 0,
    ) -> None:
        """Key store reprovisioning enable signed message class init.

        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device (least 64 bits is used), defaults to None
        :param monotonic_counter: Monotonic counter value, defaults to 0
        :param user_sab_id: User SAB id, defaults to 0
        """
        super().__init__(
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
        )
        self.flags = self.FLAGS
        self.target = self.TARGET
        self.reserved = RESERVED
        self.monotonic_counter = monotonic_counter
        self.user_sab_id = user_sab_id

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        return pack(
            self.PAYLOAD_FORMAT,
            self.flags,
            self.target,
            self.reserved,
            self.monotonic_counter,
            self.user_sab_id,
        )

    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """
        self.flags, self.target, self.reserved, self.monotonic_counter, self.user_sab_id = unpack(
            self.PAYLOAD_FORMAT, data[: self.PAYLOAD_LENGTH]
        )

    def validate(self) -> None:
        """Validate general message properties."""
        super().validate()
        if self.flags != self.FLAGS:
            raise SPSDKValueError(
                f"Message Key store reprovisioning enable request: Invalid flags: {self.flags}"
            )
        if self.target != self.TARGET:
            raise SPSDKValueError(
                f"Message Key store reprovisioning enable request: Invalid target: {self.target}"
            )
        if self.reserved != RESERVED:
            raise SPSDKValueError(
                f"Message Key store reprovisioning enable request: Invalid reserved field: {self.reserved}"
            )
        if self.monotonic_counter >= 1 << 32:
            raise SPSDKValueError(
                "Message Key store reprovisioning enable request: Invalid monotonic "
                f"counter field (not fit in 32bit): {self.monotonic_counter}"
            )

        if self.user_sab_id >= 1 << 32:
            raise SPSDKValueError(
                "Message Key store reprovisioning enable request: Invalid user SAB ID "
                f"field (not fit in 32bit): {self.user_sab_id}"
            )

    def __str__(self) -> str:
        ret = super().__str__()
        ret += (
            f"  Monotonic counter value: 0x{self.monotonic_counter:08X}, {self.monotonic_counter}\n"
        )
        ret += f"  User SAB id:             0x{self.user_sab_id:08X}, {self.user_sab_id}"
        return ret

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "Message":
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get("command", {})
        if not isinstance(command, dict) or len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.from_label(command_name) != MessageKeyStoreReprovisioningEnable.TAG:
            raise SPSDKError("Invalid configuration for Write secure fuse Request command.")

        cert_ver, permission, issue_date, uuid = Message.load_from_config_generic(config)

        keystore_repr_en = command.get("KEYSTORE_REPROVISIONING_ENABLE_REQ")
        assert isinstance(keystore_repr_en, dict)
        monotonic_counter = value_to_int(keystore_repr_en.get("monotonic_counter", 0))
        user_sab_id = value_to_int(keystore_repr_en.get("user_sab_id", 0))
        return MessageKeyStoreReprovisioningEnable(
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            monotonic_counter=monotonic_counter,
            user_sab_id=user_sab_id,
        )

    def create_config(self) -> Dict[str, Any]:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        keystore_repr_en_cfg: Dict[str, Any] = {}
        cmd_cfg = {}
        keystore_repr_en_cfg["monotonic_counter"] = f"0x{self.monotonic_counter:08X}"
        keystore_repr_en_cfg["user_sab_id"] = f"0x{self.user_sab_id:08X}"

        cmd_cfg[MessageCommands.get_label(self.TAG)] = keystore_repr_en_cfg
        cfg["command"] = cmd_cfg

        return cfg


class MessageKeyExchange(Message):
    """Key exchange request message class representation."""

    TAG = MessageCommands.KEY_EXCHANGE_REQ.tag
    PAYLOAD_LENGTH = 27 * 4
    PAYLOAD_VERSION = 0x07
    PAYLOAD_FORMAT = (
        LITTLE_ENDIAN
        + UINT8  # TAG
        + UINT8  # Version
        + UINT16  # Reserved
        + UINT32  # Key store ID
        + UINT32  # Key exchange algorithm
        + UINT16  # Salt Flags
        + UINT16  # Derived key group
        + UINT16  # Derived key size bits
        + UINT16  # Derived key type
        + UINT32  # Derived key lifetime
        + UINT32  # Derived key usage
        + UINT32  # Derived key permitted algorithm
        + UINT32  # Derived key lifecycle
        + UINT32  # Derived key ID
        + UINT32  # Private key ID
        + "32s"  # Input peer public key digest word [0-7]
        + "32s"  # Input user fixed info digest word [0-7]
    )

    class KeyExchangeAlgorithm(SpsdkEnum):
        """Key Exchange Algorithm valid values."""

        HKDF_SHA256 = (0x09020109, "HKDF SHA256")
        HKDF_SHA384 = (0x0902010A, "HKDF SHA384")

    class KeyDerivationAlgorithm(SpsdkEnum):
        """Key Derivation Algorithm valid values."""

        HKDF_SHA256 = (0x08000109, "HKDF SHA256", "HKDF SHA256 (HMAC two-step)")
        HKDF_SHA384 = (0x0800010A, "HKDF SHA384", "HKDF SHA384 (HMAC two-step)")

    class DerivedKeyType(SpsdkEnum):
        """Derived Key Type valid values."""

        AES = (0x2400, "AES SHA256", "Possible bit widths: 128/192/256")
        HMAC = (0x1100, "HMAC SHA384", "Possible bit widths: 224/256/384/512")
        OEM_IMPORT_MK_SK = (0x9200, "OEM_IMPORT_MK_SK", "Possible bit widths: 128/192/256")

    class LifeCycle(SpsdkEnum):
        """Chip life cycle valid values."""

        CURRENT = (0x00, "CURRENT", "Current device lifecycle")
        OPEN = (0x01, "OPEN")
        CLOSED = (0x02, "CLOSED")
        LOCKED = (0x04, "LOCKED")

    class LifeTime(SpsdkEnum):
        """Edgelock Enclave life time valid values."""

        VOLATILE = (0x00, "VOLATILE", "Standard volatile key")
        PERSISTENT = (0x01, "PERSISTENT", "Standard persistent key")
        PERMANENT = (0xFF, "PERMANENT", "Standard permanent key")

    class DerivedKeyUsage(SpsdkEnum):
        """Derived Key Usage valid values."""

        CACHE = (
            0x00000004,
            "Cache",
            (
                "Permission to cache the key in the ELE internal secure memory. "
                "This usage is set by default by ELE FW for all keys generated or imported."
            ),
        )
        ENCRYPT = (
            0x00000100,
            "Encrypt",
            (
                "Permission to encrypt a message with the key. It could be cipher encryption,"
                " AEAD encryption or asymmetric encryption operation."
            ),
        )
        DECRYPT = (
            0x00000200,
            "Decrypt",
            (
                "Permission to decrypt a message with the key. It could be cipher decryption,"
                " AEAD decryption or asymmetric decryption operation."
            ),
        )
        SIGN_MSG = (
            0x00000400,
            "Sign message",
            (
                "Permission to sign a message with the key. It could be a MAC generation or an "
                "asymmetric message signature operation."
            ),
        )
        VERIFY_MSG = (
            0x00000800,
            "Verify message",
            (
                "Permission to verify a message signature with the key. It could be a MAC "
                "verification or an asymmetric message signature verification operation."
            ),
        )
        SIGN_HASH = (
            0x00001000,
            "Sign hash",
            (
                "Permission to sign a hashed message with the key with an asymmetric signature "
                "operation. Setting this permission automatically sets the Sign Message usage."
            ),
        )
        VERIFY_HASH = (
            0x00002000,
            "Sign message",
            (
                "Permission to verify a hashed message signature with the key with an asymmetric "
                "signature verification operation. Setting this permission automatically sets the Verify Message usage."
            ),
        )
        DERIVE = (0x00004000, "Derive", "Permission to derive other keys from this key.")

    def __init__(
        self,
        cert_ver: int = 0,
        permissions: int = 0,
        issue_date: Optional[int] = None,
        unique_id: Optional[bytes] = None,
        key_store_id: int = 0,
        key_exchange_algorithm: KeyExchangeAlgorithm = KeyExchangeAlgorithm.HKDF_SHA256,
        salt_flags: int = 0,
        derived_key_grp: int = 0,
        derived_key_size_bits: int = 0,
        derived_key_type: DerivedKeyType = DerivedKeyType.AES,
        derived_key_lifetime: LifeTime = LifeTime.PERSISTENT,
        derived_key_usage: Optional[List[DerivedKeyUsage]] = None,
        derived_key_permitted_algorithm: KeyDerivationAlgorithm = KeyDerivationAlgorithm.HKDF_SHA256,
        derived_key_lifecycle: LifeCycle = LifeCycle.OPEN,
        derived_key_id: int = 0,
        private_key_id: int = 0,
        input_peer_public_key_digest: bytes = bytes(),
        input_user_fixed_info_digest: bytes = bytes(),
    ) -> None:
        """Key exchange signed message class init.

        :param cert_ver: Certificate version, defaults to 0
        :param permissions: Certificate permission, to be used in future
            The stated permission must allow the operation requested by the signed message
            , defaults to 0
        :param issue_date: Issue date, defaults to None (Current date will be applied)
        :param unique_id: UUID of device (least 64 bits is used), defaults to None
        :param key_store_id: Key store ID where to store the derived key. It must be the key store ID
            related to the key management handle set in the command API, defaults to 0
        :param key_exchange_algorithm: Algorithm used by the key exchange process:

            | HKDF SHA256 0x09020109
            | HKDF SHA384 0x0902010A
            | , defaults to HKDF_SHA256

        :param salt_flags: Bit field indicating the requested operations:

            | Bit 0: Salt in step #1 (HKDF-extract) of HMAC based two-step key derivation process:
            | - 0: Use zeros salt;
            | - 1:Use peer public key hash as salt;
            | Bit 1: In case of ELE import, salt used to derive OEM_IMPORT_WRAP_SK and OEM_IMPORT_CMAC_SK:
            | - 0: Zeros string;
            | - 1: Device SRKH.
            | Bit 2 to 15: Reserved, defaults to 0

        :param derived_key_grp: Derived key group. 100 groups are available per key store. It must be a
            value in the range [0; 99]. Keys belonging to the same group can be managed through
            the Manage key group command, defaults to 0
        :param derived_key_size_bits:  Derived key size bits attribute, defaults to 0
        :param derived_key_type:

            +-------------------+-------+------------------+
            |Key type           | Value | Key size in bits |
            +===================+=======+==================+
            |   AES             |0x2400 | 128/192/256      |
            +-------------------+-------+------------------+
            |  HMAC             |0x1100 | 224/256/384/512  |
            +-------------------+-------+------------------+
            | OEM_IMPORT_MK_SK* |0x9200 | 128/192/256      |
            +-------------------+-------+------------------+

            , defaults to AES

        :param derived_key_lifetime: Derived key lifetime attribute

            | VOLATILE           0x00  Standard volatile key.
            | PERSISTENT         0x01  Standard persistent key.
            | PERMANENT          0xFF  Standard permanent key., defaults to PERSISTENT

        :param derived_key_usage: Derived key usage attribute.

            | Cache  0x00000004  Permission to cache the key in the ELE internal secure memory.
            |                     This usage is set by default by ELE FW for all keys generated or imported.
            | Encrypt  0x00000100  Permission to encrypt a message with the key. It could be cipher
            |                     encryption, AEAD encryption or asymmetric encryption operation.
            | Decrypt  0x00000200  Permission to decrypt a message with the key. It could be
            |                     cipher decryption, AEAD decryption or asymmetric decryption operation.
            | Sign message  0x00000400  Permission to sign a message with the key. It could be
            |                     a MAC generation or an asymmetric message signature operation.
            | Verify message  0x00000800  Permission to verify a message signature with the key.
            |                     It could be a MAC verification or an asymmetric message signature
            |                     verification operation.
            | Sign hash  0x00001000  Permission to sign a hashed message with the key
            |                     with an asymmetric signature operation. Setting this permission automatically
            |                     sets the Sign Message usage.
            | Verify hash  0x00002000  Permission to verify a hashed message signature with
            |                     the key with an asymmetric signature verification operation.
            |                     Setting this permission automatically sets the Verify Message usage.
            | Derive  0x00004000  Permission to derive other keys from this key.
            | , defaults to 0

        :param derived_key_permitted_algorithm: Derived key permitted algorithm attribute

            | HKDF SHA256 (HMAC two-step)  0x08000109
            | HKDF SHA384 (HMAC two-step)  0x0800010A, defaults to HKDF_SHA256

        :param derived_key_lifecycle: Derived key lifecycle attribute

            | CURRENT  0x00  Key is usable in current lifecycle.
            | OPEN  0x01  Key is usable in open lifecycle.
            | CLOSED  0x02  Key is usable in closed lifecycle.
            | CLOSED and LOCKED  0x04  Key is usable in closed and locked lifecycle.
            | , defaults to OPEN

        :param derived_key_id: Derived key ID attribute. It could be:

            - Wanted key identifier of the generated key: only supported by persistent
                and permanent keys;
            - 0x00000000 to let the FW chose the key identifier: supported by all
                keys (all persistence levels). , defaults to 0

        :param private_key_id: Identifier in the ELE key storage of the private key to use with the peer
            public key during the key agreement process, defaults to 0
        :param input_peer_public_key_digest: Input peer public key digest buffer.
            The algorithm used to generate the digest must be SHA256, defaults to list(8)
        :param input_user_fixed_info_digest: Input user fixed info digest buffer.
            The algorithm used to generate the digest must be SHA256, defaults to list(8)
        """
        super().__init__(
            cert_ver=cert_ver,
            permissions=permissions,
            issue_date=issue_date,
            cmd=self.TAG,
            unique_id=unique_id,
        )
        self.tag = self.TAG
        self.version = self.PAYLOAD_VERSION
        self.reserved = RESERVED
        self.key_store_id = key_store_id
        self.key_exchange_algorithm = key_exchange_algorithm
        self.salt_flags = salt_flags
        self.derived_key_grp = derived_key_grp
        self.derived_key_size_bits = derived_key_size_bits
        self.derived_key_type = derived_key_type
        self.derived_key_lifetime = derived_key_lifetime
        self.derived_key_usage = derived_key_usage or []
        self.derived_key_permitted_algorithm = derived_key_permitted_algorithm
        self.derived_key_lifecycle = derived_key_lifecycle
        self.derived_key_id = derived_key_id
        self.private_key_id = private_key_id
        self.input_peer_public_key_digest = input_peer_public_key_digest
        self.input_user_fixed_info_digest = input_user_fixed_info_digest

    def export_payload(self) -> bytes:
        """Exports message payload to bytes array.

        :return: Bytes representation of message payload.
        """
        derived_key_usage = 0
        for usage in self.derived_key_usage:
            derived_key_usage |= usage.tag
        return pack(
            self.PAYLOAD_FORMAT,
            self.tag,
            self.version,
            self.reserved,
            self.key_store_id,
            self.key_exchange_algorithm.tag,
            self.derived_key_grp,
            self.salt_flags,
            self.derived_key_type.tag,
            self.derived_key_size_bits,
            self.derived_key_lifetime.tag,
            derived_key_usage,
            self.derived_key_permitted_algorithm.tag,
            self.derived_key_lifecycle.tag,
            self.derived_key_id,
            self.private_key_id,
            self.input_peer_public_key_digest,
            self.input_user_fixed_info_digest,
        )

    def parse_payload(self, data: bytes) -> None:
        """Parse payload.

        :param data: Binary data with Payload to parse.
        """
        (
            self.tag,
            self.version,
            self.reserved,
            self.key_store_id,
            key_exchange_algorithm,
            self.derived_key_grp,
            self.salt_flags,
            derived_key_type,
            self.derived_key_size_bits,
            derived_key_lifetime,
            derived_key_usage,
            derived_key_permitted_algorithm,
            derived_key_lifecycle,
            self.derived_key_id,
            self.private_key_id,
            input_peer_public_key_digest,
            input_user_fixed_info_digest,
        ) = unpack(self.PAYLOAD_FORMAT, data[: self.PAYLOAD_LENGTH])

        # Do some post process
        self.key_exchange_algorithm = self.KeyExchangeAlgorithm.from_tag(key_exchange_algorithm)
        self.derived_key_type = self.DerivedKeyType.from_tag(derived_key_type)
        self.derived_key_lifetime = self.LifeTime.from_tag(derived_key_lifetime)
        self.derived_key_permitted_algorithm = self.KeyDerivationAlgorithm.from_tag(
            derived_key_permitted_algorithm
        )
        self.derived_key_lifecycle = self.LifeCycle.from_tag(derived_key_lifecycle)

        self.input_peer_public_key_digest = input_peer_public_key_digest
        self.input_user_fixed_info_digest = input_user_fixed_info_digest
        self.derived_key_usage.clear()
        for tag in self.DerivedKeyUsage.tags():
            if tag & derived_key_usage:
                self.derived_key_usage.append(self.DerivedKeyUsage.from_tag(tag))

    def validate(self) -> None:
        """Validate general message properties."""
        super().validate()
        if self.tag != self.TAG:
            raise SPSDKValueError(
                f"Message Key store reprovisioning enable request: Invalid tag: {self.tag}"
            )
        if self.version != self.version:
            raise SPSDKValueError(
                f"Message Key store reprovisioning enable request: Invalid verssion: {self.version}"
            )
        if self.reserved != RESERVED:
            raise SPSDKValueError(
                f"Message Key store reprovisioning enable request: Invalid reserved field: {self.reserved}"
            )

    def __str__(self) -> str:
        ret = super().__str__()
        ret += f"  KeyStore ID value: 0x{self.key_store_id:08X}, {self.key_store_id}\n"
        ret += f"  Key exchange algorithm value: {self.key_exchange_algorithm.label}\n"
        ret += f"  Salt flags value: 0x{self.salt_flags:08X}, {self.salt_flags}\n"
        ret += f"  Derived key group value: 0x{self.derived_key_grp:08X}, {self.derived_key_grp}\n"
        ret += f"  Derived key bit size value: 0x{self.derived_key_size_bits:08X}, {self.derived_key_size_bits}\n"
        ret += f"  Derived key type value: {self.derived_key_type.label}\n"
        ret += f"  Derived key life time value: {self.derived_key_lifetime.label}\n"
        ret += f"  Derived key usage value: {[x.label for x in self.derived_key_usage]}\n"
        ret += f"  Derived key permitted algorithm value: {self.derived_key_permitted_algorithm.label}\n"
        ret += f"  Derived key life cycle value: {self.derived_key_lifecycle.label}\n"
        ret += f"  Derived key ID value: 0x{self.derived_key_id:08X}, {self.derived_key_id}\n"
        ret += f"  Private key ID value: 0x{self.private_key_id:08X}, {self.private_key_id}\n"
        ret += f"  Input peer public key digest value: {self.input_peer_public_key_digest.hex()}\n"
        ret += f"  Input user public fixed info digest value: {self.input_peer_public_key_digest.hex()}\n"
        return ret

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "Message":
        """Converts the configuration option into an message object.

        "config" content of container configurations.

        :param config: Message configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid configuration detected.
        :return: Message object.
        """
        command = config.get("command", {})
        if not isinstance(command, dict) or len(command) != 1:
            raise SPSDKError(f"Invalid config field command: {command}")
        command_name = list(command.keys())[0]
        if MessageCommands.from_label(command_name) != MessageKeyExchange.TAG:
            raise SPSDKError("Invalid configuration forKey Exchange Request command.")

        cert_ver, permission, issue_date, uuid = Message.load_from_config_generic(config)

        key_exchange = command.get("KEY_EXCHANGE_REQ")
        assert isinstance(key_exchange, dict)

        key_store_id = value_to_int(key_exchange.get("key_store_id", 0))
        key_exchange_algorithm = MessageKeyExchange.KeyExchangeAlgorithm.from_attr(
            key_exchange.get("key_exchange_algorithm", "HKDF SHA256")
        )
        salt_flags = value_to_int(key_exchange.get("salt_flags", 0))
        derived_key_grp = value_to_int(key_exchange.get("derived_key_grp", 0))
        derived_key_size_bits = value_to_int(key_exchange.get("derived_key_size_bits", 128))
        derived_key_type = MessageKeyExchange.DerivedKeyType.from_attr(
            key_exchange.get("derived_key_type", "AES SHA256")
        )
        derived_key_lifetime = MessageKeyExchange.LifeTime.from_attr(
            key_exchange.get("derived_key_lifetime", "PERSISTENT")
        )
        derived_key_usage = [
            MessageKeyExchange.DerivedKeyUsage.from_attr(x)
            for x in key_exchange.get("derived_key_usage", [])
        ]
        derived_key_permitted_algorithm = MessageKeyExchange.KeyDerivationAlgorithm.from_attr(
            key_exchange.get("derived_key_permitted_algorithm", "HKDF SHA256")
        )
        derived_key_lifecycle = MessageKeyExchange.LifeCycle.from_attr(
            key_exchange.get("derived_key_lifecycle", "OPEN")
        )
        derived_key_id = value_to_int(key_exchange.get("derived_key_id", 0))
        private_key_id = value_to_int(key_exchange.get("private_key_id", 0))
        input_peer_public_key_digest = load_hex_string(
            source=key_exchange.get("input_peer_public_key_digest", bytes(32)),
            expected_size=32,
            search_paths=search_paths,
        )
        input_user_fixed_info_digest = load_hex_string(
            source=key_exchange.get("input_user_fixed_info_digest", bytes(32)),
            expected_size=32,
            search_paths=search_paths,
        )

        return MessageKeyExchange(
            cert_ver=cert_ver,
            permissions=permission,
            issue_date=issue_date,
            unique_id=uuid,
            key_store_id=key_store_id,
            key_exchange_algorithm=key_exchange_algorithm,
            salt_flags=salt_flags,
            derived_key_grp=derived_key_grp,
            derived_key_size_bits=derived_key_size_bits,
            derived_key_type=derived_key_type,
            derived_key_lifetime=derived_key_lifetime,
            derived_key_usage=derived_key_usage,
            derived_key_permitted_algorithm=derived_key_permitted_algorithm,
            derived_key_lifecycle=derived_key_lifecycle,
            derived_key_id=derived_key_id,
            private_key_id=private_key_id,
            input_peer_public_key_digest=input_peer_public_key_digest,
            input_user_fixed_info_digest=input_user_fixed_info_digest,
        )

    def create_config(self) -> Dict[str, Any]:
        """Create configuration of the Signed Message.

        :return: Configuration dictionary.
        """
        cfg = self._create_general_config()
        key_exchange_cfg: Dict[str, Any] = {}
        cmd_cfg = {}
        key_exchange_cfg["key_store_id"] = f"0x{self.key_store_id:08X}"
        key_exchange_cfg["key_exchange_algorithm"] = self.key_exchange_algorithm.label
        key_exchange_cfg["salt_flags"] = f"0x{self.salt_flags:08X}"
        key_exchange_cfg["derived_key_grp"] = self.derived_key_grp
        key_exchange_cfg["derived_key_size_bits"] = self.derived_key_size_bits
        key_exchange_cfg["derived_key_type"] = self.derived_key_type.label
        key_exchange_cfg["derived_key_lifetime"] = self.derived_key_lifetime.label
        key_exchange_cfg["derived_key_usage"] = [x.label for x in self.derived_key_usage]
        key_exchange_cfg[
            "derived_key_permitted_algorithm"
        ] = self.derived_key_permitted_algorithm.label
        key_exchange_cfg["derived_key_lifecycle"] = self.derived_key_lifecycle.label
        key_exchange_cfg["derived_key_id"] = self.derived_key_id
        key_exchange_cfg["private_key_id"] = self.private_key_id
        key_exchange_cfg["input_peer_public_key_digest"] = self.input_peer_public_key_digest.hex()
        key_exchange_cfg["input_user_fixed_info_digest"] = (
            self.input_user_fixed_info_digest.hex()
            if self.input_user_fixed_info_digest
            else bytes(32).hex()
        )

        cmd_cfg[MessageCommands.get_label(self.TAG)] = key_exchange_cfg
        cfg["command"] = cmd_cfg

        return cfg


class SignedMessage(AHABContainerBase):
    """Class representing the Signed message.

    Signed Message::

        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |    Tag       | Length (MSB) | Length (LSB)   |     Version    |
        +-----+--------------+--------------+----------------+----------------+
        |0x04 |                          Flags                                |
        +-----+--------------+--------------+---------------------------------+
        |0x08 |   Reserved   | Fuse version |       Software version          |
        +-----+--------------+--------------+---------------------------------+
        |0x10 |                    Message descriptor                         |
        +-----+---------------------------------------------------------------+
        |0x34 |                      Message header                           |
        +-----+---------------------------------------------------------------+
        |0x44 |                      Message payload                          |
        +-----+---------------------------------------------------------------+
        |0xXX |                      Signature Block                          |
        +-----+---------------------------------------------------------------+

    Message descriptor::
        +-----+--------------+--------------+----------------+----------------+
        |Off  |    Byte 3    |    Byte 2    |      Byte 1    |     Byte 0     |
        +-----+--------------+--------------+----------------+----------------+
        |0x00 |                   Reserved                   |      Flags     |
        +-----+----------------------------------------------+----------------+
        |0x04 |                       IV (256 bits)                           |
        +-----+---------------------------------------------------------------+

    """

    TAG = SignedMessageTags.SIGNED_MSG.tag
    ENCRYPT_IV_LEN = 32

    def __init__(
        self,
        flags: int = 0,
        fuse_version: int = 0,
        sw_version: int = 0,
        message: Optional[Message] = None,
        signature_block: Optional[SignatureBlock] = None,
        encrypt_iv: Optional[bytes] = None,
    ):
        """Class object initializer.

        :param flags: flags.
        :param fuse_version: value must be equal to or greater than the version
            stored in the fuses to allow loading this container.
        :param sw_version: used by PHBC (Privileged Host Boot Companion) to select
            between multiple images with same fuse version field.
        :param message: Message command to be signed.
        :param signature_block: signature block.
        :param encrypt_iv: Encryption Initial Vector - if defined the encryption is used.
        """
        super().__init__(
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            signature_block=signature_block,
        )
        self.message = message
        self.encrypt_iv = encrypt_iv

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SignedMessage):
            if super().__eq__(other) and self.message == other.message:
                return True

        return False

    def __repr__(self) -> str:
        return f"Signed Message, {'Encrypted' if self.encrypt_iv else 'Plain'}"

    def __str__(self) -> str:
        return (
            f"  Flags:              {hex(self.flags)}\n"
            f"  Fuse version:       {hex(self.fuse_version)}\n"
            f"  SW version:         {hex(self.sw_version)}\n"
            f"  Signature Block:\n{str(self.signature_block)}\n"
            f"  Message:\n{str(self.message)}\n"
            f"  Encryption IV:      {self.encrypt_iv.hex() if self.encrypt_iv else 'Not Available'}"
        )

    @property
    def _signature_block_offset(self) -> int:
        """Returns current signature block offset.

        :return: Offset in bytes of Signature block.
        """
        # Constant size of Container header + Image array Entry table
        assert self.message
        return calcsize(self.format()) + len(self.message)

    def __len__(self) -> int:
        """Get total length of AHAB container.

        :return: Size in bytes of Message.
        """
        return self._signature_block_offset + len(self.signature_block)

    @classmethod
    def format(cls) -> str:
        """Format of binary representation."""
        return (
            super().format()
            + UINT8  # Descriptor Flags
            + UINT8  # Reserved
            + UINT16  # Reserved
            + "32s"  # IV - Initial Vector if encryption is enabled
        )

    def update_fields(self) -> None:
        """Updates all volatile information in whole container structure.

        :raises SPSDKError: When inconsistent image array length is detected.
        """
        # 0. Update length
        self.length = len(self)
        # 1. Update the signature block to get overall size of it
        self.signature_block.update_fields()
        # 2. Sign the image header
        if self.flag_srk_set != "none":
            assert self.signature_block.signature
            self.signature_block.signature.sign(self.get_signature_data())

    def _export(self) -> bytes:
        """Export raw data without updates fields into bytes.

        :return: bytes representing container header content including the signature block.
        """
        signed_message = pack(
            self.format(),
            self.version,
            len(self),
            self.tag,
            self.flags,
            self.sw_version,
            self.fuse_version,
            RESERVED,
            self._signature_block_offset,
            RESERVED,  # Reserved field
            1 if self.encrypt_iv else 0,
            RESERVED,
            RESERVED,
            self.encrypt_iv if self.encrypt_iv else bytes(32),
        )
        # Add Message Header + Message Payload
        assert self.message
        signed_message += self.message.export()
        # Add Signature Block
        signed_message += align_block(self.signature_block.export(), CONTAINER_ALIGNMENT)
        return signed_message

    def export(self) -> bytes:
        """Export the signed image into one chunk.

        :raises SPSDKValueError: if the number of images doesn't correspond the the number of
            entries in image array info.
        :return: images exported into single binary
        """
        self.update_fields()
        self.validate({})
        return self._export()

    def validate(self, data: Dict[str, Any]) -> None:
        """Validate object data.

        :param data: Additional validation data.
        :raises SPSDKValueError: Invalid any value of Image Array entry
        """
        data["flag_used_srk_id"] = self.flag_used_srk_id

        if self.length != len(self):
            raise SPSDKValueError(
                f"Container Header: Invalid block length: {self.length} != {len(self)}"
            )
        super().validate(data)
        if self.encrypt_iv and len(self.encrypt_iv) != self.ENCRYPT_IV_LEN:
            raise SPSDKValueError(
                "Signed Message: Invalid Encryption initialization vector length: "
                f"{len(self.encrypt_iv)*8} Bits != {self.ENCRYPT_IV_LEN * 8} Bits"
            )
        if self.message is None:
            raise SPSDKValueError("Signed Message: Invalid Message payload.")
        self.message.validate()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse input binary to the signed message object.

        :param data: Binary data with Container block to parse.
        :return: Object recreated from the binary data.
        """
        SignedMessage.check_container_head(data)
        image_format = SignedMessage.format()
        (
            _,  # version
            _,  # container_length
            _,  # tag
            flags,
            sw_version,
            fuse_version,
            _,  # number_of_images
            signature_block_offset,
            _,  # reserved
            descriptor_flags,
            _,  # reserved
            _,  # reserved
            iv,
        ) = unpack(image_format, data[: SignedMessage.fixed_length()])

        parsed_signed_msg = cls(
            flags=flags,
            fuse_version=fuse_version,
            sw_version=sw_version,
            encrypt_iv=iv if bool(descriptor_flags & 0x01) else None,
        )
        parsed_signed_msg.signature_block = SignatureBlock.parse(data[signature_block_offset:])

        # Parse also Message itself
        parsed_signed_msg.message = Message.parse(
            data[SignedMessage.fixed_length() : signature_block_offset]
        )
        return parsed_signed_msg

    def create_config(self, data_path: str) -> Dict[str, Any]:
        """Create configuration of the Signed Message.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        self.validate({})
        cfg = self._create_config(0, data_path)
        cfg["family"] = "N/A"
        cfg["revision"] = "N/A"
        cfg["output"] = "N/A"

        assert self.message
        cfg["message"] = self.message.create_config()

        return cfg

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "SignedMessage":
        """Converts the configuration option into an Signed message object.

        "config" content of container configurations.

        :param config: Signed Message configuration dictionaries.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Message object.
        """
        signed_msg = SignedMessage()
        signed_msg.search_paths = search_paths or []
        AHABContainerBase.load_from_config_generic(signed_msg, config)

        message = config.get("message")
        assert isinstance(message, dict)

        signed_msg.message = Message.load_from_config(message, search_paths=search_paths)

        return signed_msg

    def image_info(self) -> BinaryImage:
        """Get Image info object.

        :return: Signed Message Info object.
        """
        self.validate({})
        assert self.message
        ret = BinaryImage(
            name="Signed Message",
            size=len(self),
            offset=0,
            binary=self.export(),
            description=(f"Signed Message for {MessageCommands.get_label(self.message.TAG)}"),
        )
        return ret

    @staticmethod
    def get_validation_schemas() -> List[Dict[str, Any]]:
        """Get list of validation schemas.

        :return: Validation list of schemas.
        """
        sch = DatabaseManager().db.get_schema_file(DatabaseManager.SIGNED_MSG)
        sch["properties"]["family"]["enum"] = AHABImage.get_supported_families()
        return [sch]

    @staticmethod
    def generate_config_template(
        family: str, message: Optional[MessageCommands] = None
    ) -> Dict[str, Any]:
        """Generate AHAB configuration template.

        :param family: Family for which the template should be generated.
        :param message: Generate the template just for one message type, if not used , its generated for all messages
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        val_schemas = SignedMessage.get_validation_schemas()
        val_schemas[0]["properties"]["family"]["template_value"] = family

        if family not in AHABImage.get_supported_families():
            raise SPSDKValueError(
                f"Unsupported value for family: {family} not in {AHABImage.get_supported_families()}"
            )

        if message:
            for cmd_sch in val_schemas[0]["properties"]["message"]["properties"]["command"][
                "oneOf"
            ]:
                cmd_sch["skip_in_template"] = bool(message.label not in cmd_sch["properties"])

        yaml_data = CommentedConfig(
            f"Signed message Configuration template for {family}.", val_schemas
        ).get_template()

        return {f"{family}_signed_msg": yaml_data}
