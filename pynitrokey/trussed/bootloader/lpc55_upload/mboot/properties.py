#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Helper module for more human-friendly interpretation of the target device properties."""


import ctypes
from copy import deepcopy
from typing import Callable, Dict, List, Optional, Tuple, Type, Union

from spsdk.exceptions import SPSDKKeyError
from spsdk.mboot.exceptions import McuBootError
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum

from .commands import CommandTag
from .error_codes import StatusCode
from .memories import ExtMemPropTags, MemoryRegion


########################################################################################################################
# McuBoot helper functions
########################################################################################################################
def size_fmt(value: Union[int, float], kibibyte: bool = True) -> str:
    """Convert size value into string format.

    :param value: The raw value
    :param kibibyte: True if 1024 Bytes represent 1kB or False if 1000 Bytes represent 1kB
    :return: Stringified value
    """
    base, suffix = [(1000.0, "B"), (1024.0, "iB")][kibibyte]
    x = "B"
    for x in ["B"] + [prefix + suffix for prefix in list("kMGTP")]:
        if -base < value < base:
            break
        value /= base

    return f"{value} {x}" if x == "B" else f"{value:3.1f} {x}"


########################################################################################################################
# McuBoot helper classes
########################################################################################################################


class Version:
    """McuBoot current and target version type."""

    def __init__(self, *args: Union[str, int], **kwargs: int):
        """Initialize the Version object.

        :raises McuBootError: Argument passed the not str not int
        """
        self.mark = kwargs.get("mark", "K")
        self.major = kwargs.get("major", 0)
        self.minor = kwargs.get("minor", 0)
        self.fixation = kwargs.get("fixation", 0)
        if args:
            if isinstance(args[0], int):
                self.from_int(args[0])
            elif isinstance(args[0], str):
                self.from_str(args[0])
            else:
                raise McuBootError("Value must be 'str' or 'int' type !")

    def __eq__(self, obj: object) -> bool:
        return isinstance(obj, Version) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        return not self.__eq__(obj)

    def __lt__(self, obj: "Version") -> bool:
        return self.to_int(True) < obj.to_int(True)

    def __le__(self, obj: "Version") -> bool:
        return self.to_int(True) <= obj.to_int(True)

    def __gt__(self, obj: "Version") -> bool:
        return self.to_int(True) > obj.to_int(True)

    def __ge__(self, obj: "Version") -> bool:
        return self.to_int(True) >= obj.to_int(True)

    def __repr__(self) -> str:
        return f"<Version(mark={self.mark}, major={self.major}, minor={self.minor}, fixation={self.fixation})>"

    def __str__(self) -> str:
        return self.to_str()

    def from_int(self, value: int) -> None:
        """Parse version data from raw int value.

        :param value: Raw integer input
        """
        mark = (value >> 24) & 0xFF
        self.mark = chr(mark) if 64 < mark < 91 else None  # type: ignore
        self.major = (value >> 16) & 0xFF
        self.minor = (value >> 8) & 0xFF
        self.fixation = value & 0xFF

    def from_str(self, value: str) -> None:
        """Parse version data from string value.

        :param value: String representation input
        """
        mark_major, minor, fixation = value.split(".")
        if len(mark_major) > 1 and mark_major[0] not in "0123456789":
            self.mark = mark_major[0]
            self.major = int(mark_major[1:])
        else:
            self.major = int(mark_major)
        self.minor = int(minor)
        self.fixation = int(fixation)

    def to_int(self, no_mark: bool = False) -> int:
        """Get version value in raw integer format.

        :param no_mark: If True, return value without mark
        :return: Integer representation
        """
        value = self.major << 16 | self.minor << 8 | self.fixation
        mark = 0 if no_mark or self.mark is None else ord(self.mark) << 24  # type: ignore
        return value | mark

    def to_str(self, no_mark: bool = False) -> str:
        """Get version value in readable string format.

        :param no_mark: If True, return value without mark
        :return: String representation
        """
        value = f"{self.major}.{self.minor}.{self.fixation}"
        mark = "" if no_mark or self.mark is None else self.mark
        return f"{mark}{value}"


########################################################################################################################
# McuBoot Properties
########################################################################################################################

# fmt: off
class PropertyTag(SpsdkEnum):
    """McuBoot Properties."""

    LIST_PROPERTIES            = (0x00, 'ListProperties', 'List Properties')
    CURRENT_VERSION            = (0x01, "CurrentVersion", "Current Version")
    AVAILABLE_PERIPHERALS      = (0x02, "AvailablePeripherals", "Available Peripherals")
    FLASH_START_ADDRESS        = (0x03, "FlashStartAddress", "Flash Start Address")
    FLASH_SIZE                 = (0x04, "FlashSize", "Flash Size")
    FLASH_SECTOR_SIZE          = (0x05, "FlashSectorSize", "Flash Sector Size")
    FLASH_BLOCK_COUNT          = (0x06, "FlashBlockCount", "Flash Block Count")
    AVAILABLE_COMMANDS         = (0x07, "AvailableCommands", "Available Commands")
    CRC_CHECK_STATUS           = (0x08, "CrcCheckStatus", "CRC Check Status")
    LAST_ERROR                 = (0x09, "LastError", "Last Error Value")
    VERIFY_WRITES              = (0x0A, "VerifyWrites", "Verify Writes")
    MAX_PACKET_SIZE            = (0x0B, "MaxPacketSize", "Max Packet Size")
    RESERVED_REGIONS           = (0x0C, "ReservedRegions", "Reserved Regions")
    VALIDATE_REGIONS           = (0x0D, "ValidateRegions", "Validate Regions")
    RAM_START_ADDRESS          = (0x0E, "RamStartAddress", "RAM Start Address")
    RAM_SIZE                   = (0x0F, "RamSize", "RAM Size")
    SYSTEM_DEVICE_IDENT        = (0x10, "SystemDeviceIdent", "System Device Identification")
    FLASH_SECURITY_STATE       = (0x11, "FlashSecurityState", "Security State")
    UNIQUE_DEVICE_IDENT        = (0x12, "UniqueDeviceIdent", "Unique Device Identification")
    FLASH_FAC_SUPPORT          = (0x13, "FlashFacSupport", "Flash Fac. Support")
    FLASH_ACCESS_SEGMENT_SIZE  = (0x14, "FlashAccessSegmentSize", "Flash Access Segment Size",)
    FLASH_ACCESS_SEGMENT_COUNT = (0x15, "FlashAccessSegmentCount", "Flash Access Segment Count",)
    FLASH_READ_MARGIN          = (0x16, "FlashReadMargin", "Flash Read Margin")
    QSPI_INIT_STATUS           = (0x17, "QspiInitStatus", "QuadSPI Initialization Status")
    TARGET_VERSION             = (0x18, "TargetVersion", "Target Version")
    EXTERNAL_MEMORY_ATTRIBUTES = (0x19, "ExternalMemoryAttributes", "External Memory Attributes",)
    RELIABLE_UPDATE_STATUS     = (0x1A, "ReliableUpdateStatus", "Reliable Update Status")
    FLASH_PAGE_SIZE            = (0x1B, "FlashPageSize", "Flash Page Size")
    IRQ_NOTIFIER_PIN           = (0x1C, "IrqNotifierPin", "Irq Notifier Pin")
    PFR_KEYSTORE_UPDATE_OPT    = (0x1D, "PfrKeystoreUpdateOpt", "PFR Keystore Update Opt")
    BYTE_WRITE_TIMEOUT_MS      = (0x1E, "ByteWriteTimeoutMs", "Byte Write Timeout in ms")
    FUSE_LOCKED_STATUS         = (0x1F, "FuseLockedStatus", "Fuse Locked Status")
    UNKNOWN                    = (0xFF, "Unknown", "Unknown property")


class PropertyTagKw45xx(SpsdkEnum):
    """McuBoot Properties."""

    VERIFY_ERASE               = (0x0A, "VerifyErase", "Verify Erase")
    BOOT_STATUS_REGISTER       = (0x14, "BootStatusRegister", "Boot Status Register",)
    FIRMWARE_VERSION           = (0x15, "FirmwareVersion", "Firmware Version",)
    FUSE_PROGRAM_VOLTAGE       = (0x16, "FuseProgramVoltage", "Fuse Program Voltage")

class PeripheryTag(SpsdkEnum):
    """Tags representing peripherals."""

    UART      = (0x01, "UART", "UART Interface")
    I2C_SLAVE = (0x02, "I2C-Slave", "I2C Slave Interface")
    SPI_SLAVE = (0x04, "SPI-Slave", "SPI Slave Interface")
    CAN       = (0x08, "CAN", "CAN Interface")
    USB_HID   = (0x10, "USB-HID", "USB HID-Class Interface")
    USB_CDC   = (0x20, "USB-CDC", "USB CDC-Class Interface")
    USB_DFU   = (0x40, "USB-DFU", "USB DFU-Class Interface")
    LIN       = (0x80, "LIN", "LIN Interface")


class FlashReadMargin(SpsdkEnum):
    """Scopes for flash read."""

    NORMAL  = (0, "NORMAL")
    USER    = (1, "USER")
    FACTORY = (2, "FACTORY")


class PfrKeystoreUpdateOpt(SpsdkEnum):
    """Options for PFR updating."""

    KEY_PROVISIONING = (0, "KEY_PROVISIONING", "KeyProvisioning")
    WRITE_MEMORY     = (1, "WRITE_MEMORY", "WriteMemory")
# fmt: on

########################################################################################################################
# McuBoot Properties Values
########################################################################################################################


class PropertyValueBase:
    """Base class for property value."""

    __slots__ = ("tag", "name", "desc")

    def __init__(self, tag: int, name: Optional[str] = None, desc: Optional[str] = None) -> None:
        """Initialize the base of property.

        :param tag: Property tag, see: `PropertyTag`
        :param name: Optional name for the property
        :param desc: Optional description for the property
        """
        self.tag = tag
        self.name = name or PropertyTag.get_label(tag) or ""
        self.desc = desc or PropertyTag.get_description(tag, "")

    def __str__(self) -> str:
        return f"{self.desc} = {self.to_str()}"

    def to_str(self) -> str:
        """Stringified representation of a property.

        Derived classes should implement this function.

        :return: String representation
        :raises NotImplementedError: Derived class has to implement this method
        """
        raise NotImplementedError("Derived class has to implement this method.")


class IntValue(PropertyValueBase):
    """Integer-based value property."""

    __slots__ = (
        "value",
        "_fmt",
    )

    def __init__(self, tag: int, raw_values: List[int], str_format: str = "dec") -> None:
        """Initialize the integer-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        :param str_format: Format to display the value ('dec', 'hex', 'size')
        """
        super().__init__(tag)
        self._fmt = str_format
        self.value = raw_values[0]

    def to_int(self) -> int:
        """Get the raw integer property representation."""
        return self.value

    def to_str(self) -> str:
        """Get stringified property representation."""
        if self._fmt == "size":
            str_value = size_fmt(self.value)
        elif self._fmt == "hex":
            str_value = f"0x{self.value:08X}"
        elif self._fmt == "dec":
            str_value = str(self.value)
        elif self._fmt == "int32":
            str_value = str(ctypes.c_int32(self.value).value)
        else:
            str_value = self._fmt.format(self.value)
        return str_value


class BoolValue(PropertyValueBase):
    """Boolean-based value property."""

    __slots__ = (
        "value",
        "_true_values",
        "_false_values",
        "_true_string",
        "_false_string",
    )

    def __init__(
        self,
        tag: int,
        raw_values: List[int],
        true_values: Tuple[int] = (1,),
        true_string: str = "YES",
        false_values: Tuple[int] = (0,),
        false_string: str = "NO",
    ) -> None:
        """Initialize the Boolean-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        :param true_values: Values representing 'True', defaults to (1,)
        :param true_string: String representing 'True, defaults to 'YES'
        :param false_values: Values representing 'False', defaults to (0,)
        :param false_string: String representing 'False, defaults to 'NO'
        """
        super().__init__(tag)
        self._true_values = true_values
        self._true_string = true_string
        self._false_values = false_values
        self._false_string = false_string
        self.value = raw_values[0]

    def __bool__(self) -> bool:
        return self.value in self._true_values

    def to_int(self) -> int:
        """Get the raw integer portion of the property."""
        return self.value

    def to_str(self) -> str:
        """Get stringified property representation."""
        return self._true_string if self.value in self._true_values else self._false_string


class EnumValue(PropertyValueBase):
    """Enumeration value property."""

    __slots__ = ("value", "enum", "_na_msg")

    def __init__(
        self,
        tag: int,
        raw_values: List[int],
        enum: Type[SpsdkEnum],
        na_msg: str = "Unknown Item",
    ) -> None:
        """Initialize the enumeration-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        :param enum: Enumeration to pick from
        :param na_msg: Message to display if an item is not found in the enum
        """
        super().__init__(tag)
        self._na_msg = na_msg
        self.enum = enum
        self.value = raw_values[0]

    def to_int(self) -> int:
        """Get the raw integer portion of the property."""
        return self.value

    def to_str(self) -> str:
        """Get stringified property representation."""
        try:
            return self.enum.get_label(self.value)
        except SPSDKKeyError:
            return f"{self._na_msg}: {self.value}"


class VersionValue(PropertyValueBase):
    """Version property class."""

    __slots__ = ("value",)

    def __init__(self, tag: int, raw_values: List[int]) -> None:
        """Initialize the Version-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(tag)
        self.value = Version(raw_values[0])

    def to_int(self) -> int:
        """Get the raw integer portion of the property."""
        return self.value.to_int()

    def to_str(self) -> str:
        """Get stringified property representation."""
        return self.value.to_str()


class DeviceUidValue(PropertyValueBase):
    """Device UID value property."""

    __slots__ = ("value",)

    def __init__(self, tag: int, raw_values: List[int]) -> None:
        """Initialize the Version-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(tag)
        self.value = b"".join(
            [int.to_bytes(val, length=4, byteorder=Endianness.LITTLE.value) for val in raw_values]
        )

    def to_int(self) -> int:
        """Get the raw integer portion of the property."""
        return int.from_bytes(self.value, byteorder=Endianness.BIG.value)

    def to_str(self) -> str:
        """Get stringified property representation."""
        return " ".join(f"{item:02X}" for item in self.value)


class ReservedRegionsValue(PropertyValueBase):
    """Reserver Regions property."""

    __slots__ = ("regions",)

    def __init__(self, tag: int, raw_values: List[int]) -> None:
        """Initialize the ReserverRegion-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(tag)
        self.regions: List[MemoryRegion] = []
        for i in range(0, len(raw_values), 2):
            if raw_values[i + 1] == 0:
                continue
            self.regions.append(MemoryRegion(raw_values[i], raw_values[i + 1]))

    def __str__(self) -> str:
        return f"{self.desc} =\n{self.to_str()}"

    def to_str(self) -> str:
        """Get stringified property representation."""
        return "\n".join([f"    Region {i}: {region}" for i, region in enumerate(self.regions)])


class AvailablePeripheralsValue(PropertyValueBase):
    """Available Peripherals property."""

    __slots__ = ("value",)

    def __init__(self, tag: int, raw_values: List[int]) -> None:
        """Initialize the AvailablePeripherals-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(tag)
        self.value = raw_values[0]

    def to_int(self) -> int:
        """Get the raw integer portion of the property."""
        return self.value

    def to_str(self) -> str:
        """Get stringified property representation."""
        return ", ".join(
            [
                peripheral_tag.label
                for peripheral_tag in PeripheryTag
                if peripheral_tag.tag & self.value
            ]
        )


class AvailableCommandsValue(PropertyValueBase):
    """Available commands property."""

    __slots__ = ("value",)

    @property
    def tags(self) -> List[str]:
        """List of tags representing Available commands."""
        return [
            cmd_tag.tag  # type: ignore
            for cmd_tag in CommandTag
            if cmd_tag.tag > 0 and (1 << cmd_tag.tag - 1) & self.value
        ]

    def __init__(self, tag: int, raw_values: List[int]) -> None:
        """Initialize the AvailableCommands-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(tag)
        self.value = raw_values[0]

    def __contains__(self, item: int) -> bool:
        return isinstance(item, int) and bool((1 << item - 1) & self.value)

    def to_str(self) -> str:
        """Get stringified property representation."""
        return [
            cmd_tag.label  # type: ignore
            for cmd_tag in CommandTag
            if cmd_tag.tag > 0 and (1 << cmd_tag.tag - 1) & self.value
        ]


class IrqNotifierPinValue(PropertyValueBase):
    """IRQ notifier pin property."""

    __slots__ = ("value",)

    @property
    def pin(self) -> int:
        """Number of the pin used for reporting IRQ."""
        return self.value & 0xFF

    @property
    def port(self) -> int:
        """Number of the port used for reporting IRQ."""
        return (self.value >> 8) & 0xFF

    @property
    def enabled(self) -> bool:
        """Indicates whether IRQ reporting is enabled."""
        return bool(self.value & (1 << 32))

    def __init__(self, tag: int, raw_values: List[int]) -> None:
        """Initialize the IrqNotifierPin-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(tag)
        self.value = raw_values[0]

    def __bool__(self) -> bool:
        return self.enabled

    def to_str(self) -> str:
        """Get stringified property representation."""
        return (
            f"IRQ Port[{self.port}], Pin[{self.pin}] is {'enabled' if self.enabled else 'disabled'}"
        )


class ExternalMemoryAttributesValue(PropertyValueBase):
    """Attributes for external memories."""

    __slots__ = (
        "value",
        "mem_id",
        "start_address",
        "total_size",
        "page_size",
        "sector_size",
        "block_size",
    )

    def __init__(self, tag: int, raw_values: List[int], mem_id: int = 0) -> None:
        """Initialize the ExternalMemoryAttributes-based property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        :param mem_id: ID of the external memory
        """
        super().__init__(tag)
        self.mem_id = mem_id
        self.start_address = (
            raw_values[1] if raw_values[0] & ExtMemPropTags.START_ADDRESS.tag else None
        )
        self.total_size = (
            raw_values[2] * 1024 if raw_values[0] & ExtMemPropTags.SIZE_IN_KBYTES.tag else None
        )
        self.page_size = raw_values[3] if raw_values[0] & ExtMemPropTags.PAGE_SIZE.tag else None
        self.sector_size = raw_values[4] if raw_values[0] & ExtMemPropTags.SECTOR_SIZE.tag else None
        self.block_size = raw_values[5] if raw_values[0] & ExtMemPropTags.BLOCK_SIZE.tag else None
        self.value = raw_values[0]

    def to_str(self) -> str:
        """Get stringified property representation."""
        str_values = []
        if self.start_address is not None:
            str_values.append(f"Start Address: 0x{self.start_address:08X}")
        if self.total_size is not None:
            str_values.append(f"Total Size:    {size_fmt(self.total_size)}")
        if self.page_size is not None:
            str_values.append(f"Page Size:     {size_fmt(self.page_size)}")
        if self.sector_size is not None:
            str_values.append(f"Sector Size:   {size_fmt(self.sector_size)}")
        if self.block_size is not None:
            str_values.append(f"Block Size:    {size_fmt(self.block_size)}")
        return ", ".join(str_values)


class FuseLock:
    """Fuse Lock."""

    def __init__(self, index: int, locked: bool) -> None:
        """Initialize object representing information about fuse lock.

        :param index: value of OTP index
        :param locked: status of the lock, true if locked
        """
        self.index = index
        self.locked = locked

    def __str__(self) -> str:
        status = "LOCKED" if self.locked else "UNLOCKED"
        return f"  FUSE{(self.index):03d}: {status}\r\n"


class FuseLockRegister:
    """Fuse Lock Register."""

    def __init__(self, value: int, index: int, start: int = 0) -> None:
        """Initialize object representing the OTP Controller Program Locked Status.

        :param value: value of the register
        :param index: index of the fuse
        :param start: shift to the start of the register

        """
        self.value = value
        self.index = index
        self.msg = ""
        self.bitfields: List[FuseLock] = []

        shift = 0
        for _ in range(start, 32):
            locked = (value >> shift) & 1
            self.bitfields.append(FuseLock(index + shift, bool(locked)))
            shift += 1

    def __str__(self) -> str:
        """Get stringified property representation."""
        if self.bitfields:
            for bitfield in self.bitfields:
                self.msg += str(bitfield)
        return f"\r\n{self.msg}"


class FuseLockedStatus(PropertyValueBase):
    """Class representing FuseLocked registers."""

    __slots__ = ("fuses",)

    def __init__(self, tag: int, raw_values: List[int]) -> None:
        """Initialize the FuseLockedStatus property object.

        :param tag: Property tag, see: `PropertyTag`
        :param raw_values: List of integers representing the property
        """
        super().__init__(tag)
        self.fuses: List[FuseLockRegister] = []
        idx = 0
        for count, val in enumerate(raw_values):
            start = 0
            if count == 0:
                start = 16
            self.fuses.append(FuseLockRegister(val, idx, start))
            idx += 32
            if count == 0:
                idx -= 16

    def to_str(self) -> str:
        """Get stringified property representation."""
        msg = "\r\n"
        for count, register in enumerate(self.fuses):
            msg += f"OTP Controller Program Locked Status {count} Register: {register}"
        return msg

    def get_fuses(self) -> List[FuseLock]:
        """Get list of fuses bitfield objects.

        :return: list of FuseLockBitfield objects
        """
        fuses = []
        for registers in self.fuses:
            fuses.extend(registers.bitfields)
        return fuses


########################################################################################################################
# McuBoot property response parser
########################################################################################################################

PROPERTIES: Dict[PropertyTag, Dict] = {
    PropertyTag.CURRENT_VERSION: {"class": VersionValue, "kwargs": {}},
    PropertyTag.AVAILABLE_PERIPHERALS: {
        "class": AvailablePeripheralsValue,
        "kwargs": {},
    },
    PropertyTag.FLASH_START_ADDRESS: {
        "class": IntValue,
        "kwargs": {"str_format": "hex"},
    },
    PropertyTag.FLASH_SIZE: {"class": IntValue, "kwargs": {"str_format": "size"}},
    PropertyTag.FLASH_SECTOR_SIZE: {
        "class": IntValue,
        "kwargs": {"str_format": "size"},
    },
    PropertyTag.FLASH_BLOCK_COUNT: {"class": IntValue, "kwargs": {"str_format": "dec"}},
    PropertyTag.AVAILABLE_COMMANDS: {"class": AvailableCommandsValue, "kwargs": {}},
    PropertyTag.CRC_CHECK_STATUS: {
        "class": EnumValue,
        "kwargs": {"enum": StatusCode, "na_msg": "Unknown CRC Status code"},
    },
    PropertyTag.VERIFY_WRITES: {
        "class": BoolValue,
        "kwargs": {"true_string": "ON", "false_string": "OFF"},
    },
    PropertyTag.LAST_ERROR: {
        "class": EnumValue,
        "kwargs": {"enum": StatusCode, "na_msg": "Unknown Error"},
    },
    PropertyTag.MAX_PACKET_SIZE: {"class": IntValue, "kwargs": {"str_format": "size"}},
    PropertyTag.RESERVED_REGIONS: {"class": ReservedRegionsValue, "kwargs": {}},
    PropertyTag.VALIDATE_REGIONS: {
        "class": BoolValue,
        "kwargs": {"true_string": "ON", "false_string": "OFF"},
    },
    PropertyTag.RAM_START_ADDRESS: {"class": IntValue, "kwargs": {"str_format": "hex"}},
    PropertyTag.RAM_SIZE: {"class": IntValue, "kwargs": {"str_format": "size"}},
    PropertyTag.SYSTEM_DEVICE_IDENT: {
        "class": IntValue,
        "kwargs": {"str_format": "hex"},
    },
    PropertyTag.FLASH_SECURITY_STATE: {
        "class": BoolValue,
        "kwargs": {
            "true_values": (0x00000000, 0x5AA55AA5),
            "true_string": "UNSECURE",
            "false_values": (0x00000001, 0xC33CC33C),
            "false_string": "SECURE",
        },
    },
    PropertyTag.UNIQUE_DEVICE_IDENT: {"class": DeviceUidValue, "kwargs": {}},
    PropertyTag.FLASH_FAC_SUPPORT: {
        "class": BoolValue,
        "kwargs": {"true_string": "ON", "false_string": "OFF"},
    },
    PropertyTag.FLASH_ACCESS_SEGMENT_SIZE: {
        "class": IntValue,
        "kwargs": {"str_format": "size"},
    },
    PropertyTag.FLASH_ACCESS_SEGMENT_COUNT: {
        "class": IntValue,
        "kwargs": {"str_format": "int32"},
    },
    PropertyTag.FLASH_READ_MARGIN: {
        "class": EnumValue,
        "kwargs": {"enum": FlashReadMargin, "na_msg": "Unknown Margin"},
    },
    PropertyTag.QSPI_INIT_STATUS: {
        "class": EnumValue,
        "kwargs": {"enum": StatusCode, "na_msg": "Unknown Error"},
    },
    PropertyTag.TARGET_VERSION: {"class": VersionValue, "kwargs": {}},
    PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES: {
        "class": ExternalMemoryAttributesValue,
        "kwargs": {"mem_id": None},
    },
    PropertyTag.RELIABLE_UPDATE_STATUS: {
        "class": EnumValue,
        "kwargs": {"enum": StatusCode, "na_msg": "Unknown Error"},
    },
    PropertyTag.FLASH_PAGE_SIZE: {"class": IntValue, "kwargs": {"str_format": "size"}},
    PropertyTag.IRQ_NOTIFIER_PIN: {"class": IrqNotifierPinValue, "kwargs": {}},
    PropertyTag.PFR_KEYSTORE_UPDATE_OPT: {
        "class": EnumValue,
        "kwargs": {"enum": PfrKeystoreUpdateOpt, "na_msg": "Unknown"},
    },
    PropertyTag.BYTE_WRITE_TIMEOUT_MS: {
        "class": IntValue,
        "kwargs": {"str_format": "dec"},
    },
    PropertyTag.FUSE_LOCKED_STATUS: {
        "class": FuseLockedStatus,
        "kwargs": {},
    },
}

PROPERTIES_KW45XX = {
    PropertyTagKw45xx.VERIFY_ERASE: {
        "class": BoolValue,
        "kwargs": {"true_string": "ENABLE", "false_string": "DISABLE"},
    },
    PropertyTagKw45xx.BOOT_STATUS_REGISTER: {
        "class": IntValue,
        "kwargs": {"str_format": "int32"},
    },
    PropertyTagKw45xx.FIRMWARE_VERSION: {
        "class": IntValue,
        "kwargs": {"str_format": "int32"},
    },
    PropertyTagKw45xx.FUSE_PROGRAM_VOLTAGE: {
        "class": BoolValue,
        "kwargs": {
            "true_string": "Over Drive Voltage (2.5 V)",
            "false_string": "Normal Voltage (1.8 V)",
        },
    },
}

PROPERTIES_OVERRIDE = {"kw45xx": PROPERTIES_KW45XX, "k32w1xx": PROPERTIES_KW45XX}
PROPERTY_TAG_OVERRIDE = {"kw45xx": PropertyTagKw45xx, "k32w1xx": PropertyTagKw45xx}


def parse_property_value(
    property_tag: int,
    raw_values: List[int],
    ext_mem_id: Optional[int] = None,
    family: Optional[str] = None,
) -> Optional[PropertyValueBase]:
    """Parse the property value received from the device.

    :param property_tag: Tag representing the property
    :param raw_values: Data received from the device
    :param ext_mem_id: ID of the external memory used to read the property, defaults to None
    :param family: supported family
    :return: Object representing the property
    """
    assert isinstance(property_tag, int)
    assert isinstance(raw_values, list)
    properties_dict = deepcopy(PROPERTIES)
    if family:
        properties_dict.update(PROPERTIES_OVERRIDE[family])  # type: ignore
    if property_tag not in list(properties_dict.keys()):
        return None
    property_value = next(
        value for key, value in properties_dict.items() if key.tag == property_tag
    )
    cls: Callable = property_value["class"]
    kwargs: dict = property_value["kwargs"]
    if "mem_id" in kwargs:
        kwargs["mem_id"] = ext_mem_id
    obj = cls(property_tag, raw_values, **kwargs)
    if family:
        property_tag_override = PROPERTY_TAG_OVERRIDE[family].from_tag(property_tag)
        obj.name = property_tag_override.label
        obj.desc = property_tag_override.description
    return obj
