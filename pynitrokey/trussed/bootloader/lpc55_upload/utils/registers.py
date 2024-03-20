#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle registers descriptions with support for XML files."""

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union
from xml.dom import minidom

from ..exceptions import SPSDKError, SPSDKValueError
from ..utils.exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)
from ..utils.images import BinaryImage, BinaryPattern
from ..utils.misc import (
    Endianness,
    format_value,
    get_bytes_cnt_of_int,
    value_to_bool,
    value_to_bytes,
    value_to_int,
    write_file,
)

HTMLDataElement = Mapping[str, Union[str, dict, list]]
HTMLData = List[HTMLDataElement]

logger = logging.getLogger(__name__)


class RegsEnum:
    """Storage for register enumerations."""

    def __init__(self, name: str, value: Any, description: str, max_width: int = 0) -> None:
        """Constructor of RegsEnum class. Used to store enumeration information of bitfield.

        :param name: Name of enumeration.
        :param value: Value of enumeration.
        :param description: Text description of enumeration.
        :param max_width: Maximal width of enum value used to format output
        :raises SPSDKRegsError: Invalid input value.
        """
        self.name = name or "N/A"
        try:
            self.value = value_to_int(value)
        except (TypeError, ValueError, SPSDKError) as exc:
            raise SPSDKRegsError(f"Invalid Enum Value: {value}") from exc
        self.description = description or "N/A"
        self.max_width = max_width

    @classmethod
    def from_xml_element(cls, xml_element: ET.Element, maxwidth: int = 0) -> "RegsEnum":
        """Initialization Enum by XML ET element.

        :param xml_element: Input XML subelement with enumeration data.
        :param maxwidth: The maximal width of bitfield for this enum (used for formatting).
        :return: The instance of this class.
        :raises SPSDKRegsError: Error during enum XML parsing.
        """
        name = xml_element.attrib.get("name", "N/A")
        if "value" not in xml_element.attrib:
            raise SPSDKRegsError(f"Missing Enum Value Key for {name}.")

        raw_val = xml_element.attrib["value"]
        try:
            value = value_to_int(raw_val)
        except (TypeError, ValueError, SPSDKError) as exc:
            raise SPSDKRegsError(f"Invalid Enum Value: {raw_val}") from exc

        description = xml_element.attrib.get("description", "N/A").replace("&#10;", "\n")

        return cls(name, value, description, maxwidth)

    def get_value_int(self) -> int:
        """Method returns Integer value of enum.

        :return: Integer value of Enum.
        """
        return self.value

    def get_value_str(self) -> str:
        """Method returns formatted value.

        :return: Formatted string with enum value.
        """
        return format_value(self.value, self.max_width)

    def add_et_subelement(self, parent: ET.Element) -> None:
        """Creates the register XML structure in ElementTree.

        :param parent: The parent object of ElementTree.
        """
        element = ET.SubElement(parent, "bit_field_value")
        element.set("name", self.name)
        element.set("value", self.get_value_str())
        element.set("description", self.description)

    def __str__(self) -> str:
        """Overrides 'ToString()' to print register.

        :return: Friendly string with enum information.
        """
        output = ""
        output += f"Name:        {self.name}\n"
        output += f"Value:       {self.get_value_str()}\n"
        output += f"Description: {self.description}\n"

        return output


class ConfigProcessor:
    """Base class for processing configuration data."""

    NAME = "NOP"

    def __init__(self, description: str = "") -> None:
        """Initialize the processor."""
        self.description = description

    def pre_process(self, value: int) -> int:
        """Pre-process value coming from config file."""
        return value

    def post_process(self, value: int) -> int:
        """Post-process value going to config file."""
        return value

    def width_update(self, value: int) -> int:
        """Update bit-width of value going to config file."""
        return value

    @classmethod
    def get_method_name(cls, config_string: str) -> str:
        """Return config processor method name."""
        return config_string.split(":")[0]

    @classmethod
    def get_params(cls, config_string: str) -> Dict[str, int]:
        """Return config processor method parameters."""

        def split_params(param: str) -> Tuple[str, str]:
            """Split key=value pair into a tuple."""
            parts = param.split("=")
            if len(parts) != 2:
                raise SPSDKRegsError(
                    f"Invalid param setting: '{param}'. Expected format '<name>=<value>'"
                )
            return (parts[0], parts[1])

        parts = config_string.split(";", maxsplit=1)[0].split(":")
        if len(parts) == 1:
            return {}
        params = parts[1].split(",")
        params_dict: Dict[str, str] = dict(split_params(p) for p in params)
        return {key.lower(): value_to_int(value) for key, value in params_dict.items()}

    @classmethod
    def get_description(cls, config_string: str) -> str:
        """Return extra description for config processor."""
        parts = config_string.partition(";")
        return parts[2].replace("DESC=", "")

    @classmethod
    def from_str(cls, config_string: str) -> "ConfigProcessor":
        """Create config processor instance from configuration string."""
        return cls(config_string)

    @classmethod
    def from_xml(cls, element: ET.Element) -> Optional["ConfigProcessor"]:
        """Create config processor from XML data entry."""
        processor_node = element.find("alias[@type='CONFIG_PREPROCESS']")
        if processor_node is None:
            return None
        if "value" not in processor_node.attrib:
            raise SPSDKRegsError("CONFIG_PREPROCESS alias node doesn't have a value")
        config_string = processor_node.attrib["value"]
        method_name = cls.get_method_name(config_string=config_string)
        for klass in cls.__subclasses__():
            if klass.NAME == method_name:
                return klass.from_str(config_string=config_string)
        return None


class ShiftRightConfigProcessor(ConfigProcessor):
    """Config processor performing the right-shift operation."""

    NAME = "SHIFT_RIGHT"

    def __init__(self, count: int, description: str = "") -> None:
        """Initialize the right-shift config processor.

        :param count: Count of bit for shift operation
        :param description: Extra description for config processor, defaults to ""
        """
        super().__init__(
            description=description or f"Actual binary value is shifted by {count} bits to right."
        )
        self.count = count

    def pre_process(self, value: int) -> int:
        """Pre-process value coming from config file."""
        return value >> self.count

    def post_process(self, value: int) -> int:
        """Post-process value going to config file."""
        return value << self.count

    def width_update(self, value: int) -> int:
        """Update bit-width of value going to config file."""
        return value + self.count

    @classmethod
    def from_str(cls, config_string: str) -> "ShiftRightConfigProcessor":
        """Create config processor instance from configuration string."""
        name = cls.get_method_name(config_string=config_string)
        if name != cls.NAME:
            raise SPSDKRegsError(f"Invalid method name '{name}' expected {cls.NAME}")
        params = cls.get_params(config_string=config_string)
        if "count" not in params:
            raise SPSDKRegsError(f"{cls.NAME} requires the COUNT parameter")
        description = cls.get_description(config_string=config_string)
        return cls(count=value_to_int(params["count"]), description=description)


class RegsBitField:
    """Storage for register bitfields."""

    def __init__(
        self,
        parent: "RegsRegister",
        name: str,
        offset: int,
        width: int,
        description: Optional[str] = None,
        reset_val: Any = "0",
        access: str = "RW",
        hidden: bool = False,
        config_processor: Optional[ConfigProcessor] = None,
    ) -> None:
        """Constructor of RegsBitField class. Used to store bitfield information.

        :param parent: Parent register of bitfield.
        :param name: Name of bitfield.
        :param offset: Bit offset of bitfield.
        :param width: Bit width of bitfield.
        :param description: Text description of bitfield.
        :param reset_val: Reset value of bitfield.
        :param access: Access type of bitfield.
        :param hidden: The bitfield will be hidden from standard searches.
        """
        self.parent = parent
        self.name = name or "N/A"
        self.offset = offset
        self.width = width
        self.description = description or "N/A"
        self.reset_value = value_to_int(reset_val, 0)
        self.access = access
        self.hidden = hidden
        self._enums: List[RegsEnum] = []
        self.config_processor = config_processor or ConfigProcessor()
        self.config_width = self.config_processor.width_update(width)
        self.set_value(self.reset_value, raw=True)

    @classmethod
    def from_xml_element(cls, xml_element: ET.Element, parent: "RegsRegister") -> "RegsBitField":
        """Initialization register by XML ET element.

        :param xml_element: Input XML subelement with register data.
        :param parent: Reference to parent RegsRegister object.
        :return: The instance of this class.
        """
        name = xml_element.attrib.get("name", "N/A")
        offset = value_to_int(xml_element.attrib.get("offset", 0))
        width = value_to_int(xml_element.attrib.get("width", 0))
        description = xml_element.attrib.get("description", "N/A").replace("&#10;", "\n")
        access = xml_element.attrib.get("access", "R/W")
        reset_value = value_to_int(xml_element.attrib.get("reset_value", 0))
        hidden = xml_element.tag != "bit_field"
        config_processor = ConfigProcessor.from_xml(xml_element)

        bitfield = cls(
            parent, name, offset, width, description, reset_value, access, hidden, config_processor
        )

        for xml_enum in xml_element.findall("bit_field_value"):
            bitfield.add_enum(RegsEnum.from_xml_element(xml_enum, width))

        return bitfield

    def has_enums(self) -> bool:
        """Returns if the bitfields has enums.

        :return: True is has enums, False otherwise.
        """
        return len(self._enums) > 0

    def get_enums(self) -> List[RegsEnum]:
        """Returns bitfield enums.

        :return: List of bitfield enumeration values.
        """
        return self._enums

    def add_enum(self, enum: RegsEnum) -> None:
        """Add bitfield enum.

        :param enum: New enumeration value for bitfield.
        """
        self._enums.append(enum)

    def get_value(self) -> int:
        """Returns integer value of the bitfield.

        :return: Current value of bitfield.
        """
        reg_val = self.parent.get_value(raw=False)
        value = reg_val >> self.offset
        mask = (1 << self.width) - 1
        value = value & mask
        value = self.config_processor.post_process(value)
        return value

    def get_reset_value(self) -> int:
        """Returns integer reset value of the bitfield.

        :return: Reset value of bitfield.
        """
        return self.reset_value

    def set_value(self, new_val: Any, raw: bool = False) -> None:
        """Updates the value of the bitfield.

        :param new_val: New value of bitfield.
        :param raw: If set, no automatic modification of value is applied.
        :raises SPSDKValueError: The input value is out of range.
        """
        new_val_int = value_to_int(new_val)
        new_val_int = self.config_processor.pre_process(new_val_int)
        if new_val_int > 1 << self.width:
            raise SPSDKValueError("The input value is out of bitfield range")
        reg_val = self.parent.get_value(raw=raw)

        mask = ((1 << self.width) - 1) << self.offset
        reg_val = reg_val & ~mask
        value = (new_val_int << self.offset) & mask
        reg_val = reg_val | value
        self.parent.set_value(reg_val, raw)

    def set_enum_value(self, new_val: str, raw: bool = False) -> None:
        """Updates the value of the bitfield by its enum value.

        :param new_val: New enum value of bitfield.
        :param raw: If set, no automatic modification of value is applied.
        :raises SPSDKRegsErrorEnumNotFound: Input value cannot be decoded.
        """
        try:
            val_int = self.get_enum_constant(new_val)
        except SPSDKRegsErrorEnumNotFound:
            # Try to decode standard input
            try:
                val_int = value_to_int(new_val)
            except TypeError:
                raise SPSDKRegsErrorEnumNotFound  # pylint: disable=raise-missing-from
        self.set_value(val_int, raw)

    def get_enum_value(self) -> Union[str, int]:
        """Returns enum value of the bitfield.

        :return: Current value of bitfield.
        """
        value = self.get_value()
        for enum in self._enums:
            if enum.get_value_int() == value:
                return enum.name
        # return value
        return self.get_hex_value()

    def get_hex_value(self) -> str:
        """Get the value of register in string hex format.

        :return: Hexadecimal value of register.
        """
        fmt = f"0{self.config_width // 4}X"
        val = f"0x{format(self.get_value(), fmt)}"
        return val

    def get_enum_constant(self, enum_name: str) -> int:
        """Returns constant representation of enum by its name.

        :return: Constant of enum.
        :raises SPSDKRegsErrorEnumNotFound: The enum has not been found.
        """
        for enum in self._enums:
            if enum.name == enum_name:
                return enum.get_value_int()

        raise SPSDKRegsErrorEnumNotFound(f"The enum for {enum_name} has not been found.")

    def get_enum_names(self) -> List[str]:
        """Returns list of the enum strings.

        :return: List of enum names.
        """
        return [x.name for x in self._enums]

    def add_et_subelement(self, parent: ET.Element) -> None:
        """Creates the register XML structure in ElementTree.

        :param parent: The parent object of ElementTree.
        """
        element = ET.SubElement(parent, "reserved_bit_field" if self.hidden else "bit_field")
        element.set("offset", hex(self.offset))
        element.set("width", str(self.width))
        element.set("name", self.name)
        element.set("access", self.access)
        element.set("reset_value", format_value(self.reset_value, self.width))
        element.set("description", self.description)
        for enum in self._enums:
            enum.add_et_subelement(element)

    def __str__(self) -> str:
        """Override 'ToString()' to print register.

        :return: Friendly looking string that describes the bitfield.
        """
        output = ""
        output += f"Name:     {self.name}\n"
        output += f"Offset:   {self.offset} bits\n"
        output += f"Width:    {self.width} bits\n"
        output += f"Access:   {self.access} bits\n"
        output += f"Reset val:{self.reset_value}\n"
        output += f"Description: \n {self.description}\n"
        if self.hidden:
            output += "This is hidden bitfield!\n"

        i = 0
        for enum in self._enums:
            output += f"Enum             #{i}: \n" + str(enum)
            i += 1

        return output


class RegsRegister:
    """Initialization register by input information."""

    def __init__(
        self,
        name: str,
        offset: int,
        width: int,
        description: Optional[str] = None,
        reverse: bool = False,
        access: Optional[str] = None,
        config_as_hexstring: bool = False,
        otp_index: Optional[int] = None,
        reverse_subregs_order: bool = False,
        base_endianness: Endianness = Endianness.BIG,
        alt_widths: Optional[List[int]] = None,
    ) -> None:
        """Constructor of RegsRegister class. Used to store register information.

        :param name: Name of register.
        :param offset: Byte offset of register.
        :param width: Bit width of register.
        :param description: Text description of register.
        :param reverse: Multi byte register value could be printed in reverse order.
        :param access: Access type of register.
        :param config_as_hexstring: Config is stored as a hex string.
        :param otp_index: Index of OTP fuse.
        :param reverse_subregs_order: Reverse order of sub registers.
        :param base_endianness: Base endianness for bytes import/export of value.
        :param alt_widths: List of alternative widths.
        """
        if width % 8 != 0:
            raise SPSDKValueError("SPSDK Register supports only widths in multiply 8 bits.")
        self.name = name
        self.offset = offset
        self.width = width
        self.description = description or "N/A"
        self.access = access or "RW"
        self.reverse = reverse
        self._bitfields: List[RegsBitField] = []
        self._set_value_hooks: List = []
        self._value = 0
        self._reset_value = 0
        self.config_as_hexstring = config_as_hexstring
        self.otp_index = otp_index
        self.reverse_subregs_order = reverse_subregs_order
        self.base_endianness = base_endianness
        self.alt_widths = alt_widths
        self._alias_names: List[str] = []

        # Grouped register members
        self.sub_regs: List["RegsRegister"] = []
        self._sub_regs_width_init = False
        self._sub_regs_width = 0

    def __eq__(self, obj: Any) -> bool:
        """Compare if the objects has same settings."""
        if not isinstance(obj, self.__class__):
            return False
        if obj.name != self.name:
            return False
        if obj.width != self.width:
            return False
        if obj.reverse != self.reverse:
            return False
        if obj._value != self._value:
            return False
        if obj._reset_value != self._reset_value:
            return False
        return True

    @classmethod
    def from_xml_element(cls, xml_element: ET.Element) -> "RegsRegister":
        """Initialization register by XML ET element.

        :param xml_element: Input XML subelement with register data.
        :return: The instance of this class.
        """
        name = xml_element.attrib.get("name", "N/A")
        offset = value_to_int(xml_element.attrib.get("offset", 0))
        width = value_to_int(xml_element.attrib.get("width", 0))
        description = xml_element.attrib.get("description", "N/A").replace("&#10;", "\n")
        reverse = (xml_element.attrib.get("reversed", "False")) == "True"
        access = xml_element.attrib.get("access", "N/A")
        otp_index_raw = xml_element.attrib.get("otp_index")
        otp_index = None
        if otp_index_raw:
            otp_index = value_to_int(otp_index_raw)
        reg = cls(
            name,
            offset,
            width,
            description,
            reverse,
            access,
            otp_index=otp_index,
        )
        value = xml_element.attrib.get("value")
        if value:
            reg.set_value(value)

        if xml_element.text:
            xml_bitfields = xml_element.findall("bit_field")
            xml_bitfields.extend(xml_element.findall("reserved_bit_field"))
            xml_bitfields_len = len(xml_bitfields)
            for xml_bitfield in xml_bitfields:
                bitfield = RegsBitField.from_xml_element(xml_bitfield, reg)
                if (
                    xml_bitfields_len == 1
                    and bitfield.width == reg.width
                    and not bitfield.has_enums()
                ):
                    if len(reg.description) < len(bitfield.description):
                        reg.description = bitfield.description
                    reg.access = bitfield.access
                    reg._reset_value = bitfield.reset_value
                else:
                    if reg.access == "N/A":
                        reg.access = "Bitfields depended"
                    reg.add_bitfield(bitfield)
        return reg

    def add_alias(self, alias: str) -> None:
        """Add alias name to register.

        :param alias: Register name alias.
        """
        if not alias in self._alias_names:
            self._alias_names.append(alias)

    def has_group_registers(self) -> bool:
        """Returns true if register is compounded from sub-registers.

        :return: True if register has sub-registers, False otherwise.
        """
        return len(self.sub_regs) > 0

    def add_group_reg(self, reg: "RegsRegister") -> None:
        """Add group element for this register.

        :param reg: Register member of this register group.
        :raises SPSDKRegsErrorRegisterGroupMishmash: When any inconsistency is detected.
        """
        first_member = not self.has_group_registers()
        if first_member:
            if self.offset == 0:
                self.offset = reg.offset
            if self.width == 0:
                self.width = reg.width
            else:
                self._sub_regs_width_init = True
                self._sub_regs_width = reg.width
            if self.access == "RW":
                self.access = reg.access
        else:
            # There is strong rule that supported group MUST be in one row in memory!
            if not self._sub_regs_width_init:
                if self.offset + self.width // 8 != reg.offset:
                    raise SPSDKRegsErrorRegisterGroupMishmash(
                        f"The register {reg.name} doesn't follow the previous one."
                    )
                self.width += reg.width
            else:
                if self.offset + self.width // 8 <= reg.offset:
                    raise SPSDKRegsErrorRegisterGroupMishmash(
                        f"The register {reg.name} doesn't follow the previous one."
                    )
                self._sub_regs_width += reg.width
                if self._sub_regs_width > self.width:
                    raise SPSDKRegsErrorRegisterGroupMishmash(
                        f"The register {reg.name} bigger width than is defined."
                    )
            if self.sub_regs[0].width != reg.width:
                raise SPSDKRegsErrorRegisterGroupMishmash(
                    f"The register {reg.name} has different width."
                )
            if self.access != reg.access:
                raise SPSDKRegsErrorRegisterGroupMishmash(
                    f"The register {reg.name} has different access type."
                )
        reg.base_endianness = self.base_endianness
        self.sub_regs.append(reg)

    def add_et_subelement(self, parent: ET.Element) -> None:
        """Creates the register XML structure in ElementTree.

        :param parent: The parent object of ElementTree.
        """
        element = ET.SubElement(parent, "register")
        element.set("offset", hex(self.offset))
        element.set("width", str(self.width))
        element.set("name", self.name)
        element.set("reversed", str(self.reverse))
        element.set("description", self.description)
        if self.otp_index:
            element.set("otp_index", str(self.otp_index))
        for bitfield in self._bitfields:
            bitfield.add_et_subelement(element)

    def set_value(self, val: Any, raw: bool = False) -> None:
        """Set the new value of register.

        :param val: The new value to set.
        :param raw: Do not use any modification hooks.
        :raises SPSDKError: When invalid values is loaded into register
        """
        try:
            if isinstance(val, (bytes, bytearray)):
                value = int.from_bytes(val, self.base_endianness.value)
            else:
                value = value_to_int(val)
            if value >= 1 << self.width:
                raise SPSDKError(
                    f"Input value {value} doesn't fit into register of width {self.width}."
                )

            alt_width = self.get_alt_width(value)

            if not raw:
                for hook in self._set_value_hooks:
                    value = hook[0](value, hook[1])
                if self.reverse:
                    # The value_to_int internally is using BIG endian
                    val_bytes = value_to_bytes(
                        value,
                        align_to_2n=False,
                        byte_cnt=alt_width // 8,
                        endianness=Endianness.BIG,
                    )
                    value = value.from_bytes(val_bytes, Endianness.LITTLE.value)

            if self.has_group_registers():
                # Update also values in sub registers
                subreg_width = self.sub_regs[0].width
                sub_regs = self.sub_regs[: alt_width // subreg_width]
                for index, sub_reg in enumerate(sub_regs, start=1):
                    if self.reverse_subregs_order:
                        bit_pos = alt_width - index * subreg_width
                    else:
                        bit_pos = (index - 1) * subreg_width

                    sub_reg.set_value((value >> bit_pos) & ((1 << subreg_width) - 1), raw=raw)
            else:
                self._value = value

        except SPSDKError as exc:
            raise SPSDKError(f"Loaded invalid value {str(val)}") from exc

    def reset_value(self, raw: bool = False) -> None:
        """Reset the value of register.

        :param raw: Do not use any modification hooks.
        """
        self.set_value(self.get_reset_value(), raw)

    def get_alt_width(self, value: int) -> int:
        """Get alternative width of register.

        :param value: Input value to recognize width
        :return: Current width
        """
        alt_width = self.width
        if self.alt_widths:
            real_byte_cnt = get_bytes_cnt_of_int(value, align_to_2n=False)
            self.alt_widths.sort()
            for alt in self.alt_widths:
                if real_byte_cnt <= alt // 8:
                    alt_width = alt
                    break
        return alt_width

    def get_value(self, raw: bool = False) -> int:
        """Get the value of register.

        :param raw: Do not use any modification hooks.
        """
        if self.has_group_registers():
            # Update local value, by the sub register values
            subreg_width = self.sub_regs[0].width
            sub_regs_value = 0
            for index, sub_reg in enumerate(self.sub_regs, start=1):
                if self.reverse_subregs_order:
                    bit_pos = self.width - index * subreg_width
                else:
                    bit_pos = (index - 1) * subreg_width
                sub_regs_value |= sub_reg.get_value(raw=raw) << (bit_pos)
            value = sub_regs_value
        else:
            value = self._value

        alt_width = self.get_alt_width(value)

        if not raw and self.reverse:
            val_bytes = value_to_bytes(
                value,
                align_to_2n=False,
                byte_cnt=alt_width // 8,
                endianness=self.base_endianness,
            )
            value = value.from_bytes(
                val_bytes,
                Endianness.BIG.value
                if self.base_endianness == Endianness.LITTLE
                else Endianness.LITTLE.value,
            )

        return value

    def get_bytes_value(self, raw: bool = False) -> bytes:
        """Get the bytes value of register.

        :param raw: Do not use any modification hooks.
        :return: Register value in bytes.
        """
        value = self.get_value(raw=raw)
        return value_to_bytes(
            value,
            align_to_2n=False,
            byte_cnt=self.get_alt_width(value) // 8,
            endianness=self.base_endianness,
        )

    def get_hex_value(self, raw: bool = False) -> str:
        """Get the value of register in string hex format.

        :param raw: Do not use any modification hooks.
        :return: Hexadecimal value of register.
        """
        val_int = self.get_value(raw=raw)
        count = "0" + str(self.get_alt_width(val_int) // 4)
        value = f"{val_int:{count}X}"
        if not self.config_as_hexstring:
            value = "0x" + value
        return value

    def get_reset_value(self) -> int:
        """Returns reset value of the register.

        :return: Reset value of register.
        """
        value = self._reset_value
        for bitfield in self._bitfields:
            width = bitfield.width
            offset = bitfield.offset
            val = bitfield.reset_value
            value |= (val & ((1 << width) - 1)) << offset

        return value

    def add_bitfield(self, bitfield: RegsBitField) -> None:
        """Add register bitfield.

        :param bitfield: New bitfield value for register.
        """
        self._bitfields.append(bitfield)

    def get_bitfields(self, exclude: Optional[List[str]] = None) -> List[RegsBitField]:
        """Returns register bitfields.

        Method allows exclude some bitfields by their names.
        :param exclude: Exclude list of bitfield names if needed.
        :return: Returns List of register bitfields.
        """
        ret = []
        for bitf in self._bitfields:
            if bitf.hidden:
                continue
            if exclude and bitf.name.startswith(tuple(exclude)):
                continue
            ret.append(bitf)
        return ret

    def get_bitfield_names(self, exclude: Optional[List[str]] = None) -> List[str]:
        """Returns list of the bitfield names.

        :param exclude: Exclude list of bitfield names if needed.
        :return: List of bitfield names.
        """
        return [x.name for x in self.get_bitfields(exclude)]

    def find_bitfield(self, name: str) -> RegsBitField:
        """Returns the instance of the bitfield by its name.

        :param name: The name of the bitfield.
        :return: Instance of the bitfield.
        :raises SPSDKRegsErrorBitfieldNotFound: The bitfield doesn't exist.
        """
        for bitfield in self._bitfields:
            if name == bitfield.name:
                return bitfield

        raise SPSDKRegsErrorBitfieldNotFound(f" The {name} is not found in register {self.name}.")

    def add_setvalue_hook(self, hook: Callable, context: Optional[Any] = None) -> None:
        """Set the value hook for write operation.

        :param hook: Callable hook for set value operation.
        :param context: Context data for this hook.
        """
        self._set_value_hooks.append((hook, context))

    def __str__(self) -> str:
        """Override 'ToString()' to print register.

        :return: Friendly looking string that describes the register.
        """
        output = ""
        output += f"Name:   {self.name}\n"
        output += f"Offset: 0x{self.offset:04X}\n"
        output += f"Width:  {self.width} bits\n"
        output += f"Access:   {self.access}\n"
        output += f"Description: \n {self.description}\n"
        if self.otp_index:
            output += f"OTP Word: \n {self.otp_index}\n"

        i = 0
        for bitfield in self._bitfields:
            output += f"Bitfield #{i}: \n" + str(bitfield)
            i += 1

        return output


class Registers:
    """SPSDK Class for registers handling."""

    TEMPLATE_NOTE = (
        "All registers is possible to define also as one value although the bitfields are used. "
        "Instead of bitfields: ... field, the value: ... definition works as well."
    )

    def __init__(self, device_name: str, base_endianness: Endianness = Endianness.BIG) -> None:
        """Initialization of Registers class."""
        self._registers: List[RegsRegister] = []
        self.dev_name = device_name
        self.base_endianness = base_endianness

    def __eq__(self, obj: Any) -> bool:
        """Compare if the objects has same settings."""
        if not (
            isinstance(obj, self.__class__)
            and obj.dev_name == self.dev_name
            and obj.base_endianness == self.base_endianness
        ):
            return False
        ret = obj._registers == self._registers
        return ret

    def find_reg(self, name: str, include_group_regs: bool = False) -> RegsRegister:
        """Returns the instance of the register by its name.

        :param name: The name of the register.
        :param include_group_regs: The algorithm will check also group registers.
        :return: Instance of the register.
        :raises SPSDKRegsErrorRegisterNotFound: The register doesn't exist.
        """
        for reg in self._registers:
            if name == reg.name:
                return reg
            if name in reg._alias_names:
                return reg
            if include_group_regs and reg.has_group_registers():
                for sub_reg in reg.sub_regs:
                    if name == sub_reg.name:
                        return sub_reg

        raise SPSDKRegsErrorRegisterNotFound(
            f"The {name} is not found in loaded registers for {self.dev_name} device."
        )

    def add_register(self, reg: RegsRegister) -> None:
        """Adds register into register list.

        :param reg: Register to add to the class.
        :raises SPSDKError: Invalid type has been provided.
        :raises SPSDKRegsError: Cannot add register with same name
        """
        if not isinstance(reg, RegsRegister):
            raise SPSDKError("The 'reg' has invalid type.")

        if reg.name in self.get_reg_names():
            raise SPSDKRegsError(f"Cannot add register with same name: {reg.name}.")

        for idx, register in enumerate(self._registers):
            # TODO solve problem with group register that are always at 0 offset
            if register.offset == reg.offset != 0:
                logger.debug(
                    f"Found register at the same offset {hex(reg.offset)}"
                    f", adding {reg.name} as an alias to {register.name}"
                )
                self._registers[idx].add_alias(reg.name)
                self._registers[idx]._bitfields.extend(reg._bitfields)
                return
        # update base endianness for all registers in group
        reg.base_endianness = self.base_endianness
        self._registers.append(reg)

    def remove_registers(self) -> None:
        """Remove all registers."""
        self._registers.clear()

    def get_registers(
        self, exclude: Optional[List[str]] = None, include_group_regs: bool = False
    ) -> List[RegsRegister]:
        """Returns list of the registers.

        Method allows exclude some register by their names.
        :param exclude: Exclude list of register names if needed.
        :param include_group_regs: The algorithm will check also group registers.
        :return: List of register names.
        """
        if exclude:
            regs = [r for r in self._registers if not r.name.startswith(tuple(exclude))]
        else:
            regs = self._registers.copy()
        if include_group_regs:
            sub_regs = []
            for reg in regs:
                if reg.has_group_registers():
                    sub_regs.extend(reg.sub_regs)
            regs.extend(sub_regs)

        return regs

    def get_reg_names(
        self, exclude: Optional[List[str]] = None, include_group_regs: bool = False
    ) -> List[str]:
        """Returns list of the register names.

        :param exclude: Exclude list of register names if needed.
        :param include_group_regs: The algorithm will check also group registers.
        :return: List of register names.
        """
        return [x.name for x in self.get_registers(exclude, include_group_regs)]

    def reset_values(self, exclude: Optional[List[str]] = None) -> None:
        """The method reset values in registers.

        :param exclude: The list of register names to be excluded.
        """
        for reg in self.get_registers(exclude):
            reg.reset_value(True)

    def __str__(self) -> str:
        """Override 'ToString()' to print register.

        :return: Friendly looking string that describes the registers.
        """
        output = ""
        output += "Device name:        " + self.dev_name + "\n"
        for reg in self._registers:
            output += str(reg) + "\n"

        return output

    def write_xml(self, file_name: str) -> None:
        """Write loaded register structures into XML file.

        :param file_name: The name of XML file that should be created.
        """
        xml_root = ET.Element("regs")
        for reg in self._registers:
            reg.add_et_subelement(xml_root)

        no_pretty_data = minidom.parseString(
            ET.tostring(xml_root, encoding="unicode", short_empty_elements=False)
        )
        write_file(no_pretty_data.toprettyxml(), file_name, encoding="utf-8")

    def image_info(
        self, size: int = 0, pattern: BinaryPattern = BinaryPattern("zeros")
    ) -> BinaryImage:
        """Export Registers into  binary information.

        :param size: Result size of Image, 0 means automatic minimal size.
        :param pattern: Pattern of gaps, defaults to "zeros"
        """
        image = BinaryImage(self.dev_name, size=size, pattern=pattern)
        for reg in self._registers:
            description = reg.description
            if reg._alias_names:
                description += f"\n Alias names: {', '.join(reg._alias_names)}"
            image.add_image(
                BinaryImage(
                    reg.name,
                    reg.width // 8,
                    offset=reg.offset,
                    description=description,
                    binary=reg.get_bytes_value(raw=True),
                )
            )

        return image

    def export(self, size: int = 0, pattern: BinaryPattern = BinaryPattern("zeros")) -> bytes:
        """Export Registers into binary.

        :param size: Result size of Image, 0 means automatic minimal size.
        :param pattern: Pattern of gaps, defaults to "zeros"
        """
        return self.image_info(size, pattern).export()

    def parse(self, binary: bytes) -> None:
        """Parse the binary data values into loaded registers.

        :param binary: Binary data to parse.
        """
        bin_len = len(binary)
        if bin_len < len(self.image_info()):
            logger.info(
                f"Input binary is smaller than registers supports: {bin_len} != {len(self.image_info())}"
            )
        for reg in self.get_registers():
            if bin_len < reg.offset + reg.width // 8:
                logger.debug(f"Parsing of binary block ends at {reg.name}")
                break
            reg.set_value(binary[reg.offset : reg.offset + reg.width // 8], raw=True)

    def _get_bitfield_yaml_description(self, bitfield: RegsBitField) -> str:
        """Create the valuable comment for bitfield.

        :param bitfield: Bitfield used to generate description.
        :return: Bitfield description.
        """
        description = f"Offset: {bitfield.offset}b, Width: {bitfield.config_width}b"
        if bitfield.description not in ("", "."):
            description += ", " + bitfield.description.replace("&#10;", "\n")
        if bitfield.config_processor.description:
            description += ".\n NOTE: " + bitfield.config_processor.description
        if bitfield.has_enums():
            for enum in bitfield.get_enums():
                descr = enum.description if enum.description != "." else enum.name
                enum_description = descr.replace("&#10;", "\n")
                description += f"\n- {enum.name}, ({enum.get_value_int()}): {enum_description}"
        return description

    def get_validation_schema(self) -> Dict:
        """Get the JSON SCHEMA for registers.

        :return: JSON SCHEMA.
        """
        properties: Dict[str, Any] = {}
        for reg in self.get_registers():
            bitfields = reg.get_bitfields()
            reg_schema = [
                {
                    "type": ["string", "number"],
                    "skip_in_template": len(bitfields) > 0,
                    # "format": "number", # TODO add option to hexstring
                    "template_value": f"{reg.get_hex_value()}",
                },
                {  # Obsolete type
                    "type": "object",
                    "required": ["value"],
                    "skip_in_template": True,
                    "additionalProperties": False,
                    "properties": {
                        "value": {
                            "type": ["string", "number"],
                            # "format": "number", # TODO add option to hexstring
                            "template_value": f"{reg.get_hex_value()}",
                        }
                    },
                },
            ]

            if bitfields:
                bitfields_schema = {}
                for bitfield in bitfields:
                    if not bitfield.has_enums():
                        bitfields_schema[bitfield.name] = {
                            "type": ["string", "number"],
                            "title": f"{bitfield.name}",
                            "description": self._get_bitfield_yaml_description(bitfield),
                            "template_value": bitfield.get_value(),
                        }
                    else:
                        bitfields_schema[bitfield.name] = {
                            "type": ["string", "number"],
                            "title": f"{bitfield.name}",
                            "description": self._get_bitfield_yaml_description(bitfield),
                            "enum_template": bitfield.get_enum_names(),
                            "minimum": 0,
                            "maximum": (1 << bitfield.width) - 1,
                            "template_value": bitfield.get_enum_value(),
                        }
                # Extend register schema by obsolete style
                reg_schema.append(
                    {
                        "type": "object",
                        "required": ["bitfields"],
                        "skip_in_template": True,
                        "additionalProperties": False,
                        "properties": {
                            "bitfields": {"type": "object", "properties": bitfields_schema}
                        },
                    }
                )
                # Extend by new style of bitfields
                reg_schema.append(
                    {
                        "type": "object",
                        "skip_in_template": False,
                        "required": [],
                        "additionalProperties": False,
                        "properties": bitfields_schema,
                    },
                )

            properties[reg.name] = {
                "title": f"{reg.name}",
                "description": f"{reg.description}",
                "oneOf": reg_schema,
            }

        return {"type": "object", "title": self.dev_name, "properties": properties}

    # pylint: disable=no-self-use   #It's better to have this function visually close to callies
    def _filter_by_names(self, items: List[ET.Element], names: List[str]) -> List[ET.Element]:
        """Filter out all items in the "items" tree,whose name starts with one of the strings in "names" list.

        :param items: Items to be filtered out.
        :param names: Names to filter out.
        :return: Filtered item elements list.
        """
        return [item for item in items if not item.attrib["name"].startswith(tuple(names))]

    # pylint: disable=dangerous-default-value
    def load_registers_from_xml(
        self,
        xml: str,
        filter_reg: Optional[List[str]] = None,
        grouped_regs: Optional[List[dict]] = None,
    ) -> None:
        """Function loads the registers from the given XML.

        :param xml: Input XML data in string format.
        :param filter_reg: List of register names that should be filtered out.
        :param grouped_regs: List of register prefixes names to be grouped into one.
        :raises SPSDKRegsError: XML parse problem occurs.
        """

        def is_reg_in_group(reg: str) -> Union[dict, None]:
            """Help function to recognize if the register should be part of group."""
            if grouped_regs:
                for group in grouped_regs:
                    # pylint: disable=anomalous-backslash-in-string  # \d is a part of the regex pattern
                    if re.fullmatch(f"{group['name']}" + r"\d+", reg) is not None:
                        return group
            return None

        try:
            xml_elements = ET.parse(xml)
        except ET.ParseError as exc:
            raise SPSDKRegsError(f"Cannot Parse XML data: {str(exc)}") from exc
        xml_registers = xml_elements.findall("register")
        xml_registers = self._filter_by_names(xml_registers, filter_reg or [])
        # Load all registers into the class
        for xml_reg in xml_registers:
            group = is_reg_in_group(xml_reg.attrib["name"])
            if group:
                try:
                    group_reg = self.find_reg(group["name"])
                except SPSDKRegsErrorRegisterNotFound:
                    group_reg = RegsRegister(
                        name=group["name"],
                        offset=value_to_int(group.get("offset", 0)),
                        width=value_to_int(group.get("width", 0)),
                        description=group.get(
                            "description", f"Group of {group['name']} registers."
                        ),
                        reverse=value_to_bool(group.get("reversed", False)),
                        access=group.get("access", None),
                        config_as_hexstring=group.get("config_as_hexstring", False),
                        reverse_subregs_order=group.get("reverse_subregs_order", False),
                        alt_widths=group.get("alternative_widths"),
                    )

                    self.add_register(group_reg)
                group_reg.add_group_reg(RegsRegister.from_xml_element(xml_reg))
            else:
                self.add_register(RegsRegister.from_xml_element(xml_reg))

    def load_yml_config(self, yml_data: Dict[str, Any]) -> None:
        """The function loads the configuration from YML file.

        :param yml_data: The YAML commented data with register values.
        """
        for reg_name in yml_data.keys():
            reg_value = yml_data[reg_name]
            register = self.find_reg(reg_name, include_group_regs=True)
            if isinstance(reg_value, dict):
                if "value" in reg_value.keys():
                    raw_val = reg_value["value"]
                    val = (
                        int(raw_val, 16)
                        if register.config_as_hexstring and isinstance(raw_val, str)
                        else value_to_int(raw_val)
                    )
                    register.set_value(val, False)
                else:
                    bitfields = (
                        reg_value["bitfields"] if "bitfields" in reg_value.keys() else reg_value
                    )
                    for bitfield_name in bitfields:
                        bitfield_val = bitfields[bitfield_name]
                        try:
                            bitfield = register.find_bitfield(bitfield_name)
                        except SPSDKRegsErrorBitfieldNotFound:
                            logger.error(
                                f"The {bitfield_name} is not found in register {register.name}."
                            )
                            continue
                        try:
                            bitfield.set_enum_value(bitfield_val, True)
                        except SPSDKValueError as e:
                            raise SPSDKError(
                                f"Bitfield value: {hex(bitfield_val)} of {bitfield.name} is out of range."
                                + f"\nBitfield width is {bitfield.width} bits"
                            ) from e
                        except SPSDKError:
                            # New versions of register data do not contain register and bitfield value in enum
                            old_bitfield = bitfield_val
                            bitfield_val = bitfield_val.replace(bitfield.name + "_", "").replace(
                                register.name + "_", ""
                            )
                            # Some bitfield were renamed from ENABLE to ALLOW
                            bitfield_val = "ALLOW" if bitfield_val == "ENABLE" else bitfield_val
                            logger.warning(
                                f"Bitfield {old_bitfield} not found, trying backward"
                                " compatibility mode with {bitfield_val}"
                            )
                            bitfield.set_enum_value(bitfield_val, True)

                    # Run the processing of loaded register value
                    register.set_value(register.get_value(True), False)
            elif isinstance(reg_value, (int, str)):
                val = (
                    int(reg_value, 16)
                    if register.config_as_hexstring and isinstance(reg_value, str)
                    else value_to_int(reg_value)
                )
                register.set_value(val, False)

            else:
                logger.error(f"There are no data for {reg_name} register.")

            logger.debug(f"The register {reg_name} has been loaded from configuration.")

    def get_config(self, diff: bool = False) -> Dict[str, Any]:
        """Get the whole configuration in dictionary.

        :param diff: Get only configuration with difference value to reset state.
        :return: Dictionary of registers values.
        """
        ret: Dict[str, Any] = {}
        for reg in self.get_registers():
            if diff and reg.get_value(raw=True) == reg.get_reset_value():
                continue
            bitfields = reg.get_bitfields()
            if bitfields:
                btf = {}
                for bitfield in bitfields:
                    if diff and bitfield.get_value() == bitfield.get_reset_value():
                        continue
                    btf[bitfield.name] = bitfield.get_enum_value()
                ret[reg.name] = btf
            else:
                ret[reg.name] = reg.get_hex_value()

        return ret
