#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to keep additional utilities for binary images."""

import logging
import math
import os
import re
import textwrap
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import colorama

from spsdk.exceptions import SPSDKError, SPSDKOverlapError, SPSDKValueError
from spsdk.utils.database import DatabaseManager
from spsdk.utils.misc import (
    BinaryPattern,
    align,
    align_block,
    find_file,
    format_value,
    size_fmt,
    write_file,
)
from spsdk.utils.schema_validator import CommentedConfig

if TYPE_CHECKING:
    # bincopy will be loaded lazily as needed, this is just to satisfy type-hint checkers
    import bincopy

logger = logging.getLogger(__name__)


class ColorPicker:
    """Simple class to get each time when ask different color from list."""

    COLORS = [
        colorama.Fore.LIGHTBLACK_EX,
        colorama.Fore.BLUE,
        colorama.Fore.GREEN,
        colorama.Fore.CYAN,
        colorama.Fore.YELLOW,
        colorama.Fore.MAGENTA,
        colorama.Fore.WHITE,
        colorama.Fore.LIGHTBLUE_EX,
        colorama.Fore.LIGHTCYAN_EX,
        colorama.Fore.LIGHTGREEN_EX,
        colorama.Fore.LIGHTMAGENTA_EX,
        colorama.Fore.LIGHTWHITE_EX,
        colorama.Fore.LIGHTYELLOW_EX,
    ]

    def __init__(self) -> None:
        """Constructor of ColorPicker."""
        self.index = len(self.COLORS)

    def get_color(self, unwanted_color: Optional[str] = None) -> str:
        """Get new color from list.

        :param unwanted_color: Color that should be omitted.
        :return: Color
        """
        self.index += 1
        if self.index >= len(ColorPicker.COLORS):
            self.index = 0
        if unwanted_color and ColorPicker.COLORS[self.index] == unwanted_color:
            return self.get_color(unwanted_color)
        return ColorPicker.COLORS[self.index]


class BinaryImage:
    """Binary Image class."""

    MINIMAL_DRAW_WIDTH = 30

    def __init__(
        self,
        name: str,
        size: int = 0,
        offset: int = 0,
        description: Optional[str] = None,
        binary: Optional[bytes] = None,
        pattern: Optional[BinaryPattern] = None,
        alignment: int = 1,
        parent: Optional["BinaryImage"] = None,
    ) -> None:
        """Binary Image class constructor.

        :param name: Name of Image.
        :param size: Image size.
        :param offset: Image offset in parent image, defaults to 0
        :param description: Text description of image, defaults to None
        :param binary: Optional binary content.
        :param pattern: Optional binary pattern.
        :param alignment: Optional alignment of result image
        :param parent: Handle to parent object, defaults to None
        """
        self.name = name
        self.description = description
        self.offset = offset
        self._size = align(size, alignment)
        self.binary = binary
        self.pattern = pattern
        self.alignment = alignment
        self.parent = parent

        if parent:
            assert isinstance(parent, BinaryImage)
        self.sub_images: List["BinaryImage"] = []

    @property
    def size(self) -> int:
        """Size property."""
        return len(self)

    @size.setter
    def size(self, value: int) -> None:
        """Size property setter."""
        self._size = align(value, self.alignment)

    def add_image(self, image: "BinaryImage") -> None:
        """Add new sub image information.

        :param image: Image object.
        """
        image.parent = self
        for i, child in enumerate(self.sub_images):
            if image.offset < child.offset:
                self.sub_images.insert(i, image)
                return
        self.sub_images.append(image)

    def join_images(self) -> None:
        """Join all sub images into main binary block."""
        binary = self.export()
        self.sub_images.clear()
        self.binary = binary

    @property
    def image_name(self) -> str:
        """Image name including all parents.

        :return: Full Image name
        """
        if self.parent:
            return self.parent.image_name + "=>" + self.name
        return self.name

    @property
    def absolute_address(self) -> int:
        """Image absolute address relative to base parent.

        :return: Absolute address relative to base parent
        """
        if self.parent:
            return self.parent.absolute_address + self.offset
        return self.offset

    def aligned_start(self, alignment: int = 4) -> int:
        """Returns aligned start address.

        :param alignment: The alignment value, defaults to 4.
        :return: Floor alignment address.
        """
        return math.floor(self.absolute_address / alignment) * alignment

    def aligned_length(self, alignment: int = 4) -> int:
        """Returns aligned length for erasing purposes.

        :param alignment: The alignment value, defaults to 4.
        :return: Ceil alignment length.
        """
        end_address = self.absolute_address + len(self)
        aligned_end = math.ceil(end_address / alignment) * alignment
        aligned_len = aligned_end - self.aligned_start(alignment)
        return aligned_len

    def __str__(self) -> str:
        """Provides information about image.

        :return: String information about Image.
        """
        size = len(self)
        ret = ""
        ret += f"Name:      {self.image_name}\n"
        ret += f"Starts:    {hex(self.absolute_address)}\n"
        ret += f"Ends:      {hex(self.absolute_address+ size-1)}\n"
        ret += f"Size:      {self._get_size_line(size)}\n"
        ret += f"Alignment: {size_fmt(self.alignment, use_kibibyte=False)}\n"
        if self.pattern:
            ret += f"Pattern:{self.pattern.pattern}\n"
        if self.description:
            ret += self.description + "\n"
        return ret

    def validate(self) -> None:
        """Validate if the images doesn't overlaps each other."""
        if self.offset < 0:
            raise SPSDKValueError(
                f"Image offset of {self.image_name} cannot be in negative numbers."
            )
        if len(self) < 0:
            raise SPSDKValueError(f"Image size of {self.image_name} cannot be in negative numbers.")
        for image in self.sub_images:
            image.validate()
            begin = image.offset
            end = begin + len(image) - 1
            # Check if it fits inside the parent image
            if end >= len(self):
                raise SPSDKOverlapError(
                    f"The image {image.name} doesn't fit into {self.name} parent image."
                )
            # Check if it doesn't overlap any other sibling image
            for sibling in self.sub_images:
                if sibling != image:
                    sibling_begin = sibling.offset
                    sibling_end = sibling_begin + len(sibling) - 1
                    if end < sibling_begin or begin > sibling_end:
                        continue

                    raise SPSDKOverlapError(
                        f"The image overlap error:\n"
                        f"{str(image)}\n"
                        "overlaps the:\n"
                        f"{str(sibling)}\n"
                    )

    def _get_size_line(self, size: int) -> str:
        """Get string of size line.

        :param size: Size in bytes
        :return: Formatted size line.
        """
        if size >= 1024:
            real_size = ",".join(re.findall(".{1,3}", (str(len(self)))[::-1]))[::-1]
            return f"Size: {size_fmt(len(self), False)}; {real_size} B"

        return f"Size: {size_fmt(len(self), False)}"

    def get_min_draw_width(self, include_sub_images: bool = True) -> int:
        """Get minimal width of table for draw function.

        :param include_sub_images: Include also sub images into, defaults to True
        :return: Minimal width in characters.
        """
        widths = [
            self.MINIMAL_DRAW_WIDTH,
            len(f"+==-0x0000_0000= {self.name} =+"),
            len(f"|{self._get_size_line(self.size)}|"),
        ]
        if include_sub_images:
            for child in self.sub_images:
                widths.append(child.get_min_draw_width() + 2)  # +2 means add vertical borders
        return max(widths)

    def draw(
        self,
        include_sub_images: bool = True,
        width: int = 0,
        color: str = "",
        no_color: bool = False,
    ) -> str:
        # fmt: off
        """Draw the image into the ASCII graphics.

        :param include_sub_images: Include also sub images into, defaults to True
        :param width: Fixed width of table, 0 means autosize.
        :param color: Color of this block, None means automatic color.
        :param no_color: Disable adding colors into output.
        :raises SPSDKValueError: In case of invalid width.
        :return: ASCII art representation of image.
        """
        # +==0x0000_0000==Title1===============+
        # |            Size: 2048B             |
        # |           Description1             |
        # |       Description1 2nd line        |
        # |+==0x0000_0000==Title11============+|
        # ||           Size: 512B             ||
        # ||           Description11          ||
        # ||       Description11 2nd line     ||
        # |+==0x0000_01FF=====================+|
        # |                                    |
        # |+==0x0000_0210==Title12============+|
        # ||           Size: 512B             ||
        # ||           Description12          ||
        # ||       Description12 2nd line     ||
        # |+==0x0000_041F=====================+|
        # +==0x0000_07FF=======================+
        # fmt: on
        def _get_centered_line(text: str) -> str:
            text_len = len(text)
            spaces = width - text_len - 2
            assert spaces >= 0, "Binary Image Draw: Center line is longer than width"
            padding_l = int(spaces / 2)
            padding_r = int(spaces - padding_l)
            return color + f"|{' '*padding_l}{text}{' '*padding_r}|\n"

        def wrap_block(inner: str) -> str:
            wrapped_block = ""
            lines = inner.splitlines(keepends=False)
            for line in lines:
                wrapped_block += color + "|" + line + color + "|\n"
            return wrapped_block

        if no_color:
            color = ""
        else:
            color_picker = ColorPicker()
            try:
                self.validate()
                color = color or color_picker.get_color()
            except SPSDKError:
                color = colorama.Fore.RED

        block = "" if self.parent else "\n"
        min_width = self.get_min_draw_width(include_sub_images)
        if not width and self.parent is None:
            width = min_width

        if width < min_width:
            raise SPSDKValueError(
                f"Binary Image Draw: Width is to short ({width} < minimal width: {min_width})"
            )

        # - Title line
        header = f"+=={format_value(self.absolute_address, 32)}= {self.name} ="
        block += color + f"{header}{'='*(width-len(header)-1)}+\n"
        # - Size
        block += _get_centered_line(self._get_size_line(len(self)))
        # - Description
        if self.description:
            for line in textwrap.wrap(self.description, width=width - 2, fix_sentence_endings=True):
                block += _get_centered_line(line)
        # - Pattern
        if self.pattern:
            block += _get_centered_line(f"Pattern: {self.pattern.pattern}")
        # - Inner blocks
        if include_sub_images:
            next_free_space = 0
            for child in self.sub_images:
                # If the images doesn't comes one by one place empty line
                if child.offset != next_free_space:
                    block += _get_centered_line(
                        f"Gap: {size_fmt(child.offset-next_free_space, False)}"
                    )
                next_free_space = child.offset + len(child)
                inner_block = child.draw(
                    include_sub_images=include_sub_images,
                    width=width - 2,
                    color="" if no_color else color_picker.get_color(color),
                    no_color=no_color,
                )
                block += wrap_block(inner_block)

        # - Closing line
        footer = f"+=={format_value(self.absolute_address + len(self) - 1, 32)}=="
        block += color + f"{footer}{'='*(width-len(footer)-1)}+\n"

        if self.parent is None:
            block += "\n" + "" if no_color else colorama.Fore.RESET
        return block

    def update_offsets(self) -> None:
        """Update offsets from the sub images into main offset value begin offsets."""
        offsets = []
        for image in self.sub_images:
            offsets.append(image.offset)

        min_offset = min(offsets)
        for image in self.sub_images:
            image.offset -= min_offset
        self.offset += min_offset

    def __len__(self) -> int:
        """Get length of image.

        If internal member size is not set(is zero) the size is computed from sub images.
        :return: Size of image.
        """
        if self._size:
            return self._size
        max_size = len(self.binary) if self.binary else 0
        for image in self.sub_images:
            size = image.offset + len(image)
            max_size = max(size, max_size)
        return align(max_size, self.alignment)

    def export(self) -> bytes:
        """Export represented binary image.

        :return: Byte array of binary image.
        """
        if self.binary and len(self) == len(self.binary) and len(self.sub_images) == 0:
            return self.binary

        if self.pattern:
            ret = bytearray(self.pattern.get_block(len(self)))
        else:
            ret = bytearray(len(self))

        if self.binary:
            binary_view = memoryview(self.binary)
            ret[: len(self.binary)] = binary_view

        for image in self.sub_images:
            image_data = image.export()
            ret_slice = memoryview(ret)[image.offset : image.offset + len(image_data)]
            image_data_view = memoryview(image_data)
            ret_slice[:] = image_data_view

        return align_block(ret, self.alignment, self.pattern)

    @staticmethod
    def get_validation_schemas() -> List[Dict[str, Any]]:
        """Get validation schemas list to check a supported configuration.

        :return: Validation schemas.
        """
        return [DatabaseManager().db.get_schema_file("binary")]

    @staticmethod
    def load_from_config(
        config: Dict[str, Any], search_paths: Optional[List[str]] = None
    ) -> "BinaryImage":
        """Converts the configuration option into an Binary Image object.

        :param config: Description of binary image.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: Initialized Binary Image.
        """
        name = config.get("name", "Base Image")
        size = config.get("size", 0)
        pattern = BinaryPattern(config.get("pattern", "zeros"))
        alignment = config.get("alignment", 1)
        ret = BinaryImage(name=name, size=size, pattern=pattern, alignment=alignment)
        regions = config.get("regions")
        if regions:
            for i, region in enumerate(regions):
                binary_file: Dict = region.get("binary_file")
                if binary_file:
                    offset = binary_file.get("offset", ret.aligned_length(ret.alignment))
                    name = binary_file.get("name", binary_file["path"])
                    ret.add_image(
                        BinaryImage.load_binary_image(
                            binary_file["path"],
                            name=name,
                            offset=offset,
                            pattern=pattern,
                            search_paths=search_paths,
                        )
                    )
                binary_block: Dict = region.get("binary_block")
                if binary_block:
                    size = binary_block["size"]
                    offset = binary_block.get("offset", ret.aligned_length(ret.alignment))
                    name = binary_block.get("name", f"Binary block(#{i})")
                    pattern = BinaryPattern(binary_block["pattern"])
                    ret.add_image(BinaryImage(name, size, offset, pattern=pattern))
        return ret

    def save_binary_image(
        self,
        path: str,
        file_format: str = "BIN",
    ) -> None:
        # pylint: disable=missing-param-doc
        """Save binary data file.

        :param path: Path to the file.
        :param file_format: Format of saved file ('BIN', 'HEX', 'S19'), defaults to 'BIN'.
        :raises SPSDKValueError: The file format is invalid.
        """
        file_format = file_format.upper()
        if file_format.upper() not in ("BIN", "HEX", "S19"):
            raise SPSDKValueError(f"Invalid input file format: {file_format}")

        if file_format == "BIN":
            write_file(self.export(), path, mode="wb")
            return

        def add_into_binary(bin_image: BinaryImage) -> None:
            if bin_image.pattern:
                bin_file.add_binary(
                    bin_image.pattern.get_block(len(bin_image)),
                    address=bin_image.absolute_address,
                    overwrite=True,
                )

            if bin_image.binary:
                bin_file.add_binary(
                    bin_image.binary, address=bin_image.absolute_address, overwrite=True
                )

            for sub_image in bin_image.sub_images:
                add_into_binary(sub_image)

        # import bincopy only if needed to save startup time
        import bincopy  # pylint: disable=import-outside-toplevel

        bin_file = bincopy.BinFile()
        add_into_binary(self)

        if file_format == "HEX":
            write_file(bin_file.as_ihex(), path)
            return

        # And final supported format is....... Yes, S record from MOTOROLA
        write_file(bin_file.as_srec(), path)

    @staticmethod
    def generate_config_template() -> str:
        """Generate configuration template.

        :return: Template to create binary merge..
        """
        return CommentedConfig(
            "Binary Image Configuration template.", BinaryImage.get_validation_schemas()
        ).get_template()

    @staticmethod
    def load_binary_image(
        path: str,
        name: Optional[str] = None,
        size: int = 0,
        offset: int = 0,
        description: Optional[str] = None,
        pattern: Optional[BinaryPattern] = None,
        search_paths: Optional[List[str]] = None,
        alignment: int = 1,
        load_bin: bool = True,
    ) -> "BinaryImage":
        # pylint: disable=missing-param-doc
        r"""Load binary data file.

        Supported formats are ELF, HEX, SREC and plain binary

        :param path: Path to the file.
        :param name: Name of Image, defaults to file name.
        :param size: Image size, defaults to 0.
        :param offset: Image offset in parent image, defaults to 0
        :param description: Text description of image, defaults to None
        :param pattern: Optional binary pattern.
        :param search_paths: List of paths where to search for the file, defaults to None
        :param alignment: Optional alignment of result image
        :param load_bin: Load as binary in case of every other format load fails
        :raises SPSDKError: The binary file cannot be loaded.
        :return: Binary data represented in BinaryImage class.
        """
        path = find_file(path, search_paths=search_paths)
        try:
            with open(path, "rb") as f:
                data = f.read(4)
        except Exception as e:
            raise SPSDKError(f"Error loading file: {str(e)}") from e

        # import bincopy only if needed to save startup time
        import bincopy  # pylint: disable=import-outside-toplevel

        bin_file = bincopy.BinFile()
        try:
            if data == b"\x7fELF":
                bin_file.add_elf_file(path)
            else:
                try:
                    bin_file.add_file(path)
                except (UnicodeDecodeError, bincopy.UnsupportedFileFormatError) as e:
                    if load_bin:
                        bin_file.add_binary_file(path)
                    else:
                        raise SPSDKError("Cannot load file as ELF, HEX or SREC") from e
        except Exception as e:
            raise SPSDKError(f"Error loading file: {str(e)}") from e

        img_name = name or os.path.basename(path)
        img_size = size or 0
        img_descr = description or f"The image loaded from: {path} ."
        bin_image = BinaryImage(
            name=img_name,
            size=img_size,
            offset=offset,
            description=img_descr,
            pattern=pattern,
            alignment=alignment,
        )
        if len(bin_file.segments) == 0:
            raise SPSDKError(f"Load of {path} failed, can't be decoded.")

        for i, segment in enumerate(bin_file.segments):
            bin_image.add_image(
                BinaryImage(
                    name=f"Segment {i}",
                    size=len(segment.data),
                    offset=segment.address,
                    pattern=pattern,
                    binary=segment.data,
                    parent=bin_image,
                    alignment=alignment,
                )
            )
        # Optimize offsets in image
        bin_image.update_offsets()
        return bin_image
