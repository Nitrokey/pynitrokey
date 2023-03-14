# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import enum
import logging
import sys
from abc import abstractmethod
from dataclasses import dataclass
from re import Pattern
from typing import Callable, List, Optional, Tuple

from ..base import Nitrokey3Base
from ..utils import Version

logger = logging.getLogger(__name__)


ProgressCallback = Callable[[int, int], None]


class Variant(enum.Enum):
    LPC55 = "lpc55"
    NRF52 = "nrf52"

    @classmethod
    def from_str(cls, s: str) -> "Variant":
        for variant in cls:
            if variant.value == s:
                return variant
        raise ValueError(f"Unknown variant {s}")


@dataclass
class FirmwareMetadata:
    version: Version
    signed_by: Optional[str] = None
    signed_by_nitrokey: bool = False


class Nitrokey3Bootloader(Nitrokey3Base):
    @abstractmethod
    def update(
        self,
        image: bytes,
        callback: Optional[ProgressCallback] = None,
    ) -> None:
        ...

    @property
    @abstractmethod
    def variant(self) -> Variant:
        ...


def list() -> List[Nitrokey3Bootloader]:
    from .lpc55 import Nitrokey3BootloaderLpc55
    from .nrf52 import Nitrokey3BootloaderNrf52

    devices: List[Nitrokey3Bootloader] = []
    devices.extend(Nitrokey3BootloaderLpc55.list())
    devices.extend(Nitrokey3BootloaderNrf52.list())
    return devices


def open(path: str) -> Optional[Nitrokey3Bootloader]:
    from .lpc55 import Nitrokey3BootloaderLpc55
    from .nrf52 import Nitrokey3BootloaderNrf52

    lpc55 = Nitrokey3BootloaderLpc55.open(path)
    if lpc55:
        return lpc55

    nrf52 = Nitrokey3BootloaderNrf52.open(path)
    if nrf52:
        return nrf52

    return None


def get_firmware_filename_pattern(variant: Variant) -> Pattern:
    from .lpc55 import FILENAME_PATTERN as FILENAME_PATTERN_LPC55
    from .nrf52 import FILENAME_PATTERN as FILENAME_PATTERN_NRF52

    if variant == Variant.LPC55:
        return FILENAME_PATTERN_LPC55
    elif variant == Variant.NRF52:
        return FILENAME_PATTERN_NRF52
    else:
        raise ValueError(f"Unexpected variant {variant}")


def parse_filename(filename: str) -> Optional[Tuple[Variant, Version]]:
    for variant in Variant:
        pattern = get_firmware_filename_pattern(variant)
        match = pattern.search(filename)
        if match:
            version = Version.from_v_str(match.group("version"))
            return (variant, version)
    return None


def validate_firmware_image(
    variant: Variant,
    data: bytes,
    version: Optional[Version],
) -> FirmwareMetadata:
    try:
        metadata = parse_firmware_image(variant, data)
    except Exception:
        logger.exception("Failed to parse firmware image", exc_info=sys.exc_info())
        raise Exception("Failed to parse firmware image")

    if version:
        if version.core() != metadata.version:
            raise Exception(
                f"The firmware image for the release {version} has an unexpected product "
                f"version ({metadata.version})."
            )

    if not metadata.signed_by:
        raise Exception("Firmware image is not signed")

    if not metadata.signed_by_nitrokey:
        raise Exception(
            f"Firmware image is not signed by Nitrokey (signed by: {metadata.signed_by})"
        )

    return metadata


def parse_firmware_image(variant: Variant, data: bytes) -> FirmwareMetadata:
    from .lpc55 import parse_firmware_image as parse_firmware_image_lpc55
    from .nrf52 import parse_firmware_image as parse_firmware_image_nrf52

    if variant == Variant.LPC55:
        return parse_firmware_image_lpc55(data)
    elif variant == Variant.NRF52:
        return parse_firmware_image_nrf52(data)
    else:
        raise ValueError(f"Unexpected variant {variant}")
