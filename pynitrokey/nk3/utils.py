# -*- coding: utf-8 -*-
#
# Copyright 2021-2023 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from dataclasses import dataclass
from functools import total_ordering

from spsdk.sbfile.misc import BcdVersion3


@dataclass(order=True, frozen=True)
class Uuid:
    """UUID of a Nitrokey 3 device."""

    value: int

    def __str__(self) -> str:
        return f"{self.value:032X}"

    def __int__(self) -> int:
        return self.value


@dataclass(frozen=True)
@total_ordering
class Version:
    """
    The version of a Nitrokey 3 device, following Semantic Versioning 2.0.0.

    >>> Version(1, 0, 0)
    Version(major=1, minor=0, patch=0)
    >>> Version.from_str("1.0.0")
    Version(major=1, minor=0, patch=0)
    >>> Version.from_v_str("v1.0.0")
    Version(major=1, minor=0, patch=0)
    """

    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        """
        >>> str(Version(major=1, minor=0, patch=0))
        'v1.0.0'
        """

        return f"v{self.major}.{self.minor}.{self.patch}"

    def __lt__(self, other: object) -> bool:
        """
        >>> Version(1, 0, 0) < Version(1, 0, 0)
        False
        >>> Version(1, 0, 0) < Version(1, 0, 1)
        True
        >>> Version(1, 1, 0) < Version(2, 0, 0)
        True
        >>> Version(1, 1, 0) < Version(1, 0, 3)
        False
        """

        if not isinstance(other, Version):
            return NotImplemented
        lhs = (self.major, self.minor, self.patch)
        rhs = (other.major, other.minor, other.patch)
        return lhs < rhs

    @classmethod
    def from_int(cls, version: int) -> "Version":
        # This is the reverse of the calculation in runners/lpc55/build.rs (CARGO_PKG_VERSION):
        # https://github.com/Nitrokey/nitrokey-3-firmware/blob/main/runners/lpc55/build.rs#L131
        major = version >> 22
        minor = (version >> 6) & ((1 << 16) - 1)
        patch = version & ((1 << 6) - 1)
        return cls(major=major, minor=minor, patch=patch)

    @classmethod
    def from_str(cls, s: str) -> "Version":
        str_parts = s.split(".")
        if len(str_parts) != 3:
            raise ValueError(f"Invalid firmware version: {s}")

        try:
            int_parts = [int(part) for part in str_parts]
        except ValueError:
            raise ValueError(f"Invalid component in firmware version: {s}")

        return cls(major=int_parts[0], minor=int_parts[1], patch=int_parts[2])

    @classmethod
    def from_v_str(cls, s: str) -> "Version":
        if not s.startswith("v"):
            raise ValueError(f"Missing v prefix for firmware version: {s}")
        return Version.from_str(s[1:])

    @classmethod
    def from_bcd_version(cls, version: BcdVersion3) -> "Version":
        return cls(major=version.major, minor=version.minor, patch=version.service)
