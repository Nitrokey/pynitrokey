# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from functools import total_ordering
from typing import Tuple

from spsdk.sbfile.misc import BcdVersion3


@total_ordering
class Version:
    def __init__(self, major: int, minor: int, patch: int) -> None:
        self.major = major
        self.minor = minor
        self.patch = patch

    def __hash__(self) -> int:
        return hash(self._as_tuple())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._as_tuple() == other._as_tuple()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._as_tuple() < other._as_tuple()

    def __repr__(self) -> str:
        return f"Version(major={self.major}, minor={self.minor}, patch={self.patch})"

    def __str__(self) -> str:
        return f"v{self.major}.{self.minor}.{self.patch}"

    def _as_tuple(self) -> Tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

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
