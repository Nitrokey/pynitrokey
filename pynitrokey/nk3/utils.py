# -*- coding: utf-8 -*-
#
# Copyright 2021-2023 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import dataclasses
from dataclasses import dataclass, field
from functools import total_ordering
from typing import Optional

from spsdk.sbfile.misc import BcdVersion3


@dataclass(order=True, frozen=True)
class Uuid:
    """UUID of a Nitrokey 3 device."""

    value: int

    def __str__(self) -> str:
        return f"{self.value:032X}"

    def __int__(self) -> int:
        return self.value


@dataclass(eq=False, frozen=True)
@total_ordering
class Version:
    """
    The version of a Nitrokey 3 device, following Semantic Versioning 2.0.0.

    Some sources for version information, namely the version returned by older
    devices and the firmware binaries, do not contain the pre-release
    component.  These instances are marked with *complete=False*.  This flag
    affects comparison:  The pre-release version is only taken into account if
    both version instances are complete.

    >>> Version(1, 0, 0)
    Version(major=1, minor=0, patch=0, pre=None)
    >>> Version.from_str("1.0.0")
    Version(major=1, minor=0, patch=0, pre=None)
    >>> Version.from_v_str("v1.0.0")
    Version(major=1, minor=0, patch=0, pre=None)
    >>> Version(1, 0, 0, "rc.1")
    Version(major=1, minor=0, patch=0, pre='rc.1')
    >>> Version.from_str("1.0.0-rc.1")
    Version(major=1, minor=0, patch=0, pre='rc.1')
    >>> Version.from_v_str("v1.0.0-rc.1")
    Version(major=1, minor=0, patch=0, pre='rc.1')
    """

    major: int
    minor: int
    patch: int
    pre: Optional[str] = None
    complete: bool = field(default=False, repr=False)

    def __str__(self) -> str:
        """
        >>> str(Version(major=1, minor=0, patch=0))
        'v1.0.0'
        >>> str(Version(major=1, minor=0, patch=0, pre="rc.1"))
        'v1.0.0-rc.1'
        """

        if self.pre:
            return f"v{self.major}.{self.minor}.{self.patch}-{self.pre}"
        else:
            return f"v{self.major}.{self.minor}.{self.patch}"

    def __eq__(self, other: object) -> bool:
        """
        >>> Version(1, 0, 0) == Version(1, 0, 0)
        True
        >>> Version(1, 0, 0) == Version(1, 0, 1)
        False
        >>> Version.from_str("1.0.0-rc.1") == Version.from_str("1.0.0-rc.1")
        True
        >>> Version.from_str("1.0.0") == Version.from_str("1.0.0-rc.1")
        False
        >>> Version(1, 0, 0, complete=False) == Version.from_str("1.0.0-rc.1")
        True
        >>> Version(1, 0, 0, complete=False) == Version.from_str("1.0.1")
        False
        """
        if not isinstance(other, Version):
            return NotImplemented
        lhs = (self.major, self.minor, self.patch)
        rhs = (other.major, other.minor, other.patch)

        if lhs != rhs:
            return False
        if self.complete and other.complete:
            return self.pre == other.pre
        return True

    def __lt__(self, other: object) -> bool:
        """
        >>> def cmp(a, b):
        ...     return Version.from_str(a) < Version.from_str(b)
        >>> cmp("1.0.0", "1.0.0")
        False
        >>> cmp("1.0.0", "1.0.1")
        True
        >>> cmp("1.1.0", "2.0.0")
        True
        >>> cmp("1.1.0", "1.0.3")
        False
        >>> cmp("1.0.0-rc.1", "1.0.0-rc.1")
        False
        >>> cmp("1.0.0-rc.1", "1.0.0")
        True
        >>> cmp("1.0.0", "1.0.0-rc.1")
        False
        >>> cmp("1.0.0-rc.1", "1.0.0-rc.2")
        True
        >>> cmp("1.0.0-rc.2", "1.0.0-rc.1")
        False
        >>> cmp("1.0.0-alpha.1", "1.0.0-rc.1")
        True
        >>> cmp("1.0.0-alpha.1", "1.0.0-rc.1.0")
        True
        >>> cmp("1.0.0-alpha.1", "1.0.0-alpha.1.0")
        True
        >>> cmp("1.0.0-rc.2", "1.0.0-rc.10")
        True
        >>> Version(1, 0, 0, "rc.1") < Version(1, 0, 0)
        False
        """

        if not isinstance(other, Version):
            return NotImplemented

        lhs = (self.major, self.minor, self.patch)
        rhs = (other.major, other.minor, other.patch)

        if lhs == rhs and self.complete and other.complete:
            # relevant rules:
            # 1. pre-releases sort before regular releases
            # 2. two pre-releases for the same core version are sorted by the pre-release component
            #    (split into subcomponents)
            if self.pre == other.pre:
                return False
            elif self.pre is None:
                # self is regular release, other is pre-release
                return False
            elif other.pre is None:
                # self is pre-release, other is regular release
                return True
            else:
                # both are pre-releases
                def int_or_str(s: str) -> object:
                    if s.isdigit():
                        return int(s)
                    else:
                        return s

                lhs_pre = [int_or_str(s) for s in self.pre.split(".")]
                rhs_pre = [int_or_str(s) for s in other.pre.split(".")]
                return lhs_pre < rhs_pre
        else:
            return lhs < rhs

    def core(self) -> "Version":
        """
        Returns the core part of this version, i. e. the version without the
        pre-release component.

        >>> Version(1, 0, 0).core()
        Version(major=1, minor=0, patch=0, pre=None)
        >>> Version(1, 0, 0, "rc.1").core()
        Version(major=1, minor=0, patch=0, pre=None)
        """
        return dataclasses.replace(self, pre=None)

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
        version_parts = s.split("-", maxsplit=1)
        pre = version_parts[1] if len(version_parts) == 2 else None

        str_parts = version_parts[0].split(".")
        if len(str_parts) != 3:
            raise ValueError(f"Invalid firmware version: {s}")

        try:
            int_parts = [int(part) for part in str_parts]
        except ValueError:
            raise ValueError(f"Invalid component in firmware version: {s}")

        [major, minor, patch] = int_parts
        return cls(major=major, minor=minor, patch=patch, pre=pre, complete=True)

    @classmethod
    def from_v_str(cls, s: str) -> "Version":
        if not s.startswith("v"):
            raise ValueError(f"Missing v prefix for firmware version: {s}")
        return Version.from_str(s[1:])

    @classmethod
    def from_bcd_version(cls, version: BcdVersion3) -> "Version":
        return cls(major=version.major, minor=version.minor, patch=version.service)


@dataclass
class Fido2Certs:
    start: Version
    hashes: list[str]

    @classmethod
    def get(cls, version: Version) -> Optional["Fido2Certs"]:
        """
        >>> Fido2Certs.get(Version.from_str("0.0.0"))
        >>> Fido2Certs.get(Version.from_str("0.1.0")).start
        Version(major=0, minor=1, patch=0, pre=None)
        >>> Fido2Certs.get(Version.from_str("0.1.0-rc.1")).start
        Version(major=0, minor=1, patch=0, pre=None)
        >>> Fido2Certs.get(Version.from_str("0.2.0")).start
        Version(major=0, minor=1, patch=0, pre=None)
        >>> Fido2Certs.get(Version.from_str("1.0.3")).start
        Version(major=1, minor=0, patch=3, pre=None)
        >>> Fido2Certs.get(Version.from_str("1.0.3-alpha.1")).start
        Version(major=1, minor=0, patch=3, pre=None)
        >>> Fido2Certs.get(Version.from_str("2.5.0")).start
        Version(major=1, minor=0, patch=3, pre=None)
        """
        certs = [certs for certs in FIDO2_CERTS if version >= certs.start]
        if certs:
            return max(certs, key=lambda c: c.start)
        else:
            return None


FIDO2_CERTS = [
    Fido2Certs(
        start=Version(0, 1, 0),
        hashes=[
            "ad8fd1d16f59104b9e06ef323cc03f777ed5303cd421a101c9cb00bb3fdf722d",
        ],
    ),
    Fido2Certs(
        start=Version(1, 0, 3),
        hashes=[
            "aa1cb760c2879530e7d7fed3da75345d25774be9cfdbbcbd36fdee767025f34b",  # NK3xN/lpc55
            "4c331d7af869fd1d8217198b917a33d1fa503e9778da7638504a64a438661ae0",  # NK3AM/nrf52
            "f1ed1aba24b16e8e3fabcda72b10cbfa54488d3b778bda552162d60c6dd7b4fa",  # NK3AM/nrf52 test
        ],
    ),
]
