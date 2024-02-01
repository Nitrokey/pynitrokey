# -*- coding: utf-8 -*-
#
# Copyright 2021-2023 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from dataclasses import dataclass
from typing import Optional

from pynitrokey.trussed.utils import Version


@dataclass
class Fido2Certs:
    start: Version
    hashes: list[str]

    @classmethod
    def get(cls, version: Version) -> Optional["Fido2Certs"]:
        """
        >>> Fido2Certs.get(Version.from_str("0.0.0"))
        >>> Fido2Certs.get(Version.from_str("0.1.0")).start
        Version(major=0, minor=1, patch=0, pre=None, build=None)
        >>> Fido2Certs.get(Version.from_str("0.1.0-rc.1")).start
        Version(major=0, minor=1, patch=0, pre=None, build=None)
        >>> Fido2Certs.get(Version.from_str("0.2.0")).start
        Version(major=0, minor=1, patch=0, pre=None, build=None)
        >>> Fido2Certs.get(Version.from_str("1.0.3")).start
        Version(major=1, minor=0, patch=3, pre=None, build=None)
        >>> Fido2Certs.get(Version.from_str("1.0.3-alpha.1")).start
        Version(major=1, minor=0, patch=3, pre=None, build=None)
        >>> Fido2Certs.get(Version.from_str("2.5.0")).start
        Version(major=1, minor=0, patch=3, pre=None, build=None)
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
