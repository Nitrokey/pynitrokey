# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import sys
import time
from typing import List, Optional, Union

from fido2.hid import CtapHidDevice

from pynitrokey.exceptions import NoSoloFoundError
from pynitrokey.fido2.client import NKFido2Client, list_ctaphid_devices


def find(
    solo_serial: Optional[str] = None,
    retries: int = 5,
    raw_device: Optional[CtapHidDevice] = None,
) -> NKFido2Client:
    p = NKFido2Client()

    # This... is not the right way to do it yet
    p.use_u2f()

    for i in range(retries):
        try:
            p.find_device(dev=raw_device, solo_serial=solo_serial)
            return p
        except RuntimeError:
            time.sleep(0.2)

    print(
        "Warning: This command only works with the Nitrokey FIDO2, not with "
        "other FIDO2 devices!",
        file=sys.stderr,
    )
    raise NoSoloFoundError("no Nitrokey FIDO2 found")


def find_all() -> List[NKFido2Client]:
    return [find(raw_device=device) for device in list_ctaphid_devices()]


def device_path_to_str(path: Union[bytes, str]) -> str:
    """
    Converts a device path as returned by the fido2 library to a string.

    Typically, the path already is a string.  Only on Windows, a bytes object
    using an ANSI encoding is used instead.  We use the ISO 8859-1 encoding to
    decode the string which should work for all systems.
    """
    if isinstance(path, bytes):
        return path.decode("iso-8859-1", errors="ignore")
    else:
        return path
