import time
from typing import Union

import usb

from pynitrokey.exceptions import NoSoloFoundError

# from pynitrokey.fido2 import hmac_secret
from pynitrokey.fido2.client import NKFido2Client


def hot_patch_windows_libusb():
    # hot patch for windows libusb backend
    olddel = usb._objfinalizer._AutoFinalizedObjectBase.__del__

    def newdel(self):
        try:
            olddel(self)
        except OSError:
            pass

    usb._objfinalizer._AutoFinalizedObjectBase.__del__ = newdel


def _UDP_InternalPlatformSwitch(funcname, *args, **kwargs):
    if funcname == "__init__":
        return HidOverUDP(*args, **kwargs)
    return getattr(HidOverUDP, funcname)(*args, **kwargs)


def find(solo_serial=None, retries=5, raw_device=None, udp=False):
    if udp:
        force_udp_backend()

    p = NKFido2Client()

    # This... is not the right way to do it yet
    p.use_u2f()

    for i in range(retries):
        try:
            p.find_device(dev=raw_device, solo_serial=solo_serial)
            return p
        except RuntimeError:
            time.sleep(0.2)

    # return None
    raise NoSoloFoundError("no Nitrokey FIDO2 found")


def find_all():
    from fido2.hid import CtapHidDevice

    hid_devices = list(CtapHidDevice.list_devices())
    solo_devices = [
        d
        for d in hid_devices
        if (d.descriptor.vid, d.descriptor.pid)
        in [
            ## @FIXME: move magic numbers
            (1155, 41674),
            (0x20A0, 0x42B3),
            (0x20A0, 0x42B1),
        ]
    ]
    return [find(raw_device=device) for device in solo_devices]


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
