
import time
import socket
import usb


import fido2._pyu2f
import fido2._pyu2f.base

from pynitrokey.fido2 import hmac_secret
from pynitrokey.fido2.client import NKFido2Client
from pynitrokey.exceptions import NoSoloFoundError


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


def force_udp_backend():
    fido2._pyu2f.InternalPlatformSwitch = _UDP_InternalPlatformSwitch


class HidOverUDP(fido2._pyu2f.base.HidDevice):
    @staticmethod
    def Enumerate():
        a = [
            {
                "vendor_id": 0x1234,
                "product_id": 0x5678,
                "product_string": "software test interface",
                "serial_number": "12345678",
                "usage": 0x01,
                "usage_page": 0xF1D0,
                "path": "localhost:8111",
            }
        ]
        return a

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 7112))
        addr, port = path.split(":")
        port = int(port)
        self.token = (addr, port)
        self.sock.settimeout(1.0)

    def GetInReportDataLength(self):
        return 64

    def GetOutReportDataLength(self):
        return 64

    def Write(self, packet):
        self.sock.sendto(bytearray(packet), self.token)

    def Read(self):
        msg = [0] * 64
        pkt, _ = self.sock.recvfrom(64)
        for i, v in enumerate(pkt):
            try:
                msg[i] = ord(v)
            except TypeError:
                msg[i] = v
        return msg


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
    solo_devices = [d for d in hid_devices
        if (d.descriptor["vendor_id"], d.descriptor["product_id"]) in [
            ## @FIXME: move magic numbers
            (1155, 41674),
            (0x20A0, 0x42B3),
            (0x20A0, 0x42B1),
        ]
    ]
    return [find(raw_device=device) for device in solo_devices]


