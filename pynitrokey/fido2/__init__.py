
import time

import pynitrokey.fido2.hmac_secret as hmac_secret


def find(solo_serial=None, retries=5, raw_device=None, udp=False):
    # @fixme: revive
    #if udp:
    #    pynitrokey.fido2.force_udp_backend()

    from pynitrokey.fido2.client import NKFido2Client
    from pynitrokey.exceptions import NoSoloFoundError

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
            ## @FIXME: woop, woop MAGIC NUMBERS ahoi...
            (1155, 41674),
            (0x20A0, 0x42B3),
            (0x20A0, 0x42B1),
        ]
    ]
    return [find(raw_device=device) for device in solo_devices]


