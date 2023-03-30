import binascii
import logging
from struct import pack
from typing import Optional

from pynitrokey.start.gnuk_token import gnuk_token
import usb

USB_PRODUCT_LIST_TUP = 0x20a0
# USB class, subclass, protocol
CCID_CLASS = 0x0B
CCID_SUBCLASS = 0x00
CCID_PROTOCOL_0 = 0x00

l = logging.getLogger("ccid")


def icc_compose(msg_type, data_len, slot, seq, param, data):
    return pack("<BiBBBH", msg_type, data_len, slot, seq, 0, param) + data


def iso7816_compose(ins, p1, p2, data, cls=0x00, le=None):
    data_len = len(data)
    if data_len == 0:
        if le is None:
            return pack(">BBBB", cls, ins, p1, p2)
        else:
            return pack(">BBBBB", cls, ins, p1, p2, le)
    else:
        if le is None:
            return pack(">BBBBB", cls, ins, p1, p2, data_len) + data
        else:
            return pack(">BBBBB", cls, ins, p1, p2, data_len) + data + pack(">B", le)


def devices():
    busses = usb.busses()
    for bus in busses:
        devices = bus.devices
        for dev in devices:
            for config in dev.configurations:
                for intf in config.interfaces:
                    for alt in intf:
                        if (
                            alt.interfaceClass == CCID_CLASS
                            and alt.interfaceSubClass == CCID_SUBCLASS
                            and alt.interfaceProtocol == CCID_PROTOCOL_0
                            # and (dev.idVendor, dev.idProduct) in USB_PRODUCT_LIST_TUP
                            and dev.idVendor == USB_PRODUCT_LIST_TUP
                        ):
                            l.debug(f"dev {dev} {alt.interfaceClass} {alt.interfaceProtocol} ")
                            yield dev, config, alt
    raise RuntimeError("No devices")


def get_device() -> Optional[gnuk_token]:
    for (dev, config, intf) in devices():
        try:
            icc = gnuk_token(dev, config, intf)
            l.debug(f"got device {icc}. "
                    # f"getting status"
                    )
            # status = icc.icc_get_status()
            # l.debug(f"status {status}")
            # icc.icc_power_on()
            # if status == 0:
            #     pass  # It's ON already
            # elif status == 1:
            #     icc.icc_power_on()
            # else:
            #     raise ValueError("Unknown ICC status", status)
            return icc
        except:
            raise


def test_main():
    assert iso7816_compose(0xA4, 0x04, 0x00, bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]),
                           le=0).hex() == "00a4040007a000000527210100"

    g = get_device()
    g.reset_device()
    with g.release_on_exit():

        for d in [
            # "00a4040007a000000527210100",
            # select oath app
            iso7816_compose(0xA4, 0x04, 0x00, bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])),
        ]:
            l.debug(f"sending {d.hex()} ")
            r = g.icc_send_cmd(d)
            l.debug(f"recv d{bytes(r).hex()} ")


        data = [
            # "00a4040009a0000008470000000100",
            # "0062000000",
            # poweron
            icc_compose(0x62, 0, 0, 0, 0, b""),
            # "00a4040009a0000008470000000100",
            # "0063000000",
            # poweroff ?
            icc_compose(0x63, 0, 0, 0, 0, b""),  # this one does not seem to be needed
            # "00a4040009a0000008470000000100",
            # "0061000000",
            # solo version command (works)
            icc_compose(0x61, 0, 0, 0, 0, b""),
        ]
        for d in data:
            l.debug(f"sending {d.hex()} ")
            r = g.raw_send(d, l)
            l.debug(f"recv {bytes([*r]).hex()} ")

        for d in [
            # "00a4040007a000000527210100",
            # select oath app
            iso7816_compose(0xA4, 0x04, 0x00, bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])),
            # send reset command
            iso7816_compose(0x04, 0xDE, 0xAD, data=b'')
        ]:
            l.debug(f"sending {d.hex()} ")
            r = g.icc_send_cmd(d)
            l.debug(f"recv d{bytes(r).hex()} ")

