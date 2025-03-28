# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import platform
import sys

import click
import intelhex as ih
import nkdfu

from pynitrokey.helpers import (
    check_pynitrokey_version,
    local_critical,
    local_print,
    prompt,
)
from pynitrokey.libnk import DeviceNotFound, NitrokeyPro, RetCode

print = local_print
vendor = "20a0:42b4"


@click.group()
def pro():
    """Interact with Nitrokey Pro devices, see subcommands."""
    pass


@click.command()
def list():
    """list connected devices"""

    local_print(":: 'Nitrokey Pro' keys:")
    for dct in NitrokeyPro.list_devices():
        local_print(dct)


@click.command()
@click.option(
    "-p",
    "--password",
    default="12345678",
    help="update password to be used instead of default",
)
def enable_update(password):
    """enable firmware update for NK Pro device"""

    local_print("Enabling firmware update mode")
    nks = NitrokeyPro()
    try:
        libnk_version_current = nks.library_version()
    except Exception as e:
        local_print("Unhandled libnitrokey library version. Please upgrade it.")
        local_print(f"Error: {str(e)}")
        return 1
    libnk_version_required = (3, 5)
    if libnk_version_current < libnk_version_required:
        local_print(
            f"You need libnitrokey {libnk_version_required} to run this command. Currently installed: {libnk_version_current}."
        )
        local_print(
            "You can provide custom path for the libnitrokey with LIBNK_PATH environmental variable, e.g. by calling it like:"
        )
        local_print("$ env LIBNK_PATH=/my/path/libnitrokey.so nitropy <command>")
        return 1

    try:
        nks.connect()
        if nks.enable_firmware_update(password) == 0:
            local_print("Setting firmware update mode - success!")
        local_print("Done")
    except DeviceNotFound:
        local_print(f"No {nks.friendly_name} device found")
        local_print("If connected, perhaps already in update mode?")


@click.command()
def change_firmware_password():
    """
    Change the firmware update password.

    This is only supported by devices with the firmware version 0.11 or later.

    The user is prompted for the old and the new firmware update password.  Per
    default, the firmware update password is 12345678.
    """
    nk = NitrokeyPro()
    try:
        nk.connect()
    except DeviceNotFound:
        local_critical(f"No {nk.friendly_name} device found", support_hint=False)

    (_major, minor) = nk.fw_version
    if minor < 11:
        local_critical(
            f"The connected {nk.friendly_name} does not support firmware updates",
            support_hint=False,
        )

    old_password = prompt(
        "Old firmware update password", default="12345678", hide_input=True
    )
    new_password = prompt(
        "New firmware update password", hide_input=True, confirmation_prompt=True
    )
    ret = nk.change_firmware_password(old_password, new_password)
    if ret.ok:
        local_print("Successfully updated the firmware password")
    elif ret == RetCode.WRONG_PASSWORD:
        local_critical("Wrong firmware update password", support_hint=False)
    elif ret == RetCode.TooLongStringException:
        local_critical(
            "The new firmware update password is too long", support_hint=False
        )
    else:
        local_critical(f"Failed to update the firmware password ({ret.name})")


@click.command()
@click.argument("firmware_path")
def update(firmware_path: str):
    """
    Run firmware update with the provided binary.

    FIRMWARE_PATH: A path to the firmware file. File name should end with .bin.
    """
    import nkdfu.dfu as dfu
    import usb1

    check_pynitrokey_version()

    print = local_print
    # TODO(szszsz): extract logic to nkdfu, leaving only end-user error handling
    assert firmware_path.endswith("bin")
    vendor_str = "20a0:42b4"
    vendor_str, product_str = vendor_str.split(":")
    product = int(product_str, 16)
    vendor = int(vendor_str, 16)
    dev = None
    bus = None
    with usb1.USBContext() as context:
        for device in context.getDeviceList():
            if (
                vendor is not None
                and (
                    vendor != device.getVendorID()
                    or (product is not None and product != device.getProductID())
                )
            ) or (
                bus is not None
                and (
                    bus != device.getBusNumber()
                    or (dev is not None and dev != device.getDeviceAddress())
                )
            ):
                continue
            break
        else:
            print("No Nitrokey Pro found in the update mode.")
            print(
                "If you have Nitrokey Pro connected please run (requires libnitrokey):"
            )
            print("$ nitropy pro enable-update")
            sys.exit(1)
        dfu_device = None
        try:
            dfu_device = dfu.DFU(device.open())
        except usb1.USBErrorAccess as e:  # type: ignore[attr-defined]
            print(f"Cannot connect to the device: {device} -> {e}")
            if "LIBUSB_ERROR_ACCESS" in str(e) and platform.system().lower() == "linux":
                print(
                    "Try to install UDEV rules, e.g. by executing the following:"
                )  # TODO add command for that
                print(
                    "$ curl https://raw.githubusercontent.com/Nitrokey/libnitrokey/master/data/41-nitrokey.rules | sudo tee /usr/lib/udev/rules.d/41-nitrokey.rules"
                )
                print("$ sudo udevadm control --reload-rules; sudo udevadm trigger")
            sys.exit(1)
        except Exception as e:
            print(f"Cannot connect to the device: {device} -> {e}")
            sys.exit(1)

        print(f"Using firmware file {firmware_path}")
        hex_firmware = ih.IntelHex()
        hex_firmware.fromfile(open(firmware_path, "rb"), "bin")
        data = hex_firmware.tobinarray()
        try:
            print((dfu_device.download(data)))
            print("Please reinsert device to the USB port to complete the process")
        except nkdfu.dfu.DFUBadSate as e:
            print(f"Cannot connect to the device: {device} -> {e}")
            print(
                "Reinsert device to the USB port and try again (DFU connects, but reports invalid state)"
            )
            sys.exit(1)
        except Exception as e:
            print(f"Cannot connect to the device: {device} -> {e}")
            sys.exit(1)


pro.add_command(update)
pro.add_command(list)
pro.add_command(enable_update)
pro.add_command(change_firmware_password)
