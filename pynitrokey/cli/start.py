# -*- coding: utf-8 -*-
#
# Copyright 2020 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import fnmatch
import os
import os.path
from subprocess import check_output
from sys import stderr, stdout
from time import sleep

import click
from tqdm import tqdm
from usb.core import USBError

from pynitrokey.helpers import confirm_keyboard_interrupt, local_critical, local_print
from pynitrokey.start.gnuk_token import get_gnuk_device
from pynitrokey.start.threaded_log import ThreadLog
from pynitrokey.start.upgrade_by_passwd import (
    DEFAULT_PW3,
    DEFAULT_WAIT_FOR_REENUMERATION,
    IS_LINUX,
    logger,
    show_kdf_details,
    start_update,
    validate_gnuk,
    validate_regnual,
)
from pynitrokey.start.usb_strings import get_devices as get_devices_strings

# @fixme: add 'version' for consistency with fido2


# https://pocoo-click.readthedocs.io/en/latest/commands/#nested-handling-and-contexts
@click.group()
def start():
    """Interact with Nitrokey Start devices, see subcommands."""
    pass


@click.command()
@click.option(
    "--verbose", default=False, is_flag=True, help="Print all available information."
)
def list(verbose=False):
    """list connected devices"""
    local_print(":: 'Nitrokey Start' keys:")
    for dct in get_devices_strings():
        local_print(
            f"{dct['Serial']}: {dct['Vendor']} " f"{dct['Product']} ({dct['Revision']})"
        )
        if verbose:
            local_print(f"{dct}")


@click.command()
@click.option("--count", default=64, type=int, help="Number of bytes to get.")
@click.option(
    "--raw", default=False, is_flag=True, help="Get raw bytes (ASCII by default)."
)
@click.option("--quiet", default=False, is_flag=True, help="Do not show progress bar.")
def rng(count, raw, quiet):
    """Get random data from device by executing GET CHALLENGE command."""
    gnuk = get_gnuk_device(verbose=False)
    gnuk.cmd_select_openpgp()
    i = 0
    with tqdm(
        total=count,
        file=stderr,
        disable=quiet or not raw,
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
    ) as bar:
        while i < count:
            try:
                challenge = gnuk.cmd_get_challenge().tobytes()
                # cap at count bytes
                challenge = challenge[: count - i]
                i += len(challenge)
                bar.update(len(challenge))
            except Exception as e:
                print(count)
                raise e
            if raw:
                stdout.buffer.write(challenge)
            else:
                print(challenge.hex())


@click.command()
@click.argument("identity")
def set_identity(identity):
    """set given identity (one of: 0, 1, 2)"""
    if not identity.isdigit():
        local_critical("identity number must be a digit")

    identity = int(identity)
    if identity < 0 or identity > 2:
        local_print("identity must be 0, 1 or 2")

    local_print(f"Setting identity to {identity}")
    for x in range(3):
        try:
            gnuk = get_gnuk_device()
            gnuk.cmd_select_openpgp()
            try:
                gnuk.cmd_set_identity(identity)
            except USBError:
                local_print(f"reset done - now active identity: {identity}")
                break

        except ValueError as e:
            if "No ICC present" in str(e):
                local_print("Could not connect to device, trying to close scdaemon")
                result = check_output(
                    ["gpg-connect-agent", "SCD KILLSCD", "SCD BYE", "/bye"]
                )  # gpgconf --kill all might be better?
                sleep(3)
            else:
                local_critical(e)
        except Exception as e:
            local_critical(e)


@click.command()
@click.option(
    "--regnual", default=None, callback=validate_regnual, help="path to regnual binary"
)
@click.option(
    "--gnuk", default=None, callback=validate_gnuk, help="path to gnuk binary"
)
@click.option(
    "-f",
    "default_password",
    is_flag=True,
    default=False,
    help=f"use default Admin PIN: {DEFAULT_PW3}",
)
@click.option("-p", "password", help="use provided Admin PIN")
@click.option(
    "-e",
    "wait_e",
    default=DEFAULT_WAIT_FOR_REENUMERATION,
    type=int,
    help="time to wait for device to enumerate, after regnual was executed on device",
)
@click.option("-k", "keyno", default=0, type=int, help="selected key index")
@click.option("-v", "verbose", default=0, type=int, help="verbosity level")
@click.option("-y", "yes", default=False, is_flag=True, help="agree to everything")
@click.option(
    "-b",
    "skip_bootloader",
    default=False,
    is_flag=True,
    help="Skip bootloader upload (e.g. when done so already)",
)
@click.option(
    "--green-led",
    is_flag=True,
    default=False,
    help="Use firmware for early 'Nitrokey Start' key hardware revisions",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Execute the firmware update even if environment sanity checks fail",
)
def update(
    regnual,
    gnuk,
    default_password,
    password,
    wait_e,
    keyno,
    verbose,
    yes,
    skip_bootloader,
    green_led,
    force,
):
    """update device's firmware"""

    if not find_udev_rules():
        if force:
            local_print(
                "Warning: Could not find Nitrokey udev rules but will continue anyway as --force is set."
            )
        else:
            local_critical(
                "Failed to find Nitrokey udev rules.  These udev rules are required for the update.",
                "Please see the nitropy documentation for information on installing these rules:",
                "    https://docs.nitrokey.com/software/nitropy/linux/udev.html",
                "If you want to continue anyway, you can use the --force option.",
                support_hint=False,
            )

    args = (
        regnual,
        gnuk,
        default_password,
        password,
        wait_e,
        keyno,
        verbose,
        yes,
        skip_bootloader,
        green_led,
    )

    if green_led and (regnual is None or gnuk is None):
        local_critical(
            "You selected the --green-led option, please provide '--regnual' and "
            "'--gnuk' in addition to proceed. ",
            "use one from: https://github.com/Nitrokey/nitrokey-start-firmware)",
        )

    with confirm_keyboard_interrupt("Cancelling the update may brick your device."):
        if IS_LINUX:
            with ThreadLog(logger.getChild("dmesg"), "dmesg -w"):
                start_update(*args)
        else:
            start_update(*args)


def find_udev_rules() -> bool:
    dirs = [
        "/usr/lib/udev/rules.d",
        "/usr/local/lib/udev/rules.d",
        "/run/udev/rules.d",
        "/etc/udev/rules.d",
    ]
    for d in dirs:
        if os.path.isdir(d):
            for name in os.listdir(d):
                if fnmatch.fnmatch(name, "??-nitrokey.rules"):
                    logger.info(f"Found matching udev file at {os.path.join(d, name)}")
                    return True
    return False


@click.command()
@click.option("--passwd", default="", help="password")
def kdf_details(passwd):
    return show_kdf_details(passwd)


start.add_command(rng)
start.add_command(list)
start.add_command(set_identity)
start.add_command(update)
start.add_command(kdf_details)
