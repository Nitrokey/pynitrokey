# Copyright 2019 SoloKeys Developers
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import os
import platform
import struct
import sys
import time
from typing import Optional

if "linux" in platform.platform().lower():
    import fcntl

import click
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.hid import CtapHidDevice

import pynitrokey.fido2 as nkfido2
from pynitrokey.cli.monitor import monitor
from pynitrokey.cli.program import program
from pynitrokey.cli.update import update
from pynitrokey.exceptions import NoSoloFoundError
from pynitrokey.helpers import local_critical, local_print


@click.group()
def rng() -> None:
    """Access TRNG on device, see subcommands."""
    pass


@click.group()
def util() -> None:
    """Additional utilities, see subcommands."""
    pass


@click.command()
def list() -> None:
    """List all 'Nitrokey FIDO2' devices"""
    devs = nkfido2.find_all()
    local_print(":: 'Nitrokey FIDO2' keys")
    for c in devs:
        assert isinstance(c.dev, CtapHidDevice)
        descr = c.dev.descriptor

        if hasattr(descr, "product_name"):
            name = descr.product_name
        elif c.is_bootloader():
            name = "FIDO2 Bootloader device"
        else:
            name = "FIDO2 device"

        if hasattr(descr, "serial_number"):
            id_ = descr.serial_number
        else:
            assert isinstance(descr.path, str)
            id_ = descr.path

        local_print(f"{id_}: {name}")


@click.command()
@click.option("--count", default=8, help="How many bytes to generate (defaults to 8)")
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
def hexbytes(count: int, serial: Optional[str]) -> None:
    """Output COUNT number of random bytes, hex-encoded."""

    if not 0 <= count <= 255:
        local_critical(f"Number of bytes must be between 0 and 255, you passed {count}")
    local_print(nkfido2.find(serial).get_rng(count).hex())


# @todo: not really useful like this? endless output only on request (--count ?)
@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
def raw(serial: Optional[str]) -> None:
    """Output raw entropy endlessly."""
    p = nkfido2.find(serial)
    while True:
        r = p.get_rng(255)
        sys.stdout.buffer.write(r)


@click.command()
@click.option("--count", default=64, help="How many bytes to generate (defaults to 8)")
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
def feedkernel(count: int, serial: Optional[str]) -> None:
    """Feed random bytes to /dev/random."""

    if os.name != "posix":
        local_critical("This is a Linux-specific command!")

    if not 0 <= count <= 255:
        local_critical(f"Number of bytes must be between 0 and 255, you passed {count}")

    p = nkfido2.find(serial)

    RNDADDENTROPY = 0x40085203

    entropy_info_file = "/proc/sys/kernel/random/entropy_avail"
    print(f"entropy before: 0x{open(entropy_info_file).read().strip()}")

    r = p.get_rng(count)

    # man 4 random

    # RNDADDENTROPY
    #       Add some additional entropy to the input pool, incrementing the
    #       entropy count. This differs from writing to /dev/random or
    #       /dev/urandom, which only adds some data but does not increment the
    #       entropy count. The following structure is used:

    #           struct rand_pool_info {
    #               int    entropy_count;
    #               int    buf_size;
    #               __u32  buf[0];
    #           };

    #       Here entropy_count is the value added to (or subtracted from) the
    #       entropy count, and buf is the buffer of size buf_size which gets
    #       added to the entropy pool.

    # maximum 8, tend to be pessimistic
    entropy_bits_per_byte = 2
    t = struct.pack(f"ii{count}s", count * entropy_bits_per_byte, count, r)

    try:
        with open("/dev/random", mode="wb") as fh:
            fcntl.ioctl(fh, RNDADDENTROPY, t)

    except PermissionError as e:
        local_critical(
            "insufficient permissions to use `fnctl.ioctl` on '/dev/random'",
            "please run 'nitropy' with proper permissions",
            e,
        )

    local_print(f"entropy after:  0x{open(entropy_info_file).read().strip()}")


# @todo: also review, endless output only on request (--count ?)
@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option("-b", "--blink", is_flag=True, help="Blink in the meantime")
def status(serial: Optional[str], blink: bool) -> None:
    """Print device's status"""
    p = nkfido2.find(serial)
    t0 = time.time()
    while True:
        if time.time() - t0 > 5 and blink:
            p.wink()
        r = p.get_status()
        for b in r:
            local_print("{:#02d} ".format(b), end="")
        local_print("")
        time.sleep(0.3)


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
def version(serial: Optional[str]) -> None:
    """Version of firmware on device."""

    try:
        res = nkfido2.find(serial).solo_version()
        major, minor, patch = res[:3]
        locked = ""
        # @todo:
        if len(res) > 3:
            if res[3]:  # type: ignore
                locked = "locked"
            else:
                locked = "unlocked"
        local_print(f"{major}.{minor}.{patch} {locked}")

    except NoSoloFoundError:
        local_critical(
            "No Nitrokey found.", "If you are on Linux, are your udev rules up to date?"
        )

    # unused ???
    except (NoSoloFoundError, ApduError):
        local_critical(
            "Firmware is out of date (key does not know the NITROKEY_VERSION command)."
        )


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
def reboot(serial: Optional[str]) -> None:
    """Send reboot command to device (development command)"""
    local_print("Reboot", "Press key to confirm!")

    CTAP_REBOOT = 0x53
    dev = nkfido2.find(serial).dev
    try:
        assert isinstance(dev, CtapHidDevice)
        dev.call(CTAP_REBOOT ^ 0x80, b"")

    except OSError:
        local_print("...done")
    except CtapError as e:
        local_critical(f"...failed ({str(e)})")


rng.add_command(hexbytes)
rng.add_command(raw)
rng.add_command(feedkernel)

util.add_command(program)
util.add_command(monitor)


def add_commands(fido2: click.Group) -> None:

    fido2.add_command(list)
    # @fixme: this one exists twice, once here, once in "util program aux"
    fido2.add_command(reboot)
    fido2.add_command(rng)
    fido2.add_command(status)
    fido2.add_command(util)
    fido2.add_command(version)
    fido2.add_command(update)
