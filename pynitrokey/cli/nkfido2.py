# Copyright 2019 SoloKeys Developers
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import json
import os
import platform
import struct
import sys
import time
from typing import List, Optional

if "linux" in platform.platform().lower():
    import fcntl

import click
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.hid import CtapHidDevice

import pynitrokey.fido2 as nkfido2
import pynitrokey.fido2.operations
from pynitrokey.cli.monitor import monitor
from pynitrokey.cli.program import program
from pynitrokey.cli.update import update
from pynitrokey.helpers import local_critical, local_print


@click.group()
def rng() -> None:
    """Access TRNG on device, see subcommands."""
    pass


@click.group()
def util() -> None:
    """Additional utilities, see subcommands."""
    pass


# @todo: is this working as intended?
@click.command()
@click.option("--input-seed-file")
@click.argument("output_pem_file")
def genkey(input_seed_file: Optional[str], output_pem_file: str) -> None:
    """Generates key pair that can be used for Solo signed firmware updates.

    \b
    * Generates NIST P256 keypair.
    * Public key must be copied into correct source location in solo bootloader
    * The private key can be used for signing updates.
    * You may optionally supply a file to seed the RNG for key generating.
    """

    vk = pynitrokey.fido2.operations.genkey(
        output_pem_file, input_seed_file=input_seed_file
    )

    local_print(
        "Public key in various formats:",
        None,
        [c for c in vk.to_string()],
        None,
        "".join(["%02x" % c for c in vk.to_string()]),
        None,
        '"\\x' + "\\x".join(["%02x" % c for c in vk.to_string()]) + '"',
        None,
    )


# @todo: is this working as intended ?
@click.command()
@click.argument("verifying-key")
@click.argument("app-hex")
@click.argument("output-json")
@click.option("--pages", default=128, type=int, help="Size of the MCU flash in pages")
@click.option(
    "--end_page",
    help="Set APPLICATION_END_PAGE. Shall be in sync with firmware settings",
    default=20,
    type=int,
)
def sign(
    verifying_key: str, app_hex: str, output_json: str, end_page: int, pages: int
) -> None:
    """Signs a fw-hex file, outputs a .json file that can be used for signed update."""

    msg = pynitrokey.fido2.operations.sign_firmware(
        verifying_key, app_hex, APPLICATION_END_PAGE=end_page, PAGES=pages
    )
    local_print(f"Saving signed firmware to: {output_json}")
    with open(output_json, "wb+") as fh:
        fh.write(json.dumps(msg).encode())


@click.command()
@click.option("--attestation-key", help="attestation key in hex")
@click.option("--attestation-cert", help="attestation certificate file")
@click.option(
    "--lock",
    help="Indicate to lock device from unsigned changes permanently.",
    default=False,
    is_flag=True,
)
@click.argument("input_hex_files", nargs=-1)
@click.argument("output_hex_file")
@click.option(
    "--end_page",
    help="Set APPLICATION_END_PAGE. Should be in sync with firmware settings.",
    default=20,
    type=int,
)
@click.option(
    "--pages",
    help="Set MCU flash size in pages. Should be in sync with firmware settings.",
    default=128,
    type=int,
)
def mergehex(
    attestation_key: Optional[bytes],
    attestation_cert: Optional[bytes],
    lock: bool,
    input_hex_files: List[str],
    output_hex_file: str,
    end_page: int,
    pages: int,
) -> None:
    """Merges hex files, and patches in the attestation key.

    \b
    If no attestation key is passed, uses default Solo Hacker one.
    Note that later hex files replace data of earlier ones, if they overlap.
    """
    pynitrokey.fido2.operations.mergehex(
        input_hex_files,
        output_hex_file,
        attestation_key=attestation_key,
        APPLICATION_END_PAGE=end_page,
        attestation_cert=attestation_cert,
        lock=lock,
        PAGES=pages,
    )


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

    except pynitrokey.exceptions.NoSoloFoundError:
        local_critical(
            "No Nitrokey found.", "If you are on Linux, are your udev rules up to date?"
        )

    # unused ???
    except (pynitrokey.exceptions.NoSoloFoundError, ApduError):
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

# used for fw-signing... (does not seem to work @fixme)
util.add_command(sign)
util.add_command(genkey)
util.add_command(mergehex)
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
