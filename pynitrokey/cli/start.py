# -*- coding: utf-8 -*-
#
# Copyright 2020 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
import binascii
import typing
from subprocess import check_output
from sys import stderr, stdout
from time import sleep

import click
from smartcard.Exceptions import CardConnectionException
from smartcard.pcsc.PCSCExceptions import EstablishContextException
from tqdm import tqdm
from usb.core import USBError

from pynitrokey.helpers import local_critical, local_print
from pynitrokey.start.gnuk_token import OnlyBusyICCError, get_gnuk_device
from pynitrokey.start.threaded_log import ThreadLog
from pynitrokey.start.upgrade_by_passwd import (
    DEFAULT_PW3,
    DEFAULT_WAIT_FOR_REENUMERATION,
    IS_LINUX,
    kill_smartcard_services,
    logger,
    restart_smartcard_services,
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


class CardRemovedGPGAgentException(RuntimeWarning):
    pass


def gpg_agent_set_identity(identity: int):
    from pexpect import run

    cmd = f"gpg-connect-agent 'SCD APDU 00 85 00 0{identity}' /bye"
    app = run(cmd)
    print(cmd)
    print(app)
    if b"ERR 100663406 Card removed" in app:
        raise CardRemovedGPGAgentException("Card removed")


def pcsc_set_identity(identity):
    try:
        from smartcard import System
        from smartcard.CardConnection import CardConnection
        from smartcard.Exceptions import NoCardException

        def find_smartcard(uuid: typing.Optional[int] = None) -> CardConnection:
            for reader in System.readers():
                if "Nitrokey Start" not in str(reader):
                    continue
                conn = reader.createConnection()
                try:
                    conn.connect()
                except NoCardException:
                    continue
                #     use this for debug
                # sudo pcscd -f -a

                # if not select(conn, AID_ADMIN):
                #     continue
                # data, sw1, sw2 = conn.transmit([0x00, 0x62, 0x00, 0x00, 16])
                print(reader)
                print(conn)
                return conn
            # raise Exception(f"No smartcard with UUID {uuid:X} found")

        def select(conn: CardConnection, aid: bytes) -> bool:
            apdu = [0x00, 0xA4, 0x04, 0x00]
            apdu.append(len(aid))
            apdu.extend(aid)
            _, sw1, sw2 = conn.transmit(apdu)
            return (sw1, sw2) == (0x90, 0x00)

        def send_id_change(conn: CardConnection, identity: int) -> None:
            #  00 85 00 02
            out = [0x00, 0x85, 0x00, identity]
            for i in range(5):
                data, sw1, sw2 = conn.transmit(out)
                print((bytes(out).hex(), data, hex(sw1), hex(sw2)))
                res = bytes([sw1, sw2]).hex()
                if res == "9000":
                    print("success")
                    break
                if res == "6a88":
                    print(f"error: {res}")
                    continue

        conn = find_smartcard()
        aid = binascii.a2b_hex("D276:0001:2401".replace(":", ""))
        select(conn, aid)
        send_id_change(conn, identity)

    except ImportError:
        logger.debug("pcsc feature is deactivated, skipping firmware mode test")
        pass


@click.command()
@click.argument("identity")
def set_identity(identity):
    """Set given identity (one of: 0, 1, 2)

    Might require stopping other smart card services to connect directly to the device over CCID interface.
    These will be restarted after operation, if it is required.

    This could be replaced with:

    gpg-connect-agent "SCD APDU 00 85 00 0<IDENTITY>"
    """
    if not identity.isdigit():
        local_critical("identity number must be a digit")

    identity = int(identity)
    if identity < 0 or identity > 2:
        local_critical("identity must be 0, 1 or 2")

    local_print(f"Setting identity to {identity}")

    # Note: the error in communication coming after changing the identity is caused by the immediate restart of
    # the device, without responding to the call. The idea was to avoid operating with a potentially inconsistent state in
    # the memory.
    def inner():
        """
        Call all the methods in the order of the success chance
        """

        # this works when gpg has opened connection, stops after changing identity with it
        try:
            gpg_agent_set_identity(identity)
            return True
        except CardRemovedGPGAgentException:
            # this error shows up when the identity was just changed with gpg, and the new state was not reloaded
            pass

        # this works when gpg has no connection, but pcsc server is working
        try:
            pcsc_set_identity(identity)
            print(f"PCSC change works")
            return True
        except CardConnectionException as e:
            print(f"Expected error. PCSC reports {e}")
            # this error is expected after sucessfully changing the identity
            return True
        except EstablishContextException:
            # pcscd must not work, try another method
            local_print("pcscd must not work, try another method")

        # this works, when neither gnupg nor opensc is claiming the smart card interface
        try:
            set_identity_raw(identity)
        except:
            raise

    inner()
    # apparently calling it 2 times reloads the gnupg, and allows for immediate use of it after changing the identity
    # otherwise its reload is needed with gpgconf --reload all
    inner()
    local_print(f"Reset done - now active identity: {identity}")


def set_identity_raw(identity):
    for x in range(3):
        try:
            gnuk = get_gnuk_device()
            with gnuk.release_on_exit() as gnuk:
                gnuk.cmd_select_openpgp()
                try:
                    gnuk.cmd_set_identity(identity)
                    break
                except USBError:
                    # local_print(f"Reset done - now active identity: {identity}")
                    break

        except OnlyBusyICCError:
            local_print(
                "Device is occupied by some other service and cannot be connected to. Identity not changed."
            )
            break
        except ValueError as e:
            if "No ICC present" in str(e):
                local_print(
                    "Device is occupied by some other service and cannot be connected to. Identity not changed."
                )
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
):
    """update device's firmware"""

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

    if IS_LINUX:
        with ThreadLog(logger.getChild("dmesg"), "dmesg -w"):
            start_update(*args)
    else:
        start_update(*args)


@click.command()
@click.option("--passwd", default="", help="password")
def kdf_details(passwd):
    return show_kdf_details(passwd)


start.add_command(rng)
start.add_command(list)
start.add_command(set_identity)
start.add_command(update)
start.add_command(kdf_details)
