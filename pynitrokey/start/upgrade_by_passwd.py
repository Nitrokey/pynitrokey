#! /usr/bin/env python3

"""
upgrade_by_passwd.py - a tool to install another firmware for Gnuk Token
                       which is just shipped from factory

Copyright (C) 2012, 2013, 2015, 2018
              Free Software Initiative of Japan
Author: NIIBE Yutaka <gniibe@fsij.org>
Copyright (C) 2020 Nitrokey Gmbh

This file is a part of Gnuk, a GnuPG USB Token implementation.

Gnuk is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Gnuk is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from pprint import pprint

IMPORT_ERROR_HELP = """
Some required modules are missing from this environment.
Please install the following packages:
    pyusb requests
e.g. with the following command to install all dependencies:
    python3 -m pip install -r ./requirements.txt
(while being in the ./tool directory)
"""

try:
    import requests
    import usb  # noqa
except ImportError:
    print(IMPORT_ERROR_HELP)
    exit(1)

import binascii
import hashlib
import logging
import os
import platform
import time
from collections import defaultdict
from datetime import datetime
from enum import Enum
from functools import lru_cache
from struct import pack
from subprocess import check_output

import requests
from click import BadParameter

import pynitrokey.start.rsa as rsa
from pynitrokey.confconsts import LOG_FN, LOG_FORMAT_STDOUT
from pynitrokey.helpers import AskUser, local_critical, local_print
from pynitrokey.start.gnuk_token import (
    SHA256_OID_PREFIX,
    crc32,
    get_gnuk_device,
    gnuk_devices_by_vidpid,
    parse_kdf_data,
    regnual,
)
from pynitrokey.start.kdf_calc import kdf_calc
from pynitrokey.start.rsa_pub_key import rsa_key_data

# from pynitrokey.start.threaded_log import ThreadLog
from pynitrokey.start.usb_strings import get_devices, print_device

# This should be event driven, not guessing some period, or polling.
# @todo: move to confconsts.py
TIME_DETECT_DEVICE_AFTER_UPDATE_LONG_S = 5
TIME_DETECT_DEVICE_AFTER_UPDATE_S = 30
ERR_EMPTY_COUNTER = "6983"
ERR_INVALID_PIN = "6982"
DEFAULT_WAIT_FOR_REENUMERATION = 20
DEFAULT_PW3 = "12345678"
BY_ADMIN = 3
KEYNO_FOR_AUTH = 2
IS_LINUX = platform.system() == "Linux"

logger = logging.getLogger()


def progress_func(x):
    x = x * 100
    if x == 0:
        progress_func.last = 0

    if progress_func.last * 10 <= x < 100:
        progress_func.last += 1
        local_print(f"Progress: {round(x, 2)}%\r", end="", flush=True)


progress_func.last = 0  # type: ignore


def main(
    wait_e, keyno, passwd, data_regnual, data_upgrade, skip_bootloader, verbosity=0
):
    reg = None

    # @todo: this is constantly used: how about a consistent/generic solution?
    conn_retries = 3

    for i in range(conn_retries):
        if reg is not None:
            break

        local_print(".", end="", flush=True)
        time.sleep(1)

        for dev in gnuk_devices_by_vidpid():
            try:
                reg = regnual(dev)
                if dev.filename:
                    local_print(f"Device: {dev.filename}")
                reg.set_logger(logger)
                break
            except Exception as e:
                if str(e) != "Wrong interface class":
                    local_print(e)

    if reg is None and not skip_bootloader:
        local_print("", "Starting bootloader upload procedure")

        _l = len(data_regnual)
        if (_l & 0x03) != 0:
            data_regnual = data_regnual.ljust(_l + 4 - (_l & 0x03), chr(0))
        crc32code = crc32(data_regnual)

        # @todo: use global verbosity
        if verbosity:
            local_print("CRC32: %04x\n" % crc32code)
        data_regnual += pack("<I", crc32code)

        rsa_key = rsa.read_key_from_list(rsa_key_data)
        rsa_raw_pubkey = rsa.get_raw_pubkey(rsa_key)

        gnuk = get_gnuk_device(logger=logger)
        gnuk.cmd_select_openpgp()
        local_print("Connected to the device")

        # Compute passwd data
        try:
            kdf_data = gnuk.cmd_get_data(0x00, 0xF9).tobytes()
        except Exception as e:
            local_print("Note: KDF DO not found", e)
            kdf_data = b""

        if kdf_data == b"":
            passwd_data = passwd.encode("UTF-8")
        else:
            (
                algo,
                subalgo,
                iters,
                salt_user,
                salt_reset,
                salt_admin,
                hash_user,
                hash_admin,
            ) = parse_kdf_data(kdf_data)

            salt = salt_admin if salt_admin else salt_user
            passwd_data = kdf_calc(passwd, salt, iters)

        # And authenticate with the passwd data
        gnuk.cmd_verify(BY_ADMIN, passwd_data)
        gnuk.cmd_write_binary(1 + keyno, rsa_raw_pubkey, False)

        gnuk.cmd_select_openpgp()
        challenge = gnuk.cmd_get_challenge().tobytes()
        digestinfo = binascii.unhexlify(SHA256_OID_PREFIX) + challenge
        signed = rsa.compute_signature(rsa_key, digestinfo)
        signed_bytes = rsa.integer_to_bytes_256(signed)
        gnuk.cmd_external_authenticate(keyno, signed_bytes)
        gnuk.stop_gnuk()

        mem_info = gnuk.mem_info()
        # @todo: use global verbosity
        if verbosity:
            local_print("%08x:%08x" % mem_info)

        local_print(
            "Running update!",
            "Do NOT remove the device from the USB slot, until further notice",
            "Downloading flash upgrade program...",
        )

        gnuk.download(
            mem_info[0],
            data_regnual,
            progress_func=progress_func,
            verbose=verbosity == 2,
        )

        local_print("Executing flash upgrade...")

        for i in range(conn_retries):
            time.sleep(1.5 * (i + 1))
            try:
                gnuk.execute(mem_info[0] + len(data_regnual) - 4)
                break
            except Exception as e:
                local_print(f"failed - trying again - retry: {i+1}", e)
                if i == conn_retries - 1:
                    raise e
                continue

        time.sleep(3)
        gnuk.reset_device()

        del gnuk
        gnuk = None

    if reg is None:
        local_print("Waiting for device to appear:")
        local_print(f"  Wait {wait_e} second{'s' if wait_e > 1 else ''}...", end="")

        for i in range(wait_e):
            if reg is not None:
                break

            local_print(".", end="", flush=True)
            time.sleep(1)

            for dev in gnuk_devices_by_vidpid():
                try:
                    reg = regnual(dev)
                    if dev.filename:
                        local_print("Device: {dev.filename}")
                    break
                except Exception as e:
                    local_print(f"failed - trying again - retry: {i+1}", e)
                    # @todo: log exception to file: e

        local_print("", "")
        if reg is None:
            # @todo: replace with proper Exception
            raise RuntimeWarning("device not found - exiting")

    # Then, send upgrade program...
    mem_info = reg.mem_info()

    # @todo: use global verbosity
    if verbosity:
        local_print("%08x:%08x" % mem_info)

    local_print("Downloading the program")
    reg.download(
        mem_info[0], data_upgrade, progress_func=progress_func, verbose=verbosity == 2
    )

    local_print("Protecting device")
    reg.protect()

    local_print("Finish flashing")
    reg.finish()

    local_print("Resetting device")
    reg.reset_device()

    local_print("Update procedure finished. Device could be removed from USB slot.", "")

    return 0


@lru_cache()
def get_latest_release_data():
    try:
        # @todo: move to confconsts.py
        r = requests.get(
            "https://api.github.com/repos/Nitrokey/nitrokey-start-firmware/releases/latest"
        )
        json = r.json()
        if r.status_code == 403:
            local_critical(
                f"JSON raw data: {json}",
                f"No Github API access, status code: {r.status_code}",
            )
        latest_tag = json

    except Exception as e:
        local_critical("Failed getting release data", e)
        latest_tag = defaultdict(lambda: "unknown")

    return latest_tag


def validate_binary_file(path: str):
    import os.path

    if not os.path.exists(path):
        raise BadParameter('Path does not exist: "{}"'.format(path))
    if not path.endswith(".bin"):
        raise BadParameter(
            'Supplied file "{}" does not have ".bin" extension. '
            "Make sure you are sending correct file to the device.".format(
                os.path.basename(path)
            )
        )
    return path


def validate_name(path: str, name: str):
    if name not in path:
        raise BadParameter(
            'Supplied file "{}" does not have "{}" in name. '
            "Make sure you have not swapped the arguments.".format(
                os.path.basename(path), name
            )
        )
    return path


def validate_gnuk(ctx, param, path: str):
    if path is None:
        return path

    validate_binary_file(path)
    validate_name(path, "gnuk")
    return path


def validate_regnual(ctx, param, path: str):
    if path is None:
        return path

    validate_binary_file(path)
    validate_name(path, "regnual")
    return path


def kill_smartcard_services():
    local_print("Could not connect to the device. Attempting to close scdaemon.")

    # check_output(["gpg-connect-agent",
    #               "SCD KILLSCD", "SCD BYE", "/bye"])
    commands = [
        ("gpgconf --kill all".split(), True),
        ("sudo systemctl stop pcscd pcscd.socket".split(), IS_LINUX),
    ]

    for command, flag in commands:
        if not flag:
            continue
        local_print(f"Running: {' '.join(command)}")
        try:
            check_output(command)
        except Exception as e:
            local_print("Error while running command", e)

    time.sleep(3)


# @fixme: maybe also move to confconsts.py?
class FirmwareType(Enum):
    UNKNOWN = 0
    REGNUAL = 1
    GNUK = 2
    CHECKSUM = 3


# @fixme: move constants to confconsts.py
REMOTE_PATH = "https://raw.githubusercontent.com/Nitrokey/nitrokey-start-firmware/gnuk1.2-regnual-fix/prebuilt"
FIRMWARE_URL = {
    FirmwareType.REGNUAL: ("%s/{}/regnual.bin" % REMOTE_PATH),
    FirmwareType.GNUK: ("%s/{}/gnuk.bin" % REMOTE_PATH),
    FirmwareType.CHECKSUM: ("%s/checksums.sha512" % REMOTE_PATH),
}


def hash_data_512(data):
    hash512 = hashlib.sha512(data).digest()
    hash512_hex = binascii.b2a_hex(hash512)
    return hash512_hex


def validate_hash(url: str, hash: bytes):
    checksums = download_file_or_exit(FIRMWARE_URL.get(FirmwareType.CHECKSUM, None))
    name = " " + "/".join(url.split("/")[-2:])
    for line in checksums.splitlines():
        if name in line.decode():
            hash_expected, hash_name = line.split()
            logger.debug(
                "{} {}/{} {}".format(  # type: ignore
                    hash_expected == hash,
                    hash_name,
                    name,
                    hash[-8:],
                    hash_expected[-8:],
                )
            )
            return hash_expected == hash
    return False


def get_firmware_file(file_name: str, type: FirmwareType):
    if file_name:
        with open(file_name, "rb") as f:
            firmware_data = f.read()
        local_print("- {}: {}".format(file_name, len(firmware_data)))
        return firmware_data

    tag = get_latest_release_data()["tag_name"]
    url = FIRMWARE_URL.get(type, None).format(tag)  # type: ignore
    firmware_data = download_file_or_exit(url)
    hash_data = hash_data_512(firmware_data)
    hash_valid = "valid" if validate_hash(url, hash_data) else "invalid"

    local_print(
        f"- {type}: {len(firmware_data)}, "
        f"hash: ...{hash_data[-8:]} {hash_valid} (from ...{url[-24:]})"
    )
    return firmware_data


@lru_cache()
def download_file_or_exit(url):
    resp = requests.get(url)
    if not resp.ok:
        local_critical(f"Cannot download firmware: {url}: {resp.status_code}")
    firmware_data = resp.content
    return firmware_data


def show_kdf_details(passwd):
    gnuk = None
    try:
        gnuk = get_gnuk_device(logger=logger, verbose=True)
    except ValueError as e:
        local_print("Connection error", e)
        if "No ICC present" in str(e):
            print("Cannot connect to device. Closing other open connections.")
            kill_smartcard_services()
            return
        else:
            raise
    gnuk.cmd_select_openpgp()
    # Compute passwd data
    try:
        kdf_data = gnuk.cmd_get_data(0x00, 0xF9).tobytes()
    except:
        kdf_data = b""
    if kdf_data == b"":
        print("KDF not set")
        # passwd_data = passwd.encode('UTF-8')
    else:
        (
            algo,
            subalgo,
            iters,
            salt_user,
            salt_reset,
            salt_admin,
            hash_user,
            hash_admin,
        ) = parse_kdf_data(kdf_data)
        if salt_admin:
            salt = salt_admin
        else:
            salt = salt_user
        d = {
            "algo": algo,
            "subalgo": subalgo,
            "iters": iters,
            "salt_user": binascii.b2a_hex(salt_user),
            "salt_reset": binascii.b2a_hex(salt_reset),
            "salt_admin": binascii.b2a_hex(salt_admin),
            "hash_user": binascii.b2a_hex(hash_user),
            "hash_admin": binascii.b2a_hex(hash_admin),
        }
        pprint(d, width=100)
        if passwd:
            try:
                passwd_data = kdf_calc(passwd, salt, iters)
                print(f"passwd_data: {binascii.b2a_hex(passwd_data)}")
            except ValueError as e:
                local_print("Error getting KDF", e)
        else:
            print("Provide password to calculate final hash")


def start_update(
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

    # @todo: move to some more generic position...
    local_print("Nitrokey Start firmware update tool")
    # @fixme: especially this, which is to be handle application wide
    logger.debug("Start session {}".format(datetime.now()))
    local_print("Platform: {}".format(platform.platform()))
    local_print("System: {}, is_linux: {}".format(platform.system(), IS_LINUX))
    local_print("Python: {}".format(platform.python_version()))
    local_print("Saving run log to: {}".format(LOG_FN))

    arg_descs = [
        "regnual",
        "gnuk",
        "default_password",
        "password",
        "wait_e",
        "keyno",
        "verbose",
        "yes",
        "skip_bootloader",
        "green_led",
    ]
    args = (
        regnual,
        gnuk,
        default_password,
        "<hidden>",
        wait_e,
        keyno,
        verbose,
        yes,
        skip_bootloader,
        green_led,
    )
    logger.debug(
        "Arguments: "
        + ", ".join(f"{key}= '{val}'" for key, val in zip(arg_descs, args))
    )

    passwd = None

    if verbose == 3:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.DEBUG)
        stream_handler.setFormatter(logging.Formatter(LOG_FORMAT_STDOUT))
        logger.addHandler(stream_handler)

    if password:
        passwd = password
    elif default_password:
        passwd = DEFAULT_PW3
    if not passwd:
        try:
            passwd = AskUser.hidden("Admin password:")
        except Exception as e:
            local_critical("aborting update", e)

    local_print("Firmware data to be used:")
    data = get_firmware_file(regnual, FirmwareType.REGNUAL)
    data_upgrade = get_firmware_file(gnuk, FirmwareType.GNUK)

    # Detect devices
    dev_strings = get_devices()
    if len(dev_strings) > 1:
        local_critical(
            "Only one device should be connected",
            "Please remove other devices and retry",
        )

    if dev_strings:
        local_print("Currently connected device strings:")
        print_device(dev_strings[0])
    else:
        local_print("Cannot identify device")

    # @todo: debugging information, log-file only
    local_print(f"initial device strings: {dev_strings}")

    latest_tag = get_latest_release_data()

    local_print(
        "Please note:",
        "- Latest firmware available is: ",
        f"  {latest_tag['tag_name']} (published: {latest_tag['published_at']})",
        f"- provided firmware: {gnuk}",
        "- all data will be removed from the device!",
        "- do not interrupt update process - the device may not run properly!",
        "- the process should not take more than 1 minute",
        "- if the update fails, do not remove the device! Repeat the update instead.",
    )
    if yes:
        local_print("Accepted automatically")
    else:
        if not AskUser.strict_yes_no("Do you want to continue?"):
            local_critical("Exiting due to user request", support_hint=False)

    update_done = False
    retries = 3
    for attempt_counter in range(retries):
        try:
            # First 4096-byte in data_upgrade is SYS, so, skip it.
            main(
                wait_e,
                keyno,
                passwd,
                data,
                data_upgrade[4096:],
                skip_bootloader,
                verbosity=verbose,
            )
            update_done = True
            break

        # @todo: add proper exceptions (for each case) here
        except ValueError as e:
            local_print("error while running update", e)
            str_factory_reset = (
                "Please 'factory-reset' your device to "
                "continue (this will delete all user data from the device) "
                "and try again with PIN='12345678'"
            )

            if "No ICC present" in str(e):
                kill_smartcard_services()
                local_print("retrying...")

            else:
                # @fixme run factory reset here since data are lost anyway (rly?)
                if str(e) == ERR_EMPTY_COUNTER:
                    local_critical(
                        "- device returns: 'Attempt counter empty' "
                        "- error for Admin PIN",
                        str_factory_reset,
                        e,
                    )

                if str(e) == ERR_INVALID_PIN:
                    local_critical(
                        "- device returns: 'Invalid PIN' error",
                        "- please retry with correct PIN",
                        e,
                    )
        except Exception as e:
            local_critical("unexpected error", e)

    if not update_done:
        local_critical(
            "",
            "Could not proceed with the update",
            "Please execute one or all of the following and try again:",
            "- run factory-reset on the device",
            "- close other applications, which could use it (e.g., scdaemon, pcscd)",
            "- repeat the update",
        )

    dev_strings_upgraded = None
    takes_long_time = False
    local_print("Currently connected device strings (after upgrade):")
    for i in range(TIME_DETECT_DEVICE_AFTER_UPDATE_S):
        if i > TIME_DETECT_DEVICE_AFTER_UPDATE_LONG_S:
            if not takes_long_time:
                local_print(
                    "",
                    "If you have removed the device, please reinsert it to the USB slot",
                )
                takes_long_time = True
        time.sleep(1)
        dev_strings_upgraded = get_devices()
        if len(dev_strings_upgraded) > 0:
            local_print()
            print_device(dev_strings_upgraded[0])
            break
        local_print(".", end="", flush=True)

    if not dev_strings_upgraded:
        local_critical(
            "",
            "could not connect to the device - might be due to a failed update",
            "please check the device version with:",
            "$ nitropy start list",
            "and repeat the update if necessary",
        )

    local_print(
        "device can now be safely removed from the USB slot",
        f"final device strings: {dev_strings_upgraded}",
    )

    # @todo: add this to all logs and skip it here
    local_print(f"finishing session {datetime.now()}")
    # @todo: always output this in certain situations... (which ones? errors? warnings?)
    local_print(f"Log saved to: {LOG_FN}")
