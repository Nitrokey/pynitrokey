# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import json
import os
import platform
import struct
import sys
from dataclasses import dataclass
from time import sleep, time
from typing import List, Literal, Optional

import click

if "linux" in platform.platform().lower():
    import fcntl

# @fixme: 1st layer `nkfido2` lower layer `fido2` not to be used here !
from fido2.cbor import dump_dict
from fido2.client import ClientError as Fido2ClientError
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2.base import Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocol
from fido2.hid import CtapHidDevice

import pynitrokey
import pynitrokey.fido2 as nkfido2
import pynitrokey.fido2.operations
from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.monitor import monitor
from pynitrokey.cli.program import program
from pynitrokey.cli.update import update
from pynitrokey.fido2 import client
from pynitrokey.fido2.client import NKFido2Client
from pynitrokey.fido2.commands import SoloBootloader
from pynitrokey.helpers import (
    AskUser,
    local_critical,
    local_print,
    require_windows_admin,
)

# @todo: in version 0.4 UDP & anything earlier inside fido2.__init__ is broken/removed
#        - check if/what is needed here
#        - revive UDP support

# https://pocoo-click.readthedocs.io/en/latest/commands/#nested-handling-and-contexts


@click.group()
def fido2() -> None:
    """Interact with Nitrokey FIDO2 devices, see subcommands."""
    require_windows_admin()


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


@click.group()
def rng() -> None:
    """Access TRNG on device, see subcommands."""
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
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option("--pin", help="provide PIN instead of asking the user", default=None)
def list_credentials(serial: str, pin: str) -> None:
    """List all credentials saved on the key as well as the amount of remaining slots."""

    # Makes sure pin exists
    if not pin:
        pin = AskUser.hidden("Please provide pin: ")

    nk_client = NKFido2Client()
    cred_manager = nk_client.cred_mgmt(serial, pin)

    # Returns Sequence[Mapping[int, Any]]
    # Use this to get all existing creds
    cred_metadata = cred_manager.get_metadata()
    cred_count = cred_metadata.get(CredentialManagement.RESULT.EXISTING_CRED_COUNT)
    remaining_cred_space = cred_metadata.get(
        CredentialManagement.RESULT.MAX_REMAINING_COUNT
    )

    if cred_count == 0:
        local_print("There are no registered credentials")
        local_print(
            f"There is an estimated amount of {remaining_cred_space} credential slots left"
        )
        return

    # Get amount of registered creds from first key in list (Same trick is used in the CredentialManager)
    local_print(f"There are {cred_count} registered credentials")

    reliable_party_list = cred_manager.enumerate_rps()

    for reliable_party_result in reliable_party_list:
        reliable_party = reliable_party_result.get(CredentialManagement.RESULT.RP)
        reliable_party_hash = reliable_party_result.get(
            CredentialManagement.RESULT.RP_ID_HASH
        )
        assert isinstance(reliable_party, dict)
        local_print("-----------------------------------")
        name_or_id = reliable_party.get("name", reliable_party.get("id", "(no id)"))
        local_print(f"{name_or_id}: ")
        for cred in cred_manager.enumerate_creds(reliable_party_hash):
            _cred_id = cred.get(CredentialManagement.RESULT.CREDENTIAL_ID)
            assert isinstance(_cred_id, dict)
            cred_id = _cred_id["id"]
            local_print(f"- id: {cred_id.hex()}")
            cred_user = cred.get(CredentialManagement.RESULT.USER)
            assert isinstance(cred_user, dict)
            display_name = cred_user.get("displayName")
            user_name = cred_user.get("name", "(no name)")
            if display_name is None or user_name == display_name:
                local_print(f"  user: {cred_user['name']}")
            else:
                local_print(f"  user: {display_name} ({cred_user['name']})")

    local_print("-----------------------------------")
    local_print(
        f"There is an estimated amount of {remaining_cred_space} credential slots left"
    )


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option("--pin", help="provide PIN instead of asking the user", default=None)
@click.option(
    "-cid", "--cred-id", help="Credential id of there Credential to be deleted"
)
def delete_credential(serial: str, pin: str, cred_id: str) -> None:
    """Delete a specific credential from the key"""

    if not cred_id:
        cred_id = AskUser.hidden("Please provide credential-id")

    if not pin:
        pin = AskUser.hidden("Please provide pin: ")

    nk_client = NKFido2Client()
    cred_manager = nk_client.cred_mgmt(serial, pin)

    tmp_cred_id = {"id": bytes.fromhex(cred_id), "type": "public-key"}

    # @todo: proper typing
    try:
        cred_manager.delete_cred(tmp_cred_id)  # type: ignore
    except Exception as e:
        local_critical("Failed to delete credential, was the right cred_id given?")
        return
    local_print("Credential was successfully deleted")


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
    t0 = time()
    while True:
        if time() - t0 > 5 and blink:
            p.wink()
        r = p.get_status()
        for b in r:
            local_print("{:#02d} ".format(b), end="")
        local_print("")
        sleep(0.3)


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


REQUIREMENT_CHOICE = click.Choice(["discouraged", "preferred", "required"])


@click.command()
@click.option(
    "--host", help="Relying party's host", default="nitrokeys.dev", show_default=True
)
@click.option("--user", help="User ID", default="they", show_default=True)
@click.option(
    "--resident-key",
    help="Whether to create a resident key",
    type=REQUIREMENT_CHOICE,
    default="discouraged",
    show_default=True,
)
@click.option(
    "--user-verification",
    help="Whether to perform user verification (PIN query)",
    type=REQUIREMENT_CHOICE,
    default="preferred",
    show_default=True,
)
def make_credential(
    host: str, user: str, resident_key: str, user_verification: str
) -> None:
    """Generate a credential.

    Pass `--prompt ""` to output only the `credential_id` as hex.
    """

    nkfido2.find().make_credential(
        host=host,
        user_id=user,
        output=True,
        resident_key=resident_key,
        user_verification=user_verification,
    )


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option("--host", help="Relying party's host", default="nitrokeys.dev")
@click.option("--user", help="User ID", default="they")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
@click.option(
    "--prompt",
    help="Prompt for user",
    default="Touch your authenticator to generate a response...",
    show_default=True,
)
@click.argument("credential-id")
@click.argument("challenge")
def challenge_response(
    serial: Optional[str],
    host: str,
    user: str,
    prompt: str,
    credential_id: str,
    challenge: str,
    udp: bool,
) -> None:
    """Uses `hmac-secret` to implement a challenge-response mechanism.

    We abuse hmac-secret, which gives us `HMAC(K, hash(challenge))`, where `K`
    is a secret tied to the `credential_id`. We hash the challenge first, since
    a 32 byte value is expected (in original usage, it's a salt).

    This means that we first need to setup a credential_id; this depends on the
    specific authenticator used. To do this, use `nitropy fido2 make-credential`.

    If so desired, user and relying party can be changed from the defaults.

    The prompt can be suppressed using `--prompt ""`.
    """

    nkfido2.find().simple_secret(
        credential_id,
        challenge,
        host=host,
        user_id=user,
        serial=serial,
        prompt=prompt,
        output=True,
        udp=udp,
    )


######
# @fixme: - excluded 'probe' for now, as command:
# SoloBootloader.HIDCommandProbe => 0x70 returns "INVALID_COMMAND"
# - decide its future asap...
@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
@click.argument("hash-type")
@click.argument("filename")
def probe(
    serial: Optional[str],
    udp: bool,
    hash_type: str,
    filename: str,
) -> None:
    """Calculate HASH"""

    # @todo: move to constsconf.py
    # all_hash_types = ("SHA256", "SHA512", "RSA2048", "Ed25519")
    all_hash_types = ("SHA256", "SHA512", "RSA2048")
    # @fixme: Ed25519 needs `nacl` dependency, which is not available currently?!

    if hash_type.upper() not in all_hash_types:
        local_critical(
            f"invalid [HASH_TYPE] provided: {hash_type}",
            f"use one of: {', '.join(all_hash_types)}",
        )

    data = open(filename, "rb").read()

    # < CTAPHID_BUFFER_SIZE
    # https://fidoalliance.org/specs/fido-v2.0-id-20180227/
    #             fido-client-to-authenticator-protocol-v2.0-id-20180227.html
    #             #usb-message-and-packet-structure
    # also account for padding (see data below....)
    # so 6kb is conservative

    # @todo: proper error/exception + cut in chunks?
    assert len(data) <= 6 * 1024

    p = nkfido2.find(serial, udp=udp)

    serialized_command = dump_dict({"subcommand": hash_type, "data": data})
    result = p.send_data_hid(SoloBootloader.HIDCommandProbe, serialized_command)
    result_hex = result.hex()
    local_print(result_hex)

    # @todo: unreachable
    if hash_type == "Ed25519":
        # @fixme: mmmh, where to get `nacl` (python-libnacl? python-pynacl?)
        import nacl.signing

        # print(f"content from hex: {bytes.fromhex(result_hex[128:]).decode()}")
        local_print(
            f"content: {result[64:]!r}",
            f"content from hex: {bytes.fromhex(result_hex[128:])!r}",
            f"signature: {result[:128]!r}",
        )

        # verify_key = nacl.signing.VerifyKey(bytes.fromhex("c69995185efa20bf7a88139f5920335aa3d3e7f20464345a2c095c766dfa157a"))
        # @fixme: where does this 'magic-number' come from!?
        verify_key = nacl.signing.VerifyKey(
            bytes.fromhex(
                "c69995185efa20bf7a88139f5920335aa3d3e7f20464345a2c095c766dfa157a"
            )
        )
        try:
            verify_key.verify(result)
            local_print("verified!")
        except nacl.exceptions.BadSignatureError:
            local_print("failed verification!")

    # print(fido2.cbor.loads(result))


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option("-y", "--yes", help="Agree to all questions", is_flag=True)
def reset(serial: Optional[str], yes: bool) -> None:
    """Reset device - wipes all credentials!!!"""
    local_print(
        "Reset is only possible 10secs after plugging in the device.",
        "Please (re-)plug in your Nitrokey FIDO2 now!",
    )
    if yes or AskUser.yes_no("Warning: Your credentials will be lost!!! continue?"):
        local_print("Press key to confirm -- again, your credentials will be lost!!!")
        try:
            nkfido2.find(serial).reset()
        except CtapError as e:
            local_critical(
                f"Reset failed ({str(e)})",
                "Did you confirm with a key-press 10secs after plugging in?",
                "Please re-try...",
            )
        local_print("....aaaand they're gone")


# @fixme: lacking functionality? remove? implement?
@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
def change_pin(serial: Optional[str]) -> None:
    """Change pin of current device"""

    old_pin = AskUser.hidden("Please enter old pin: ")
    new_pin = AskUser.hidden("Please enter new pin: ")
    confirm_pin = AskUser.hidden("Please confirm new pin: ")

    if new_pin != confirm_pin:
        local_critical(
            "new pin does not match confirm-pin",
            "please try again!",
            support_hint=False,
        )
    try:
        # @fixme: move this (function) into own fido2-client-class
        dev = nkfido2.find(serial)
        client = dev.client
        assert isinstance(dev.ctap2, Ctap2)
        client_pin = ClientPin(dev.ctap2)
        client_pin.change_pin(old_pin, new_pin)
        local_print("done - please use new pin to verify key")

    except Exception as e:
        local_critical(
            "failed changing to new pin!", "did you set one already? or is it wrong?", e
        )


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
# @click.option("--new-pin", help="set current pin to this value", default=None)
def set_pin(serial: Optional[str]) -> None:
    """Set pin of current device."""

    # ask for new pin
    new_pin = AskUser.hidden("Please enter new pin: ")
    confirm_pin = AskUser.hidden("Please confirm new pin: ")
    if new_pin != confirm_pin:
        local_critical(
            "new pin does not match confirm-pin",
            "please try again!",
            support_hint=False,
        )
    # use provided --pin arg
    else:
        confirm_pin = new_pin

    try:
        # @fixme: move this (function) into own fido2-client-class
        dev = nkfido2.find(serial)
        client = dev.client
        assert isinstance(dev.ctap2, Ctap2)
        client_pin = ClientPin(dev.ctap2)
        client_pin.set_pin(new_pin)
        local_print("done - please use new pin to verify key")

    except Exception as e:
        local_critical(
            "failed setting new pin, maybe it's already set?",
            "to change an already set pin, please use:",
            "$ nitropy fido2 change-pin",
            e,
        )


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
@click.option("--pin", help="PIN for device access", default=None)
def verify(serial: Optional[str], udp: bool, pin: Optional[str]) -> None:
    """Verify if connected Nitrokey FIDO2 device is genuine."""

    cert = None
    try:
        cert = nkfido2.find(serial, udp=udp, pin=pin).make_credential(
            fingerprint_only=True
        )

    except Fido2ClientError as e:
        cause = str(e.cause)
        # error 0x31
        if "PIN_INVALID" in cause:
            local_critical(
                "your key has a different PIN. Please try to remember it :)", e
            )

        # error 0x34 (power cycle helps)
        if "PIN_AUTH_BLOCKED" in cause:
            local_critical(
                "your key's PIN auth is blocked due to too many incorrect attempts.",
                "please plug it out and in again, then again!",
                "please be careful, after too many incorrect attempts, ",
                "   the key will fully block.",
                e,
            )

        # error 0x32 (only reset helps)
        if "PIN_BLOCKED" in cause:
            local_critical(
                "your key's PIN is blocked. ",
                "to use it again, you need to fully reset it.",
                "you can do this using: `nitropy fido2 reset`",
                e,
            )

        # error 0x01
        if "INVALID_COMMAND" in cause:
            local_critical(
                "error getting credential, is your key in bootloader mode?",
                "try: `nitropy fido2 util program aux leave-bootloader`",
                e,
            )

        # pin required error
        if "PIN required" in str(e):
            local_critical("your key has a PIN set - pass it using `--pin <PIN>`", e)

        local_critical("unexpected Fido2Client (CTAP) error", e)

    except Exception as e:
        local_critical("unexpected error", e)

    hashdb = {
        "d7a23679007fe799aeda4388890f33334aba4097bb33fee609c8998a1ba91bd3": "Nitrokey FIDO2 1.x",
        "6d586c0b00b94148df5b54f4a866acd93728d584c6f47c845ac8dade956b12cb": "Nitrokey FIDO2 2.x",
        "e1f40563be291c30bc3cc381a7ef46b89ef972bdb048b716b0a888043cf9072a": "Nitrokey FIDO2 Dev 2.x ",
        "ad8fd1d16f59104b9e06ef323cc03f777ed5303cd421a101c9cb00bb3fdf722d": "Nitrokey 3",
        "44fa598fdc98681dc5c8659a804c40bd6e53f8e54a781608b0651d47a53e1c8a": "Nitrokey 3 Dev",
        "aa1cb760c2879530e7d7fed3da75345d25774be9cfdbbcbd36fdee767025f34b": "Nitrokey 3 A NFC",
        "4c331d7af869fd1d8217198b917a33d1fa503e9778da7638504a64a438661ae0": "Nitrokey 3 A Mini",
    }

    a_hex = cert
    if a_hex in hashdb:
        local_print(f"found device: {hashdb[a_hex]} ({a_hex})")
    else:
        local_print(f"unknown fingerprint! {a_hex}")


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
def version(serial: Optional[str], udp: bool) -> None:
    """Version of firmware on device."""

    try:
        res = nkfido2.find(serial, udp=udp).solo_version()
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
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
def wink(serial: Optional[str], udp: bool) -> None:
    """Send wink command to device (blinks LED a few times)."""

    nkfido2.find(serial, udp=udp).wink()


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
def reboot(serial: Optional[str], udp: bool) -> None:
    """Send reboot command to device (development command)"""
    local_print("Reboot", "Press key to confirm!")

    CTAP_REBOOT = 0x53
    dev = nkfido2.find(serial, udp=udp).dev
    try:
        assert isinstance(dev, CtapHidDevice)
        dev.call(CTAP_REBOOT ^ 0x80, b"")

    except OSError:
        local_print("...done")
    except CtapError as e:
        local_critical(f"...failed ({str(e)})")


def _large_blobs(client: NKFido2Client) -> LargeBlobs:
    large_blobs = client.large_blobs()
    if large_blobs is None:
        raise CliException("Device does not support large blobs", support_hint=False)
    return large_blobs


def _cred_mgmt(client: NKFido2Client, pin: str) -> Optional[CredentialManagement]:
    if not client.ctap2:
        return None
    if not CredentialManagement.is_supported(client.ctap2.info):
        return None
    client_pin = ClientPin(client.ctap2)
    try:
        client_token = client_pin.get_pin_token(pin)
    except CtapError as error:
        if error.code == CtapError.ERR.PIN_NOT_SET:
            return None
        elif error.code == CtapError.ERR.PIN_AUTH_BLOCKED:
            raise CliException(
                "Pin authentication is blocked, try reinserting the key or setting a pin if none is set.",
                support_hint=False,
            )
        elif error.code == CtapError.ERR.PIN_BLOCKED:
            raise CliException(
                "Your device has been blocked after too many failed unlock attempts.  You need to reset it to fix this. "
                "If no pin is set, reinserting the key might fix this warning.",
                support_hint=False,
            )
        else:
            raise
    return CredentialManagement(client.ctap2, client_pin.protocol, client_token)


@dataclass
class LargeBlobKey:
    rp: str
    cred: str
    large_blob_key: str


def _large_blob_keys(cred_mgmt: CredentialManagement) -> List[LargeBlobKey]:
    credentials = []

    for rp in cred_mgmt.enumerate_rps():
        rp_id_hash = rp[CredentialManagement.RESULT.RP_ID_HASH]
        rp_entity = rp[CredentialManagement.RESULT.RP]
        rp_label = rp_entity.get("name", rp_entity.get("id", rp_id_hash))
        for cred in cred_mgmt.enumerate_creds(rp_id_hash):
            if CredentialManagement.RESULT.LARGE_BLOB_KEY not in cred:
                continue
            user_entity = cred[CredentialManagement.RESULT.USER]
            cred_id = cred[CredentialManagement.RESULT.CREDENTIAL_ID]
            cred_label = user_entity.get(
                "displayName", user_entity.get("name", cred_id["id"].hex())
            )
            large_blob_key = cred[CredentialManagement.RESULT.LARGE_BLOB_KEY]
            credentials.append(
                LargeBlobKey(
                    rp=rp_label, cred=cred_label, large_blob_key=large_blob_key
                )
            )

    return credentials


@click.command()
def list_large_blobs() -> None:
    """
    List the large blobs on the FIDO2 device.

    This command only works for models that implement the Large Blobs extension
    for FIDO2.
    """
    # TODO: use public API
    import zlib

    from fido2.ctap2.blob import _decompress, _lb_unpack

    pin = AskUser.hidden("Please provide pin: ")
    client = nkfido2.find()
    large_blobs = _large_blobs(client)
    large_blob_array = large_blobs.read_blob_array()
    print(f"Found large blob array with {len(large_blob_array)} elements")

    cred_mgmt = _cred_mgmt(client, pin)
    large_blob_keys = _large_blob_keys(cred_mgmt) if cred_mgmt else []
    print(f"Found {len(large_blob_keys)} credentials with large blob keys")

    print()
    print("Large blob array:")

    for entry in large_blob_array:
        key = None
        blob = None
        for large_blob_key in large_blob_keys:
            try:
                compressed, orig_size = _lb_unpack(large_blob_key.large_blob_key, entry)  # type: ignore[no-untyped-call]
                decompressed = _decompress(compressed)  # type: ignore[no-untyped-call]
                if len(decompressed) == orig_size:
                    key = large_blob_key
                    blob = decompressed
                    break
            except (ValueError, zlib.error):
                pass

        if blob and key:
            print(f"- entry for {key.rp}/{key.cred}:")
            print(f"  {blob.hex()}")
        else:
            print("- entry without matching key")


fido2.add_command(rng)

# @fixme: this one exists twice, once here, once in "util program aux"
fido2.add_command(reboot)
fido2.add_command(list)

fido2.add_command(list_credentials)
fido2.add_command(delete_credential)

rng.add_command(hexbytes)
rng.add_command(raw)
rng.add_command(feedkernel)

fido2.add_command(make_credential)
fido2.add_command(challenge_response)
fido2.add_command(reset)
fido2.add_command(status)
fido2.add_command(update)

fido2.add_command(version)
fido2.add_command(verify)
fido2.add_command(wink)

fido2.add_command(set_pin)
fido2.add_command(change_pin)

fido2.add_command(list_large_blobs)

fido2.add_command(util)

util.add_command(program)

# used for fw-signing... (does not seem to work @fixme)
util.add_command(sign)
util.add_command(genkey)
util.add_command(mergehex)
util.add_command(monitor)

# see above -> @fixme: likely to be removed?!
# fido2.add_command(probe)
# key.add_command(sha256sum)
# key.add_command(sha512sum)
