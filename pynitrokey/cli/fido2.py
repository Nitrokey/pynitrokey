# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from dataclasses import fields
from typing import Optional

import click

# @fixme: 1st layer `nkfido2` lower layer `fido2` not to be used here !
from fido2.client import ClientError as Fido2ClientError
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2, Info
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.webauthn import Aaguid

import pynitrokey.fido2 as nkfido2
from pynitrokey.fido2.client import NKFido2Client
from pynitrokey.helpers import (
    AskUser,
    local_critical,
    local_print,
    require_windows_admin,
)

# https://pocoo-click.readthedocs.io/en/latest/commands/#nested-handling-and-contexts


@click.group()
def fido2() -> None:
    """Interact with Nitrokey FIDO2 devices, see subcommands."""
    require_windows_admin()


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
def get_info(serial: Optional[str]) -> None:
    """Execute the CTAP2 GET_INFO command and print the response."""
    p = nkfido2.find(serial)
    if p.ctap2 is None:
        print("CTAP2 not supported")
        return

    info = p.ctap2.send_cbor(Ctap2.CMD.GET_INFO)
    for i, field in enumerate(fields(Info)):
        key = i + 1
        if key in info:
            value = info[i + 1]

            if field.name == "aaguid":
                if isinstance(value, bytes):
                    try:
                        value = Aaguid(value)
                    except Exception:
                        value = value.hex()

            print(f"{field.name}: {value}")


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
    except Exception:
        local_critical("Failed to delete credential, was the right cred_id given?")
        return
    local_print("Credential was successfully deleted")


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
    )


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
@click.option("--pin", help="PIN for device access", default=None)
def verify(serial: Optional[str], pin: Optional[str]) -> None:
    """Verify if connected Nitrokey FIDO2 device is genuine."""

    cert = None
    try:
        cert = nkfido2.find(serial, pin=pin).make_credential(fingerprint_only=True)

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
def wink(serial: Optional[str]) -> None:
    """Send wink command to device (blinks LED a few times)."""

    nkfido2.find(serial).wink()


fido2.add_command(challenge_response)
fido2.add_command(change_pin)
fido2.add_command(delete_credential)
fido2.add_command(get_info)
fido2.add_command(list_credentials)
fido2.add_command(make_credential)
fido2.add_command(reset)
fido2.add_command(set_pin)
fido2.add_command(verify)
fido2.add_command(wink)
