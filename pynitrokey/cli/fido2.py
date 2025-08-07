# Copyright 2019 SoloKeys Developers
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import hashlib
import secrets
import time
from dataclasses import fields
from getpass import getpass
from typing import Any, Optional

import click
from fido2.attestation.base import InvalidSignature
from fido2.attestation.packed import PackedAttestation
from fido2.client import ClientError as Fido2ClientError
from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.cose import ES256, EdDSA
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2, Info
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.extensions import (
    HMACGetSecretInput,
    HMACGetSecretOutput,
    HmacSecretExtension,
)
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice, open_device
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from pynitrokey.cli.exceptions import CliException
from pynitrokey.exceptions import NonUniqueDeviceError, NoSoloFoundError
from pynitrokey.helpers import (
    AskUser,
    local_critical,
    local_print,
    require_windows_admin,
)

# https://pocoo-click.readthedocs.io/en/latest/commands/#nested-handling-and-contexts


class CliInteraction(UserInteraction):
    def __init__(self, pin: Optional[str]) -> None:
        self.pin = pin

    def prompt_up(self) -> None:
        print("Touch your authenticator device now...")

    def request_pin(self, permissions: Any, rd_id: Any) -> str:
        if self.pin:
            return self.pin
        else:
            return getpass("Enter PIN: ")

    def request_uv(self, permissions: Any, rd_id: Any) -> bool:
        return True


def _device(serial: Optional[str] = None) -> CtapHidDevice:
    for i in range(5):
        devices = []
        if serial is not None:
            if serial.startswith("device="):
                serial = serial.split("=")[1]
                devices = [open_device(serial)]
            else:
                devices = [
                    d
                    for d in CtapHidDevice.list_devices()
                    if d.descriptor.serial_number == serial
                ]
        else:
            devices = list(CtapHidDevice.list_devices())
        if len(devices) > 1:
            raise NonUniqueDeviceError
        if len(devices) > 0:
            return devices[0]

        time.sleep(0.2)

    raise NoSoloFoundError("no Nitrokey FIDO2 found")


def _ctap2(device: CtapHidDevice) -> Ctap2:
    try:
        return Ctap2(device)
    except CtapError:
        raise CliException("Device does not support CTAP2", support_hint=False)


def _credential_management(device: CtapHidDevice, pin: str) -> CredentialManagement:
    ctap2 = _ctap2(device)

    client_pin = ClientPin(ctap2)

    try:
        client_token = client_pin.get_pin_token(
            pin, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT
        )
    except CtapError as error:
        if error.code == CtapError.ERR.PIN_NOT_SET:
            local_critical(
                "Please set a pin in order to manage credentials", support_hint=False
            )
        if error.code == CtapError.ERR.PIN_AUTH_BLOCKED:
            local_critical(
                "Pin authentication has been blocked, try reinserting the key or setting a pin if none is set",
                support_hint=False,
            )
        if error.code == CtapError.ERR.PIN_BLOCKED:
            local_critical(
                "Your device has been blocked after too many failed unlock attempts, to fix this it "
                "will have to be reset. (If no pin is set, plugging it in again might fix this warning)",
                support_hint=False,
            )
        if error.code == CtapError.ERR.PIN_INVALID:
            local_critical("Wrong pin, please retry", support_hint=False)
        raise

    return CredentialManagement(ctap2, client_pin.protocol, client_token)


def _fido2(
    device: CtapHidDevice,
    host: str,
    hmac_secret: bool = False,
    pin: Optional[str] = None,
) -> Fido2Client:
    # TODO: set user_interaction
    origin = f"https://{host}"
    client_data_collector = DefaultClientDataCollector(origin=origin)
    extensions = []
    if hmac_secret:
        # there are no type annotations for HmacSecretExtension.__init__
        extensions.append(HmacSecretExtension(allow_hmac_secret=True))  # type: ignore[no-untyped-call]
    user_interaction = CliInteraction(pin)
    return Fido2Client(
        device=device,
        client_data_collector=client_data_collector,
        extensions=extensions,
        user_interaction=user_interaction,
    )


def _make_credential(
    client: Fido2Client,
    host: str,
    user_id: str,
    resident_key: str = "",
    user_verification: str = "",
    hmac_secret: bool = False,
) -> AttestationObject:
    extensions = {}
    if hmac_secret:
        extensions["hmacCreateSecret"] = True

    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(name="Example RP", id=host),
        user=PublicKeyCredentialUserEntity(name="A. User", id=user_id.encode()),
        challenge=secrets.token_bytes(32),
        pub_key_cred_params=[
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY, alg=EdDSA.ALGORITHM
            ),
            PublicKeyCredentialParameters(
                type=PublicKeyCredentialType.PUBLIC_KEY, alg=ES256.ALGORITHM
            ),
        ],
        extensions=extensions,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement(resident_key),
            user_verification=UserVerificationRequirement(user_verification),
        ),
    )

    registration_response = client.make_credential(options)

    attestation_response = registration_response.response
    att_obj = attestation_response.attestation_object
    assert att_obj.fmt == "packed"
    verifier = PackedAttestation()
    try:
        verifier.verify(
            att_obj.att_stmt, att_obj.auth_data, attestation_response.client_data.hash
        )
    except InvalidSignature:
        raise CliException("Invalid attestation signature in makeCredential")

    if hmac_secret:
        extension_outputs = registration_response.client_extension_results
        assert "hmacCreateSecret" in extension_outputs
        assert extension_outputs["hmacCreateSecret"] is True

    return att_obj


def _simple_secret(
    device: CtapHidDevice,
    credential_id: str,
    secret_input: str,
    host: str,
) -> bytes:
    client = _fido2(device, host, hmac_secret=True)

    allow_list = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=bytes.fromhex(credential_id),
        )
    ]

    challenge = secrets.token_bytes(32)
    salt = hashlib.sha256(secret_input.encode()).digest()

    assertion = client.get_assertion(
        PublicKeyCredentialRequestOptions(
            challenge=challenge,
            rp_id=host,
            allow_credentials=allow_list,
            extensions={"hmacGetSecret": HMACGetSecretInput(salt1=salt)},
        )
    ).get_response(0)

    assert "hmacGetSecret" in assertion.client_extension_results
    # from_dict would be more suitable but does not have type annotations
    output = HMACGetSecretOutput(**assertion.client_extension_results["hmacGetSecret"])

    return output.output1


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

    device = _device(serial)

    try:
        ctap2 = Ctap2(device)
    except CtapError:
        print("CTAP2 not supported")
        return

    info = ctap2.send_cbor(Ctap2.CMD.GET_INFO)
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

    device = _device(serial)
    cred_manager = _credential_management(device, pin)

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
@click.option("-cid", "--cred-id", help="Credential id of the Credential to be deleted")
def delete_credential(serial: str, pin: str, cred_id: str) -> None:
    """Delete a specific credential from the key"""

    if not cred_id:
        cred_id = AskUser.hidden("Please provide credential-id")

    if not pin:
        pin = AskUser.hidden("Please provide pin: ")

    device = _device(serial)
    cred_manager = _credential_management(device, pin)

    cred_descriptor = PublicKeyCredentialDescriptor(
        type=PublicKeyCredentialType.PUBLIC_KEY, id=bytes.fromhex(cred_id)
    )

    try:
        cred_manager.delete_cred(cred_descriptor)
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
    """Generate a credential."""

    # TODO: add flag for hmac-secret

    device = _device()
    client = _fido2(device, host, hmac_secret=True)
    attestation_object = _make_credential(
        client=client,
        host=host,
        user_id=user,
        resident_key=resident_key,
        user_verification=user_verification,
        hmac_secret=True,
    )

    credential = attestation_object.auth_data.credential_data
    if not credential:
        raise ValueError("No credential ID available")
    print(credential.credential_id.hex())


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
@click.option("--host", help="Relying party's host", default="nitrokeys.dev")
@click.argument("credential-id")
@click.argument("challenge")
def challenge_response(
    serial: Optional[str],
    host: str,
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
    """

    device = _device(serial)
    output = _simple_secret(
        device,
        credential_id,
        challenge,
        host=host,
    )
    print(output.hex())


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
        "Reset is only possible within 10secs after plugging in the device.",
        "Please (re-)plug in your Nitrokey FIDO2 now!",
    )
    if yes or AskUser.yes_no("Warning: Your credentials will be lost!!! continue?"):
        local_print("Press key to confirm -- again, your credentials will be lost!!!")
        try:
            device = _device(serial)
            ctap2 = _ctap2(device)
            ctap2.reset()
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
        device = _device(serial)
        ctap2 = _ctap2(device)
        client_pin = ClientPin(ctap2)
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
        device = _device(serial)
        ctap2 = _ctap2(device)
        client_pin = ClientPin(ctap2)
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

    host = "nitrokey.dev"
    device = _device(serial)

    try:
        client = _fido2(device, host, pin=pin)
        attestation_object = _make_credential(client=client, host=host, user_id="they")

    except Fido2ClientError as e:
        cause = str(e.cause)
        # error 0x31
        if "PIN_INVALID" in cause:
            raise CliException(
                "your key has a different PIN. Please try to remember it :)", e
            )

        # error 0x34 (power cycle helps)
        if "PIN_AUTH_BLOCKED" in cause:
            raise CliException(
                "your key's PIN auth is blocked due to too many incorrect attempts.",
                "please plug it out and in again, then again!",
                "please be careful, after too many incorrect attempts, ",
                "   the key will fully block.",
                e,
            )

        # error 0x32 (only reset helps)
        if "PIN_BLOCKED" in cause:
            raise CliException(
                "your key's PIN is blocked. ",
                "to use it again, you need to fully reset it.",
                "you can do this using: `nitropy fido2 reset`",
                e,
            )

        # error 0x01
        if "INVALID_COMMAND" in cause:
            raise CliException(
                "error getting credential, is your key in bootloader mode?",
                "try: `nitropy fido2 util program aux leave-bootloader`",
                e,
            )

        raise CliException("unexpected Fido2Client (CTAP) error", e)

    except Exception as e:
        raise CliException("unexpected error", e)

    hashdb = {
        "d7a23679007fe799aeda4388890f33334aba4097bb33fee609c8998a1ba91bd3": "Nitrokey FIDO2 1.x",
        "6d586c0b00b94148df5b54f4a866acd93728d584c6f47c845ac8dade956b12cb": "Nitrokey FIDO2 2.x",
        "e1f40563be291c30bc3cc381a7ef46b89ef972bdb048b716b0a888043cf9072a": "Nitrokey FIDO2 Dev 2.x ",
        "ad8fd1d16f59104b9e06ef323cc03f777ed5303cd421a101c9cb00bb3fdf722d": "Nitrokey 3",
        "44fa598fdc98681dc5c8659a804c40bd6e53f8e54a781608b0651d47a53e1c8a": "Nitrokey 3 Dev",
        "aa1cb760c2879530e7d7fed3da75345d25774be9cfdbbcbd36fdee767025f34b": "Nitrokey 3 A NFC",
        "4c331d7af869fd1d8217198b917a33d1fa503e9778da7638504a64a438661ae0": "Nitrokey 3 A Mini",
        "c7512dfcd15ffc5a7b4000e4898e5956ee858027794c5086cc137a02cd15d123": "Nitrokey Passkey",
    }

    if "x5c" not in attestation_object.att_stmt:
        raise ValueError("No x5c information available")

    data = attestation_object.att_stmt["x5c"]
    cert = hashlib.sha256(data[0]).digest().hex()
    if cert in hashdb:
        local_print(f"found device: {hashdb[cert]} ({cert})")
    else:
        local_print(f"unknown fingerprint! {cert}")


@click.command()
@click.option(
    "-s",
    "--serial",
    help="Serial number of Nitrokey to use. Prefix with 'device=' to provide device file, e.g. 'device=/dev/hidraw5'.",
)
def wink(serial: Optional[str]) -> None:
    """Send wink command to device (blinks LED a few times)."""

    _device(serial).wink()


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
