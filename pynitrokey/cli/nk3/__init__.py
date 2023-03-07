# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
import logging
import os.path
from base64 import b32decode
from hashlib import sha256
from typing import BinaryIO, List, Optional, Type, TypeVar

import click
import fido2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from ecdsa import NIST256p, SigningKey

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import (
    AskUser,
    DownloadProgressBar,
    Retries,
    local_print,
    prompt,
    require_windows_admin,
)
from pynitrokey.nk3 import list as list_nk3
from pynitrokey.nk3 import open as open_nk3
from pynitrokey.nk3.base import Nitrokey3Base
from pynitrokey.nk3.bootloader import (
    Nitrokey3Bootloader,
    Variant,
    detect_variant,
    parse_firmware_image,
)
from pynitrokey.nk3.device import BootMode, Nitrokey3Device
from pynitrokey.nk3.exceptions import TimeoutException
from pynitrokey.nk3.otp_app import STRING_TO_KIND, Algorithm, OTPApp
from pynitrokey.nk3.provisioner_app import ProvisionerApp
from pynitrokey.nk3.updates import REPOSITORY, get_firmware_update
from pynitrokey.updates import OverwriteError

T = TypeVar("T", bound=Nitrokey3Base)

logger = logging.getLogger(__name__)

VARIANT_CHOICE = click.Choice(
    [variant.value for variant in Variant],
    case_sensitive=False,
)


def variant_callback(
    _ctx: object, _param: object, value: Optional[str]
) -> Optional[Variant]:
    return Variant.from_str(value) if value else None


class Context:
    def __init__(self, path: Optional[str]) -> None:
        self.path = path

    def list(self) -> List[Nitrokey3Base]:
        if self.path:
            device = open_nk3(self.path)
            if device:
                return [device]
            else:
                return []
        else:
            return list_nk3()

    def _select_unique(self, name: str, devices: List[T]) -> T:
        if len(devices) == 0:
            msg = f"No {name} device found"
            if self.path:
                msg += f" at path {self.path}"
            raise CliException(msg)

        if len(devices) > 1:
            raise CliException(
                f"Multiple {name} devices found -- use the --path option to select one"
            )

        return devices[0]

    def connect(self) -> Nitrokey3Base:
        return self._select_unique("Nitrokey 3", self.list())

    def connect_device(self) -> Nitrokey3Device:
        devices = [
            device for device in self.list() if isinstance(device, Nitrokey3Device)
        ]
        return self._select_unique("Nitrokey 3", devices)

    def _await(self, name: str, ty: Type[T]) -> T:
        for t in Retries(10):
            logger.debug(f"Searching {name} device ({t})")
            devices = [device for device in self.list() if isinstance(device, ty)]
            if len(devices) == 0:
                logger.debug(f"No {name} device found, continuing")
                continue
            if len(devices) > 1:
                raise CliException(f"Multiple {name} devices found")
            return devices[0]

        raise CliException(f"No {name} device found")

    def await_device(self) -> Nitrokey3Device:
        return self._await("Nitrokey 3", Nitrokey3Device)

    def await_bootloader(self) -> Nitrokey3Bootloader:
        # mypy does not allow abstract types here, but this is still valid
        return self._await("Nitrokey 3 bootloader", Nitrokey3Bootloader)  # type: ignore


@click.group()
@click.option("-p", "--path", "path", help="The path of the Nitrokey 3 device")
@click.pass_context
def nk3(ctx: click.Context, path: Optional[str]) -> None:
    """Interact with Nitrokey 3 devices, see subcommands."""
    ctx.obj = Context(path)
    require_windows_admin()


@nk3.command()
def list() -> None:
    """List all Nitrokey 3 devices."""
    local_print(":: 'Nitrokey 3' keys")
    for device in list_nk3():
        with device as device:
            uuid = device.uuid()
            if uuid:
                local_print(f"{device.path}: {device.name} {uuid}")
            else:
                local_print(f"{device.path}: {device.name}")


@nk3.command()
@click.option(
    "--bootloader",
    is_flag=True,
    help="Reboot a Nitrokey 3 device into bootloader mode",
)
@click.pass_obj
def reboot(ctx: Context, bootloader: bool) -> None:
    """
    Reboot the key.

    Per default, the key will reboot into regular firmware mode.  If the --bootloader option
    is set, a key can boot from firmware mode to bootloader mode.  Booting into
    bootloader mode has to be confirmed by pressing the touch button.
    """
    with ctx.connect() as device:
        if bootloader:
            if isinstance(device, Nitrokey3Device):
                success = reboot_to_bootloader(device)
            else:
                raise CliException(
                    "A Nitrokey 3 device in bootloader mode can only reboot into firmware mode.",
                    support_hint=False,
                )
        else:
            success = device.reboot()

    if not success:
        raise CliException(
            "The connected device cannot be rebooted automatically.  Remove and reinsert the "
            "device to reboot it.",
            support_hint=False,
        )


def reboot_to_bootloader(device: Nitrokey3Device) -> bool:
    local_print(
        "Please press the touch button to reboot the device into bootloader mode ..."
    )
    try:
        return device.reboot(BootMode.BOOTROM)
    except TimeoutException:
        raise CliException(
            "The reboot was not confirmed with the touch button.",
            support_hint=False,
        )


@nk3.command()
@click.option(
    "-l",
    "--length",
    "length",
    default=57,
    help="The length of the generated data (default: 57)",
)
@click.pass_obj
def rng(ctx: Context, length: int) -> None:
    """Generate random data on the device."""
    with ctx.connect_device() as device:
        while length > 0:
            rng = device.rng()
            local_print(rng[:length].hex())
            length -= len(rng)


@nk3.command()
@click.option(
    "--pin",
    "pin",
    help="The FIDO2 PIN of the device (if enabled)",
)
@click.option(
    "--only",
    "only",
    help="Run only the specified tests (may not be used with --all, --include or --exclude)",
)
@click.option(
    "--all",
    "all",
    is_flag=True,
    default=False,
    help="Run all tests (except those specified with --exclude)",
)
@click.option(
    "--include",
    "include",
    help="Also run the specified tests",
)
@click.option(
    "--exclude",
    "exclude",
    help="Do not run the specified tests",
)
@click.option(
    "--list",
    "list_",
    is_flag=True,
    default=False,
    help="List the selected tests instead of running them",
)
@click.pass_obj
def test(
    ctx: Context,
    pin: Optional[str],
    only: Optional[str],
    all: bool,
    include: Optional[str],
    exclude: Optional[str],
    list_: bool,
) -> None:
    """Run some tests on all connected Nitrokey 3 devices."""
    from .test import (
        TestContext,
        TestSelector,
        list_tests,
        log_devices,
        log_system,
        run_tests,
    )

    test_selector = TestSelector(all=all)
    if only:
        if all or include or exclude:
            raise CliException(
                "--only may not be used together with --all, --include or --exclude.",
                support_hint=False,
            )
        test_selector.only = only.split(",")
    if include:
        test_selector.include = include.split(",")
    if exclude:
        test_selector.exclude = exclude.split(",")

    if list_:
        list_tests(test_selector)
        return

    log_system()
    devices = ctx.list()

    if len(devices) == 0:
        log_devices()
        raise CliException("No connected Nitrokey 3 devices found")

    local_print(f"Found {len(devices)} Nitrokey 3 device(s):")
    for device in devices:
        local_print(f"- {device.name} at {device.path}")

    results = []
    test_ctx = TestContext(pin=pin)
    for device in devices:
        results.append(run_tests(test_ctx, device, test_selector))

    n = len(devices)
    success = sum(results)
    failure = n - success
    local_print("")
    local_print(
        f"Summary: {n} device(s) tested, {success} successful, {failure} failed"
    )

    if failure > 0:
        local_print("")
        raise CliException(f"Test failed for {failure} device(s)")


@nk3.command()
@click.argument("path", default=".")
@click.option(
    "--variant",
    type=VARIANT_CHOICE,
    callback=variant_callback,
    required=True,
    help="The variant to fetch the update for",
)
@click.option(
    "-f",
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the firmware image if it already exists",
)
@click.option("--version", help="Download this version instead of the latest one")
def fetch_update(
    path: str, force: bool, variant: Variant, version: Optional[str]
) -> None:
    """
    Fetches a firmware update for the Nitrokey 3 and stores it at the given path.

    If no path is given, the firmware image stored in the current working
    directory.  If the given path is a directory, the image is stored under
    that directory.  Otherwise it is written to the path.  Existing files are
    only overwritten if --force is set.

    Per default, the latest firmware release is fetched.  If you want to
    download a specific version, use the --version option.
    """
    try:
        release = REPOSITORY.get_release_or_latest(version)
        update = get_firmware_update(release, variant)
    except Exception as e:
        if version:
            raise CliException(f"Failed to find firmware update {version}", e)
        else:
            raise CliException("Failed to find latest firmware update", e)

    bar = DownloadProgressBar(desc=update.tag)

    try:
        if os.path.isdir(path):
            path = update.download_to_dir(path, overwrite=force, callback=bar.update)
        else:
            if not force and os.path.exists(path):
                raise OverwriteError(path)
            with open(path, "wb") as f:
                update.download(f, callback=bar.update)

        bar.close()

        local_print(f"Successfully downloaded firmware release {update.tag} to {path}")
    except OverwriteError as e:
        raise CliException(
            f"{e.path} already exists.  Use --force to overwrite the file.",
            support_hint=False,
        )
    except Exception as e:
        raise CliException(f"Failed to download firmware update {update.tag}", e)


@nk3.command()
@click.argument("image")
@click.option(
    "--variant",
    type=VARIANT_CHOICE,
    callback=variant_callback,
    help="The variant of the given firmage image",
)
def validate_update(image: str, variant: Optional[Variant]) -> None:
    """
    Validates the given firmware image and prints the firmware version and the signer.

    If the name of the firmware image name is changed so that the device variant can no longer be
    detected from the filename, it has to be set explictly with --variant.
    """
    if not variant:
        variant = detect_variant(image)
    if not variant:
        variant = Variant.from_str(
            prompt("Firmware image variant", type=VARIANT_CHOICE)
        )

    with open(image, "rb") as f:
        data = f.read()

    try:
        metadata = parse_firmware_image(variant, data)
    except Exception as e:
        raise CliException("Failed to parse and validate firmware image", e)

    signed_by = metadata.signed_by or "unsigned"

    print(f"version:    {metadata.version}")
    print(f"signed by:  {signed_by}")


@nk3.command()
@click.argument("image", required=False)
@click.option(
    "--variant",
    type=VARIANT_CHOICE,
    callback=variant_callback,
    help="The variant of the given firmage image",
)
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
    hidden=True,
)
@click.pass_obj
def update(
    ctx: Context, image: Optional[str], variant: Optional[Variant], experimental: bool
) -> None:
    """
    Update the firmware of the device using the given image.

    This command requires that exactly one Nitrokey 3 in bootloader or firmware mode is connected.
    The user is asked to confirm the operation before the update is started.  The Nitrokey 3 may
    not be removed during the update.  Also, additional Nitrokey 3 devices may not be connected
    during the update.

    If no firmware image is given, the latest firmware release is downloaded automatically.  If a
    firmware image is given and its name is changed so that the device variant can no longer be
    detected from the filename, it has to be set explictly with --variant.

    If the connected Nitrokey 3 device is in firmware mode, the user is prompted to touch the
    device’s button to confirm rebooting to bootloader mode.
    """

    if experimental:
        "The --experimental switch is not required to run this command anymore and can be safely removed."

    from .update import update as exec_update

    update_version = exec_update(ctx, image, variant)

    local_print("")
    with ctx.await_device() as device:
        version = device.version()
        if version == update_version:
            local_print(f"Successfully updated the firmware to version {version}.")
        else:
            raise CliException(
                f"The firmware update to {update_version} was successful, but the firmware "
                f"is still reporting version {version}."
            )


@nk3.command()
@click.pass_obj
def version(ctx: Context) -> None:
    """Query the firmware version of the device."""
    with ctx.connect_device() as device:
        version = device.version()
        local_print(version)


@nk3.command()
@click.pass_obj
def wink(ctx: Context) -> None:
    """Send wink command to the device (blinks LED a few times)."""
    with ctx.connect_device() as device:
        device.wink()


@nk3.group()
@click.pass_context
def otp(ctx: click.Context) -> None:
    """Manage OTP secrets on the device.
    Use NITROPY_OTP_PASSWORD to pass password for the scripted execution."""
    pass


@otp.command()
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
@click.argument(
    "secret",
    type=click.STRING,
    # help="The shared secret string (by default in base32)",
)
@click.option(
    "--digits_str",
    "digits_str",
    type=click.Choice(["6", "8"]),
    help="Digits count",
    default="6",
)
@click.option(
    "--kind",
    "kind",
    type=click.Choice(choices=STRING_TO_KIND.keys(), case_sensitive=False),  # type: ignore[arg-type]
    help="OTP mechanism to use. Case insensitive.",
    default="TOTP",
)
@click.option(
    "--hash",
    "hash",
    type=click.Choice(["SHA1", "SHA256"]),
    help="Hash algorithm to use",
    default="SHA1",
)
@click.option(
    "--counter_start",
    "counter_start",
    type=click.INT,
    help="Starting value for the counter (HOTP only)",
    default=0,
)
@click.option(
    "--touch_button",
    "touch_button",
    type=click.BOOL,
    help="This credential requires button press before use",
    is_flag=True,
)
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
)
def register(
    ctx: Context,
    name: str,
    secret: str,
    digits_str: str,
    kind: str,
    hash: str,
    counter_start: int,
    touch_button: bool,
    experimental: bool,
) -> None:
    """Register OTP credential.

    Write SECRET under the NAME.
    SECRET should be encoded in base32 format.
    Experimental.
    """
    check_experimental_flag(experimental)

    digits = int(digits_str)
    secret_bytes = b32decode(secret)
    otp_kind = STRING_TO_KIND[kind.upper()]
    hash_algorithm = Algorithm.Sha1 if hash == "SHA1" else Algorithm.Sha256
    with ctx.connect_device() as device:
        app = OTPApp(device)
        ask_to_touch_if_needed()
        authenticate_if_needed(app)
        app.register(
            name.encode(),
            secret_bytes,
            digits,
            kind=otp_kind,
            algo=hash_algorithm,
            initial_counter_value=counter_start,
            touch_button_required=touch_button,
        )


def check_experimental_flag(experimental: bool) -> None:
    """Helper function to show common warning for the experimental features"""
    if not experimental:
        local_print(" ")
        local_print(
            "This feature is experimental, which means it was not tested thoroughly.\n"
            "Note: data stored with it can be lost in the next firmware update.\n"
            "Please pass --experimental switch to force running it anyway."
        )
        local_print(" ")
        raise click.Abort()


def ask_to_touch_if_needed() -> None:
    """Helper function to show common request for the touch if device signalizes it"""
    local_print("Please touch the device if it blinks")


@otp.command()
@click.pass_obj
@click.option(
    "--hex",
    "hex",
    type=click.BOOL,
    help="Use hex representation",
    default=False,
    is_flag=True,
)
def show(ctx: Context, hex: bool) -> None:
    """List registered OTP credentials."""
    with ctx.connect_device() as device:
        app = OTPApp(device)
        ask_to_touch_if_needed()
        authenticate_if_needed(app)
        for e in app.list():
            local_print(e.hex() if hex else e)


@otp.command()
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
def remove(ctx: Context, name: str) -> None:
    """Remove OTP credential."""
    with ctx.connect_device() as device:
        app = OTPApp(device)
        ask_to_touch_if_needed()
        authenticate_if_needed(app)
        app.delete(name.encode())


@otp.command()
@click.pass_obj
@click.option(
    "--force",
    is_flag=True,
    help="Do not ask for confirmation",
)
def reset(ctx: Context, force: bool) -> None:
    """Remove all OTP credentials from the device."""
    confirmed = force or click.confirm("Do you want to continue?")
    if not confirmed:
        local_print("Operation cancelled")
        click.Abort()
    with ctx.connect_device() as device:
        app = OTPApp(device)
        ask_to_touch_if_needed()
        app.reset()
        local_print("Operation executed")


@otp.command()
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
@click.option(
    "--timestamp",
    "timestamp",
    type=click.INT,
    help="The timestamp to use instead of the local time (TOTP only)",
    default=0,
)
@click.option(
    "--period",
    "period",
    type=click.INT,
    help="The period to use in seconds (TOTP only)",
    default=30,
)
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
)
def get(
    ctx: Context, name: str, timestamp: int, period: int, experimental: bool
) -> None:
    """Generate OTP code from registered credential.
    Experimental."""
    # TODO: for TOTP get the time from a timeserver via NTP, instead of the local clock
    check_experimental_flag(experimental)

    from datetime import datetime

    now = datetime.now()
    timestamp = timestamp if timestamp else int(datetime.timestamp(now))
    with ctx.connect_device() as device:
        try:
            app = OTPApp(device)
            ask_to_touch_if_needed()
            authenticate_if_needed(app)
            code = app.calculate(name.encode(), timestamp // period)
            local_print(
                f"Timestamp: {datetime.isoformat(now, timespec='seconds')} ({timestamp}), period: {period}"
            )
            local_print(code.decode())
        except fido2.ctap.CtapError as e:
            local_print(
                f"Device returns error: {e}. This credential id might not be registered."
            )


@otp.command()
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
@click.option(
    "--code",
    "code",
    type=click.INT,
    help="The code to verify",
    default=0,
)
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
)
def verify(ctx: Context, name: str, code: int, experimental: bool) -> None:
    """Proceed with the incoming OTP code verification (aka reverse HOTP).
    Does not need authentication by design.
    Experimental."""
    check_experimental_flag(experimental)

    with ctx.connect_device() as device:
        app = OTPApp(device)
        ask_to_touch_if_needed()
        try:
            app.verify_code(name.encode(), code)
        except fido2.ctap.CtapError as e:
            local_print(
                f"Device returns error: {e}. This credential id might not be registered, or the provided HOTP code has not passed verification."
            )


def ask_for_passphrase_if_needed(app: OTPApp) -> Optional[str]:
    passphrase = None
    if app.authentication_required():
        health_check = helper_secrets_app_health_check(app)
        if health_check:
            local_print(*health_check)
        counter = app.select().pin_attempt_counter
        if counter is None or counter == 0:
            raise RuntimeError("PIN not available to use")
        passphrase = AskUser(
            f"Current Password ({counter} attempts left)",
            envvar="NITROPY_OTP_PASSWORD",
            hide_input=True,
        ).ask()
    return passphrase


def authenticate_if_needed(app: OTPApp) -> None:
    try:
        passphrase = ask_for_passphrase_if_needed(app)
        if passphrase is not None:
            app.verify_pin_raw(passphrase)
    except Exception as e:
        local_print(f'Authentication failed with error: "{e}"')
        raise click.Abort()


@otp.command()
@click.pass_obj
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
)
@click.password_option()
def set_password(ctx: Context, password: str, experimental: bool) -> None:
    """Set the passphrase used to authenticate to other commands.
    Experimental."""
    check_experimental_flag(experimental)
    new_password = password

    with ctx.connect_device() as device:
        try:
            app = OTPApp(device)
            ask_to_touch_if_needed()

            if app.select().pin_attempt_counter is None:
                app.set_pin_raw(new_password)
                local_print("Password set")
                return

            current_password = ask_for_passphrase_if_needed(app)
            app.change_pin_raw(current_password, new_password)
            local_print("Password changed")
        except fido2.ctap.CtapError as e:
            local_print(
                f"Device returns error: {e}. This passphrase might be invalid or is set already."
            )


@otp.command()
@click.pass_obj
@click.option(
    "--force",
    is_flag=True,
    help="Do not ask for confirmation",
)
def status(ctx: Context, force: bool) -> None:
    """Show OTP status"""
    with ctx.connect_device() as device:
        app = OTPApp(device)
        r = app.select()
        local_print(f"{r}")
        local_print(*helper_secrets_app_health_check(app))


def helper_secrets_app_health_check(app: OTPApp) -> List[str]:
    messages = []
    r = app.select()
    if r.pin_attempt_counter is None:
        messages.append("- Device does not have a PIN. Set PIN before the first use.")
    if r.pin_attempt_counter == 0:
        messages.append(
            "- All attempts on the PIN counter are used. Call factory reset to use the device again."
        )
    if messages:
        messages.insert(0, "Health check notes:")
    return messages


@nk3.group(hidden=True)
def provision() -> None:
    """
    Provision the device.  This command is only used during the production
    process and not available for regular devices.
    """
    pass


@provision.command("fido2")
@click.pass_obj
@click.option(
    "--key",
    "key_file",
    required=True,
    type=click.File("rb"),
    help="The path of the FIDO2 attestation key",
)
@click.option(
    "--cert",
    "cert_file",
    required=True,
    type=click.File("rb"),
    help="The path of the FIDO2 attestation certificate",
)
def provision_fido2(ctx: Context, key_file: BinaryIO, cert_file: BinaryIO) -> None:
    """Provision the FIDO2 attestation key and certificate."""
    key = key_file.read()
    cert = cert_file.read()

    if len(key) != 36:
        raise CliException(f"Invalid key length {len(key)} (expected 36)")
    ecdsa_key = SigningKey.from_string(key[4:], curve=NIST256p)
    pem_pubkey = serialization.load_pem_public_key(
        ecdsa_key.get_verifying_key().to_pem()
    )

    x509_cert = x509.load_der_x509_certificate(cert)
    cert_pubkey = x509_cert.public_key()

    if not isinstance(pem_pubkey, EllipticCurvePublicKey):
        raise CliException("The FIDO2 attestation key is not an EC key")
    if not isinstance(cert_pubkey, EllipticCurvePublicKey):
        raise CliException(
            "The FIDO2 attestation certificate does not contain an EC key"
        )
    if pem_pubkey.public_numbers() != cert_pubkey.public_numbers():
        raise CliException(
            "The FIDO2 attestation certificate does not match the public key"
        )

    # See https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
    if x509_cert.version != x509.Version.v3:
        raise CliException(
            f"Unexpected certificate version {x509_cert.version} (expected v3)"
        )

    subject_attrs = {
        attr.rfc4514_attribute_name: attr.value for attr in x509_cert.subject
    }
    for name in ["C", "CN", "O", "OU"]:
        if name not in subject_attrs:
            raise CliException(f"Missing subject {name} in certificate")
    if subject_attrs["OU"] != "Authenticator Attestation":
        raise CliException(
            f"Unexpected certificate subject OU {subject_attrs['OU']} (expected "
            "Authenticator Attestation)"
        )

    found_aaguid = False
    for extension in x509_cert.extensions:
        if extension.oid.dotted_string == "1.3.6.1.4.1.45724.1.1.4":
            found_aaguid = True
    if not found_aaguid:
        raise CliException("Missing AAGUID extension in certificate")

    basic_constraints = x509_cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    )
    if basic_constraints.value.ca:
        raise CliException("CA must be set to false in the basic constraints")

    cert_hash = sha256(cert).digest().hex()
    print(f"FIDO2 certificate hash: {cert_hash}")

    with ctx.connect_device() as device:
        provisioner = ProvisionerApp(device)
        provisioner.write_file(b"fido/x5c/00", cert)
        provisioner.write_file(b"fido/sec/00", key)
