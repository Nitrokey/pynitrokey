# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import os.path
import sys
from hashlib import sha256
from typing import BinaryIO, List, Optional

import click
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from ecdsa import NIST256p, SigningKey

from pynitrokey.cli import trussed
from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import DownloadProgressBar, check_experimental_flag, local_print
from pynitrokey.nk3.bootloader import Nitrokey3Bootloader
from pynitrokey.nk3.device import Nitrokey3Device
from pynitrokey.nk3.provisioner_app import ProvisionerApp
from pynitrokey.nk3.updates import REPOSITORY, get_firmware_update
from pynitrokey.trussed.base import NitrokeyTrussedBase
from pynitrokey.trussed.bootloader import (
    Device,
    FirmwareContainer,
    parse_firmware_image,
)
from pynitrokey.updates import OverwriteError


class Context(trussed.Context[Nitrokey3Bootloader, Nitrokey3Device]):
    def __init__(self, path: Optional[str]) -> None:
        super().__init__(path, Nitrokey3Bootloader, Nitrokey3Device)  # type: ignore[type-abstract]

    @property
    def device_name(self) -> str:
        return "Nitrokey 3"

    def open(self, path: str) -> Optional[NitrokeyTrussedBase]:
        from pynitrokey.nk3 import open

        return open(path)

    def list_all(self) -> List[NitrokeyTrussedBase]:
        from pynitrokey.nk3 import list

        return list()


@click.group()
@click.option("-p", "--path", "path", help="The path of the Nitrokey 3 device")
@click.pass_context
def nk3(ctx: click.Context, path: Optional[str]) -> None:
    """Interact with Nitrokey 3 devices, see subcommands."""
    ctx.obj = Context(path)
    trussed.prepare_group()


# shared Trussed commands
trussed.add_commands(nk3)


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
    "-f",
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the firmware image if it already exists",
)
@click.option("--version", help="Download this version instead of the latest one")
def fetch_update(path: str, force: bool, version: Optional[str]) -> None:
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
        update = get_firmware_update(release)
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
@click.argument("image", type=click.Path(exists=True, dir_okay=False))
def validate_update(image: str) -> None:
    """
    Validates the given firmware image and prints the firmware version and the signer for all
    available variants.
    """
    container = FirmwareContainer.parse(image, Device.NITROKEY3)
    print(f"version:      {container.version}")
    if container.pynitrokey:
        print(f"pynitrokey:   >= {container.pynitrokey}")

    for variant in container.images:
        data = container.images[variant]
        try:
            metadata = parse_firmware_image(variant, data)
        except Exception as e:
            raise CliException("Failed to parse and validate firmware image", e)

        signed_by = metadata.signed_by or "unsigned"

        print(f"variant:      {variant.value}")
        print(f"  version:    {metadata.version}")
        print(f"  signed by:  {signed_by}")

        if container.version != metadata.version:
            raise CliException(
                f"The firmware image for the {variant} variant and the release "
                f"{container.version} has an unexpected product version ({metadata.version})."
            )


@nk3.command()
@click.argument("image", type=click.Path(exists=True, dir_okay=False), required=False)
@click.option(
    "--version",
    help="Set the firmware version to update to (default: latest stable)",
)
@click.option(
    "--ignore-pynitrokey-version",
    default=False,
    is_flag=True,
    help="Allow updates with an outdated pynitrokey version (dangerous)",
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
    ctx: Context,
    image: Optional[str],
    version: Optional[str],
    ignore_pynitrokey_version: bool,
    experimental: bool,
) -> None:
    """
    Update the firmware of the device using the given image.

    This command requires that exactly one Nitrokey 3 in bootloader or firmware mode is connected.
    The user is asked to confirm the operation before the update is started.  The Nitrokey 3 may
    not be removed during the update.  Also, additional Nitrokey 3 devices may not be connected
    during the update.

    If no firmware image is given, the latest firmware release is downloaded automatically.  If
    the --version option is set, the given version is downloaded instead.

    If the connected Nitrokey 3 device is in firmware mode, the user is prompted to touch the
    device’s button to confirm rebooting to bootloader mode.
    """

    if experimental:
        "The --experimental switch is not required to run this command anymore and can be safely removed."

    from .update import update as exec_update

    exec_update(ctx, image, version, ignore_pynitrokey_version)


@nk3.command()
@click.pass_obj
@click.argument("key")
def get_config(ctx: Context, key: str) -> None:
    """Query a config value."""
    with ctx.connect_device() as device:
        value = device.admin.get_config(key)
        print(value)


@nk3.command()
@click.pass_obj
@click.argument("key")
@click.argument("value")
@click.option(
    "-f",
    "--force",
    is_flag=True,
    default=False,
    help="Set the config value even if it is not known to pynitrokey",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Perform all checks but don’t execute the configuration change",
)
def set_config(ctx: Context, key: str, value: str, force: bool, dry_run: bool) -> None:
    """
    Set a config value.

    Per default, this command can only be used with configuration values that
    are known to pynitrokey.  Changing some configuration values can have side
    effects.  For these values, a summary of the effects of the change and a
    confirmation prompt will be printed.

    If you use the --force/-f flag, you can also set configuration values that
    are not known to pynitrokey.  This may have unexpected side effects, for
    example resetting an application.  It is only intended for development and
    testing.

    To see the information about a config value without actually performing the
    change, use the --dry-run flag.
    """

    with ctx.connect_device() as device:
        # before the confirmation prompt, check if the config value is supported
        if not device.admin.has_config(key):
            raise CliException(
                f"The configuration option '{key}' is not supported by the device.",
                support_hint=False,
            )

        # config fields that don’t have side effects
        whitelist = [
            "fido.disable_skip_up_timeout",
        ]
        requires_touch = False
        requires_reboot = False

        if key == "opcard.use_se050_backend":
            requires_touch = True
            requires_reboot = True
            print(
                "This configuration values determines whether the OpenPGP Card "
                "application uses a software implementation or the secure element.",
                file=sys.stderr,
            )
            print(
                "Changing this configuration value will cause a factory reset of "
                "the OpenPGP card application and destroy all OpenPGP keys and "
                "user data currently stored on the device.",
                file=sys.stderr,
            )
        elif key not in whitelist:
            pass
            print(
                "Changing configuration values can have unexpected side effects, including data loss.",
                file=sys.stderr,
            )
            print(
                "This should only be used for development and testing.",
                file=sys.stderr,
            )

            if not force:
                raise CliException(
                    "Unknown config values can only be set if the --force/-f flag is set.  Aborting.",
                    support_hint=False,
                )

        if key not in whitelist:
            click.confirm("Do you want to continue anyway?", abort=True)

        if dry_run:
            print("Stopping dry run.", file=sys.stderr)
            raise click.Abort()

        if requires_touch:
            print(
                "Press the touch button to confirm the configuration change.",
                file=sys.stderr,
            )

        device.admin.set_config(key, value)

        if requires_reboot:
            print("Rebooting device to apply config change.")
            device.reboot()

        print(f"Updated configuration {key}.")


@nk3.command()
@click.pass_obj
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
    hidden=True,
)
def factory_reset(ctx: Context, experimental: bool) -> None:
    """Factory reset all functionality of the device"""
    check_experimental_flag(experimental)
    with ctx.connect_device() as device:
        device.admin.factory_reset()


# We consciously do not allow resetting the admin app
APPLICATIONS_CHOICE = click.Choice(["fido", "opcard", "secrets", "piv", "webcrypt"])


@nk3.command()
@click.pass_obj
@click.argument("application", type=APPLICATIONS_CHOICE, required=True)
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
    hidden=True,
)
def factory_reset_app(ctx: Context, application: str, experimental: bool) -> None:
    """Factory reset all functionality of an application"""
    check_experimental_flag(experimental)
    with ctx.connect_device() as device:
        device.admin.factory_reset_app(application)


@nk3.command()
@click.pass_obj
def wink(ctx: Context) -> None:
    """Send wink command to the device (blinks LED a few times)."""
    with ctx.connect_device() as device:
        device.wink()


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
            f"Unexpected certificate subject OU {subject_attrs['OU']!r} (expected "
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


# This import has to be added here to avoid circular dependency
# Import "secrets" subcommand from the secrets module
from . import secrets  # noqa: F401,E402
