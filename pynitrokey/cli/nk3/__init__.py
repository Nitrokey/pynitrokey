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
from hashlib import sha256
from typing import BinaryIO, Callable, List, Optional, Type, TypeVar

import click
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from ecdsa import NIST256p, SigningKey

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import (
    DownloadProgressBar,
    Retries,
    local_print,
    require_windows_admin,
)
from pynitrokey.nk3 import list as list_nk3
from pynitrokey.nk3 import open as open_nk3
from pynitrokey.nk3.admin_app import AdminApp
from pynitrokey.nk3.base import Nitrokey3Base
from pynitrokey.nk3.bootloader import (
    FirmwareContainer,
    Nitrokey3Bootloader,
    parse_firmware_image,
)
from pynitrokey.nk3.device import BootMode, Nitrokey3Device
from pynitrokey.nk3.exceptions import TimeoutException
from pynitrokey.nk3.provisioner_app import ProvisionerApp
from pynitrokey.nk3.updates import REPOSITORY, get_firmware_update
from pynitrokey.updates import OverwriteError

T = TypeVar("T", bound=Nitrokey3Base)

logger = logging.getLogger(__name__)


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

    def _await(
        self,
        name: str,
        ty: Type[T],
        retries: int,
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> T:
        for t in Retries(retries):
            logger.debug(f"Searching {name} device ({t})")
            devices = [device for device in self.list() if isinstance(device, ty)]
            if len(devices) == 0:
                if callback:
                    callback(int((t.i / retries) * 100), 100)
                logger.debug(f"No {name} device found, continuing")
                continue
            if len(devices) > 1:
                raise CliException(f"Multiple {name} devices found")
            if callback:
                callback(100, 100)
            return devices[0]

        raise CliException(f"No {name} device found")

    def await_device(
        self,
        retries: Optional[int] = 30,
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> Nitrokey3Device:
        assert isinstance(retries, int)
        return self._await("Nitrokey 3", Nitrokey3Device, retries, callback)

    def await_bootloader(
        self,
        retries: Optional[int] = 30,
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> Nitrokey3Bootloader:
        assert isinstance(retries, int)
        # mypy does not allow abstract types here, but this is still valid
        return self._await("Nitrokey 3 bootloader", Nitrokey3Bootloader, retries, callback)  # type: ignore


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
@click.argument("image")
def validate_update(image: str) -> None:
    """
    Validates the given firmware image and prints the firmware version and the signer for all
    available variants.
    """
    container = FirmwareContainer.parse(image)
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
                f"The firmware image for the {variant} variant and the release {version} has an "
                f"unexpected product version ({metadata.version})."
            )


@nk3.command()
@click.argument("image", required=False)
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
def status(ctx: Context) -> None:
    """Query the device status."""
    with ctx.connect_device() as device:
        uuid = device.uuid()
        if uuid is not None:
            local_print(f"UUID:               {uuid}")

        admin = AdminApp(device)
        version = admin.version()
        local_print(f"Firmware version:   {version}")

        status = admin.status()
        if status.init_status is not None:
            local_print(f"Init status:        {status.init_status}")
        if status.ifs_blocks is not None:
            local_print(f"Free blocks (int):  {status.ifs_blocks}")
        if status.efs_blocks is not None:
            local_print(f"Free blocks (ext):  {status.efs_blocks}")


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


# This import has to be added here to avoid circular dependency
# Import "secrets" subcommand from the secrets module
from . import secrets  # noqa: F401,E402
