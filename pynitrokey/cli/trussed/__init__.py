# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import logging
import os.path
import sys
from abc import ABC, abstractmethod
from hashlib import sha256
from typing import BinaryIO, Callable, Generic, Optional, Sequence, TypeVar

import click
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from nitrokey import trussed
from nitrokey.trussed import (
    FirmwareContainer,
    Model,
    TimeoutException,
    TrussedBase,
    TrussedBootloader,
    TrussedDevice,
    Version,
    parse_firmware_image,
    should_default_ccid,
    updates,
)
from nitrokey.trussed.admin_app import BootMode, InitStatus, Status
from nitrokey.trussed.provisioner_app import ProvisionerApp
from nitrokey.trussed.updates import Warning
from nitrokey.updates import OverwriteError

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import (
    DownloadProgressBar,
    Retries,
    Table,
    local_critical,
    local_print,
    require_windows_admin,
)

from .test import TestCase

T = TypeVar("T", bound=TrussedBase)
Bootloader = TypeVar("Bootloader", bound=TrussedBootloader)
Device = TypeVar("Device", bound=TrussedDevice)

logger = logging.getLogger(__name__)


class Context(ABC, Generic[Bootloader, Device]):
    def __init__(
        self,
        path: Optional[str],
        bootloader_type: type[Bootloader],
        device_type: type[Device],
        model: Model,
        protocol_is_ccid: bool,
    ) -> None:
        self.path = path
        self.bootloader_type = bootloader_type
        self.device_type = device_type
        self.model = model
        self.protocol_is_ccid = protocol_is_ccid

    @property
    @abstractmethod
    def test_cases(self) -> Sequence[TestCase]: ...

    def open(self, path: str) -> Optional[TrussedBase]:
        return trussed.open(path, model=self.model)

    def list_all(self) -> Sequence[TrussedBase]:
        return trussed.list(self.protocol_is_ccid, model=self.model)

    def list(self) -> Sequence[TrussedBase]:
        if self.path:
            device = self.open(self.path)
            if device:
                return [device]
            else:
                return []
        else:
            return self.list_all()

    def connect(self) -> TrussedBase:
        return self._select_unique(str(self.model), self.list())

    def connect_device(self) -> Device:
        devices = [
            device for device in self.list() if isinstance(device, self.device_type)
        ]
        return self._select_unique(str(self.model), devices)

    def await_device(
        self,
        retries: Optional[int] = None,
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> Device:
        return self._await(str(self.model), self.device_type, retries, callback)

    def await_bootloader(
        self,
        retries: Optional[int] = None,
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> Bootloader:
        return self._await(
            f"{self.model} bootloader", self.bootloader_type, retries, callback
        )

    def _select_unique(self, name: str, devices: Sequence[T]) -> T:
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

    def _await(
        self,
        name: str,
        ty: type[T],
        retries: Optional[int],
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> T:
        if retries is None:
            retries = 30
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


def prepare_group() -> None:
    require_windows_admin()


def add_commands(group: click.Group, *, has_app_reset: bool = True) -> None:
    group.add_command(fetch_update)
    group.add_command(list)
    group.add_command(list_config_fields)
    group.add_command(get_config)
    group.add_command(set_config)
    group.add_command(factory_reset)
    if has_app_reset:
        group.add_command(factory_reset_app)
    group.add_command(provision)
    group.add_command(reboot)
    group.add_command(rng)
    group.add_command(status)
    group.add_command(test)
    group.add_command(update)
    group.add_command(validate_update)
    group.add_command(version)


@click.command()
@click.argument("path", default=".")
@click.option(
    "-f",
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the firmware image if it already exists",
)
@click.option("--version", help="Download this version instead of the latest one")
@click.pass_obj
def fetch_update(
    ctx: Context[Bootloader, Device], path: str, force: bool, version: Optional[str]
) -> None:
    """
    Fetches a firmware update and stores it at the given path.

    If no path is given, the firmware image stored in the current working
    directory.  If the given path is a directory, the image is stored under
    that directory.  Otherwise it is written to the path.  Existing files are
    only overwritten if --force is set.

    Per default, the latest firmware release is fetched.  If you want to
    download a specific version, use the --version option.
    """
    try:
        firmware_repository = updates.get_firmware_repository(ctx.model)
        release = firmware_repository.get_release_or_latest(version)
        update = updates.get_firmware_update(ctx.model, release)
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


@click.command()
@click.pass_obj
def list(ctx: Context[Bootloader, Device]) -> None:
    """List all devices."""
    return _list(ctx)


def _list(ctx: Context[Bootloader, Device]) -> None:
    local_print(f":: '{ctx.model}' keys")
    for device in ctx.list_all():
        print("DEVICE", device)
        with device as device:
            uuid = device.uuid()
            msg = ""
            if device.path:
                msg = msg + device.path + ": "
            msg = msg + device.name
            if uuid:
                msg = msg + f" {uuid}"
            local_print(msg)


@click.command()
@click.pass_obj
def list_config_fields(ctx: Context[Bootloader, Device]) -> None:
    """
    List all supported config fields.

    This commands lists all config fields that can be accessed with get-config
    and set-config as well as their type. The possible types are Bool ("true"
    or "false") and U8 (an integer between 0 and 255).

    The available config fields depend on the firmware version of the device.
    """
    with ctx.connect_device() as device:
        fields = device.admin.list_available_fields()

        table = Table(["config field", "type"])
        for field in fields:
            table.add_row(
                [
                    field.name,
                    field.ty,
                ]
            )
        local_print(table)


@click.command()
@click.pass_obj
@click.argument("key")
def get_config(ctx: Context[Bootloader, Device], key: str) -> None:
    """Query a config value."""
    with ctx.connect_device() as device:
        value = device.admin.get_config(key)
        print(value)


@click.command()
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
def set_config(
    ctx: Context[Bootloader, Device], key: str, value: str, force: bool, dry_run: bool
) -> None:
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
        config_fields = device.admin.list_available_fields()

        field_metadata = None
        for field in config_fields:
            if field.name == key:
                field_metadata = field

        if field_metadata is None:
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

        if (
            not force
            and field_metadata is not None
            and not field_metadata.ty.is_valid(value)
        ):
            raise CliException(
                f"Invalid config value for {field}: expected {field_metadata.ty}, got `{value}`. Unknown config values can only be set if the --force/-f flag is set.  Aborting.",
                support_hint=False,
            )

        if key == "opcard.use_se050_backend":
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
        elif field_metadata is not None and field_metadata.destructive:
            print(
                "This configuration value may delete data on your device",
                file=sys.stderr,
            )

        if field_metadata is not None and field_metadata.destructive:
            click.confirm("Do you want to continue anyway?", abort=True)

        if dry_run:
            print("Stopping dry run.", file=sys.stderr)
            raise click.Abort()

        if field_metadata is not None and field_metadata.requires_touch_confirmation:
            print(
                "Press the touch button to confirm the configuration change.",
                file=sys.stderr,
            )

        device.admin.set_config(key, value)

        if field_metadata is not None and field_metadata.requires_reboot:
            print("Rebooting device to apply config change.")
            device.reboot()

        print(f"Updated configuration {key}.")


@click.command()
@click.pass_obj
def factory_reset(ctx: Context[Bootloader, Device]) -> None:
    """Factory reset all functionality of the device"""

    with ctx.connect_device() as device:
        local_print("Please touch the device to confirm the operation", file=sys.stderr)
        if not device.admin.factory_reset():
            local_critical(
                "Factory reset is not supported by the firmware version on the device",
                support_hint=False,
            )


# opcard is the only application that supports factory reset at the moment
# see the reset_client_id implementations in components/apps/src/lib.rs in nitrokey-3-firmware
APPLICATIONS_CHOICE = click.Choice(["opcard"])


@click.command()
@click.pass_obj
@click.argument("application", type=APPLICATIONS_CHOICE, required=True)
def factory_reset_app(ctx: Context[Bootloader, Device], application: str) -> None:
    """Factory reset all functionality of an application"""

    with ctx.connect_device() as device:
        local_print("Please touch the device to confirm the operation", file=sys.stderr)
        if not device.admin.factory_reset_app(application):
            local_critical(
                "Application Factory reset is not supported by the firmware version on the device",
                support_hint=False,
            )


@click.group(hidden=True)
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
def provision_fido2(
    ctx: Context[Bootloader, Device], key_file: BinaryIO, cert_file: BinaryIO
) -> None:
    """Provision the FIDO2 attestation key and certificate."""
    key = key_file.read()
    cert = cert_file.read()

    if len(key) != 36:
        raise CliException(f"Invalid key length {len(key)} (expected 36)")
    ec_key = ec.derive_private_key(int(key[4:].hex(), 16), ec.SECP256R1())
    ec_pubkey = ec_key.public_key()
    x509_cert = x509.load_der_x509_certificate(cert)
    cert_pubkey = x509_cert.public_key()

    if not isinstance(cert_pubkey, ec.EllipticCurvePublicKey):
        raise CliException(
            "The FIDO2 attestation certificate does not contain an EC key"
        )
    if ec_pubkey.public_numbers() != cert_pubkey.public_numbers():
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
            f"Unexpected certificate subject OU {subject_attrs['OU']!r} (expected Authenticator Attestation)"
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


@click.command()
@click.option(
    "--bootloader",
    is_flag=True,
    help="Reboot the device into bootloader mode",
)
@click.pass_obj
def reboot(ctx: Context[Bootloader, Device], bootloader: bool) -> None:
    """
    Reboot the key.

    Per default, the key will reboot into regular firmware mode.  If the --bootloader option
    is set, a key can boot from firmware mode to bootloader mode.  Booting into
    bootloader mode has to be confirmed by pressing the touch button.
    """
    with ctx.connect() as device:
        if bootloader:
            if isinstance(device, TrussedDevice):
                success = reboot_to_bootloader(device)
            else:
                raise CliException(
                    "A device in bootloader mode can only reboot into firmware mode.",
                    support_hint=False,
                )
        else:
            success = device.reboot()

    if not success:
        raise CliException(
            "The connected device cannot be rebooted automatically.  Remove and reinsert the device to reboot it.",
            support_hint=False,
        )


def reboot_to_bootloader(device: TrussedDevice) -> bool:
    local_print(
        "Please press the touch button to reboot the device into bootloader mode ..."
    )
    try:
        return device.admin.reboot(BootMode.BOOTROM)
    except TimeoutException:
        raise CliException(
            "The reboot was not confirmed with the touch button.",
            support_hint=False,
        )


@click.command()
@click.option(
    "-l",
    "--length",
    "length",
    default=57,
    help="The length of the generated data (default: 57)",
)
@click.pass_obj
def rng(ctx: Context[Bootloader, Device], length: int) -> None:
    """Generate random data on the device."""
    with ctx.connect_device() as device:
        while length > 0:
            rng = device.admin.rng()
            local_print(rng[:length].hex())
            length -= len(rng)


def print_status(version: Version, status: Status) -> None:
    local_print(f"Firmware version:   {version}")
    if status.init_status is not None:
        local_print(f"Init status:        {status.init_status}")
    if status.ifs_blocks is not None:
        local_print(f"Free blocks (int):  {status.ifs_blocks}")
    if status.efs_blocks is not None:
        local_print(f"Free blocks (ext):  {status.efs_blocks}")
    if status.variant is not None:
        local_print(f"Variant:            {status.variant.name}")

    # Print at the end so that other status info are written
    if status.init_status is not None:
        if status.init_status & InitStatus.EXT_FLASH_NEED_REFORMAT:
            local_critical(
                "EFS is corrupted, please contact support for information on how to solve this issue"
            )


@click.command()
@click.pass_obj
def status(ctx: Context[Bootloader, Device]) -> None:
    """Query the device status."""
    with ctx.connect_device() as device:
        uuid = device.uuid()
        if uuid is not None:
            local_print(f"UUID:               {uuid}")

        version = device.admin.version()
        local_print(f"Firmware version:   {version}")

        status = device.admin.status()
        if status.init_status is not None:
            local_print(f"Init status:        {status.init_status}")
        if status.ifs_blocks is not None:
            local_print(f"Free blocks (int):  {status.ifs_blocks}")
        if status.efs_blocks is not None:
            local_print(f"Free blocks (ext):  {status.efs_blocks}")
        if status.variant is not None:
            local_print(f"Variant:            {status.variant.name}")


@click.command()
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
    ctx: Context[Bootloader, Device],
    pin: Optional[str],
    only: Optional[str],
    all: bool,
    include: Optional[str],
    exclude: Optional[str],
    list_: bool,
) -> None:
    """Run some tests on all connected devices."""
    from pynitrokey.cli.trussed.test import (
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
        list_tests(test_selector, ctx.test_cases)
        return

    log_system()
    devices = ctx.list()

    if len(devices) == 0:
        log_devices()
        raise CliException(f"No connected {ctx.model} devices found")

    local_print(f"Found {len(devices)} {ctx.model} device(s):")
    for device in devices:
        local_print(f"- {device.name} at {device.path}")

    results = []
    test_ctx = TestContext(pin=pin)
    for device in devices:
        results.append(
            run_tests(
                test_ctx,
                device,
                test_selector,
                ctx.test_cases,
            )
        )

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


@click.command()
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
    "--ignore-warning",
    help="Ignore the warning(s) with the given ID(s) during the update (dangerous)",
    type=click.Choice([w.value for w in Warning]),
    multiple=True,
)
@click.option(
    "--confirm",
    default=False,
    is_flag=True,
    help="Confirm all questions to allow running non-interactively",
)
@click.pass_obj
def update(
    ctx: Context[Bootloader, Device],
    image: Optional[str],
    version: Optional[str],
    ignore_warning: Sequence[str],
    ignore_pynitrokey_version: bool,
    confirm: bool,
) -> None:
    """
    Update the firmware of the device using the given image.

    This command requires that exactly one Nitrokey in bootloader or firmware mode is connected.
    The user is asked to confirm the operation before the update is started.  If the --confirm
    option is provided, this is the confirmation.  This option may be used to automate an update.
    The Nitrokey may not be removed during the update.  Also, additional Nitrokey devices may
    not be connected during the update.

    If no firmware image is given, the latest firmware release is downloaded automatically.  If
    the --version option is set, the given version is downloaded instead.

    If the connected Nitrokey device is in firmware mode, the user is prompted to touch the
    device’s button to confirm rebooting to bootloader mode.
    """

    from .update import update as exec_update

    if ctx.protocol_is_ccid:
        windows_part = ""
        flag_part = ""
        if sys.platform == "win32" or sys.platform == "cygwin":
            windows_part = " be aware that --use-ctaphid will require runing nitropy as an administrator"
        flag_part = (
            "please use `nitropy nk3 --use-ctaphid update`"
            if should_default_ccid()
            else "please remove the `--use-ccid flag`"
        )
        local_critical(
            f"Updating is not supported over ccid, {flag_part}{windows_part}",
            support_hint=False,
        )

    ignore_warnings = frozenset([Warning.from_str(s) for s in ignore_warning])
    update_to_version, status = exec_update(
        ctx, image, version, ignore_pynitrokey_version, ignore_warnings, confirm
    )
    print_status(update_to_version, status)


@click.command()
@click.argument("image", type=click.Path(exists=True, dir_okay=False))
@click.pass_obj
def validate_update(ctx: Context[Bootloader, Device], image: str) -> None:
    """
    Validates the given firmware image and prints the firmware version and the signer for all
    available variants.
    """
    try:
        container = FirmwareContainer.parse(image, ctx.model)
    except ValueError as e:
        raise CliException("Failed to validate firmware image", e, support_hint=False)

    print(f"version:      {container.version}")
    if container.sdk:
        print(f"Nitrokey SDK: >= {container.sdk}")
    if container.pynitrokey:
        print(f"pynitrokey:   >= {container.pynitrokey}")

    for variant in container.images:
        data = container.images[variant]
        try:
            metadata = parse_firmware_image(variant, data, ctx.model)
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


@click.command()
@click.pass_obj
def version(ctx: Context[Bootloader, Device]) -> None:
    """Query the firmware version of the device."""
    with ctx.connect_device() as device:
        version = device.admin.version()
        local_print(version)
