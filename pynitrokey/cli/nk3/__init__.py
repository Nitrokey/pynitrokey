# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import sys
from typing import Optional, Sequence

import click
from nitrokey.nk3 import NK3, NK3Bootloader
from nitrokey.trussed import Model, TrussedBase
from nitrokey.trussed.updates import Warning

from pynitrokey.cli import trussed
from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.trussed import print_status
from pynitrokey.cli.trussed.test import TestCase
from pynitrokey.helpers import Table, local_critical, local_print


class Context(trussed.Context[NK3Bootloader, NK3]):
    def __init__(self, path: Optional[str]) -> None:
        super().__init__(path, NK3Bootloader, NK3, Model.NK3)  # type: ignore[type-abstract]

    @property
    def test_cases(self) -> list[TestCase]:
        from pynitrokey.cli.trussed import tests

        return [
            tests.test_uuid_query,
            tests.test_firmware_version_query,
            tests.test_nk3_device_status,
            tests.test_bootloader_configuration,
            tests.test_firmware_mode,
            tests.test_se050,
            tests.test_fido2,
        ]

    def open(self, path: str) -> Optional[TrussedBase]:
        from nitrokey.nk3 import open

        return open(path)

    def list_all(self) -> Sequence[TrussedBase]:
        from nitrokey.nk3 import list

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


def _list() -> None:
    trussed._list(Context(None))


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
    ignore_warning: list[str],
    ignore_pynitrokey_version: bool,
    confirm: bool,
    experimental: bool,
) -> None:
    """
    Update the firmware of the device using the given image.

    This command requires that exactly one Nitrokey 3 in bootloader or firmware mode is connected.
    The user is asked to confirm the operation before the update is started.  If the --confirm
    option is provided, this is the confirmation.  This option may be used to automate an update.
    The Nitrokey 3 may not be removed during the update.  Also, additional Nitrokey 3 devices may
    not be connected during the update.

    If no firmware image is given, the latest firmware release is downloaded automatically.  If
    the --version option is set, the given version is downloaded instead.

    If the connected Nitrokey 3 device is in firmware mode, the user is prompted to touch the
    device’s button to confirm rebooting to bootloader mode.
    """

    if experimental:
        local_print(
            "The --experimental switch is not required to run this command anymore and can be safely removed."
        )

    from .update import update as exec_update

    ignore_warnings = frozenset([Warning.from_str(s) for s in ignore_warning])
    update_to_version, status = exec_update(
        ctx, image, version, ignore_pynitrokey_version, ignore_warnings, confirm
    )
    print_status(update_to_version, status)


@nk3.command()
@click.pass_obj
def list_config_fields(ctx: Context) -> None:
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

    if experimental:
        local_print(
            "The --experimental switch is not required to run this command anymore and can be safely removed."
        )

    with ctx.connect_device() as device:
        local_print("Please touch the device to confirm the operation", file=sys.stderr)
        if not device.admin.factory_reset():
            local_critical(
                "Factory reset is not supported by the firmware version on the device",
                support_hint=False,
            )


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

    if experimental:
        local_print(
            "The --experimental switch is not required to run this command anymore and can be safely removed."
        )

    with ctx.connect_device() as device:
        local_print("Please touch the device to confirm the operation", file=sys.stderr)
        if not device.admin.factory_reset_app(application):
            local_critical(
                "Application Factory reset is not supported by the firmware version on the device",
                support_hint=False,
            )


@nk3.command()
@click.pass_obj
def wink(ctx: Context) -> None:
    """Send wink command to the device (blinks LED a few times)."""
    with ctx.connect_device() as device:
        device.wink()


# This import has to be added here to avoid circular dependency
# Import "secrets" subcommand from the secrets module
from . import piv  # noqa: F401,E402
from . import secrets  # noqa: F401,E402
