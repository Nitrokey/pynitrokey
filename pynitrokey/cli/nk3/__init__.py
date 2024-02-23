# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import sys
from typing import List, Optional

import click

from pynitrokey.cli import trussed
from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.trussed.test import TestCase
from pynitrokey.helpers import check_experimental_flag
from pynitrokey.nk3 import NK3_DATA
from pynitrokey.nk3.bootloader import Nitrokey3Bootloader
from pynitrokey.nk3.device import Nitrokey3Device
from pynitrokey.trussed.base import NitrokeyTrussedBase
from pynitrokey.trussed.bootloader import Device


class Context(trussed.Context[Nitrokey3Bootloader, Nitrokey3Device]):
    def __init__(self, path: Optional[str]) -> None:
        super().__init__(path, Nitrokey3Bootloader, Nitrokey3Device, Device.NITROKEY3, NK3_DATA)  # type: ignore[type-abstract]

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


# This import has to be added here to avoid circular dependency
# Import "secrets" subcommand from the secrets module
from . import secrets  # noqa: F401,E402
