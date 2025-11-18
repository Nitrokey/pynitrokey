# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from typing import Optional, Sequence

import click
from nitrokey.nk3 import NK3, NK3Bootloader
from nitrokey.trussed import Model, TrussedBase
from nitrokey.trussed.updates import Warning

from pynitrokey.cli import trussed
from pynitrokey.cli.trussed import print_status
from pynitrokey.cli.trussed.test import TestCase
from pynitrokey.helpers import local_print


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
def wink(ctx: Context) -> None:
    """Send wink command to the device (blinks LED a few times)."""
    with ctx.connect_device() as device:
        device.wink()


# This import has to be added here to avoid circular dependency
# Import "secrets" subcommand from the secrets module
from . import piv  # noqa: F401,E402
from . import secrets  # noqa: F401,E402
