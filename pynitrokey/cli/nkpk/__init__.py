# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from typing import Optional, Sequence

import click
from nitrokey.nkpk import NKPK, NKPKBootloader
from nitrokey.trussed import Model, TrussedBase
from nitrokey.trussed.updates import Warning

from pynitrokey.cli import trussed
from pynitrokey.cli.trussed import print_status
from pynitrokey.cli.trussed.test import TestCase


class Context(trussed.Context[NKPKBootloader, NKPK]):
    def __init__(self, path: Optional[str]) -> None:
        super().__init__(
            path,
            NKPKBootloader,
            NKPK,
            Model.NKPK,
        )

    @property
    def test_cases(self) -> list[TestCase]:
        from pynitrokey.cli.trussed import tests

        return [
            tests.test_uuid_query,
            tests.test_firmware_version_query,
            tests.test_nkpk_device_status,
            tests.test_bootloader_configuration,
            tests.test_firmware_mode,
            tests.test_fido2,
        ]

    @property
    def device_name(self) -> str:
        return "Nitrokey Passkey"

    def open(self, path: str) -> Optional[TrussedBase]:
        from nitrokey.nkpk import open

        return open(path)

    def list_all(self) -> Sequence[TrussedBase]:
        from nitrokey.nkpk import list

        return list()


@click.group()
@click.option("-p", "--path", "path", help="The path of the Nitrokey 3 device")
@click.pass_context
def nkpk(ctx: click.Context, path: Optional[str]) -> None:
    """Interact with Nitrokey Passkey devices, see subcommands."""
    ctx.obj = Context(path)
    trussed.prepare_group()


# shared Trussed commands
trussed.add_commands(nkpk)


def _list() -> None:
    trussed._list(Context(None))


@nkpk.command()
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
    ctx: Context,
    image: Optional[str],
    version: Optional[str],
    ignore_warning: list[str],
    ignore_pynitrokey_version: bool,
    confirm: bool,
) -> None:
    """
    Update the firmware of the device using the given image.

    This command requires that exactly one Nitrokey Passkey in bootloader or firmware mode is connected.
    The user is asked to confirm the operation before the update is started. If the --confirm
    option is provided, this is the confirmation. This option may be used to automate an update.
    The Nitrokey Passkey may not be removed during the update. Also, additional Nitrokey Passkey devices may
    not be connected during the update.

    If no firmware image is given, the latest firmware release is downloaded automatically. If
    the --version option is set, the given version is downloaded instead.

    If the connected Nitrokey 3 device is in firmware mode, the user is prompted to touch the
    device's button to confirm rebooting to bootloader mode.
    """

    from .update import update as exec_update

    ignore_warnings = frozenset([Warning.from_str(s) for s in ignore_warning])
    update_to_version, status = exec_update(
        ctx, image, version, ignore_pynitrokey_version, ignore_warnings, confirm
    )
    print_status(update_to_version, status)
