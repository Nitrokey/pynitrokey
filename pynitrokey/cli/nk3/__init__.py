# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from typing import Optional

import click
from nitrokey.nk3 import NK3, NK3Bootloader
from nitrokey.trussed import Model

from pynitrokey.cli import trussed
from pynitrokey.cli.trussed.test import TestCase


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
@click.pass_obj
def wink(ctx: Context) -> None:
    """Send wink command to the device (blinks LED a few times)."""
    with ctx.connect_device() as device:
        device.wink()


# This import has to be added here to avoid circular dependency
# Import "secrets" subcommand from the secrets module
from . import piv  # noqa: F401,E402
from . import secrets  # noqa: F401,E402
