# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from typing import Optional

import click
from nitrokey.nkpk import NKPK, NKPKBootloader
from nitrokey.trussed import Model

from pynitrokey.cli.trussed.test import TestCase

from . import trussed


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


@click.group()
@click.option("-p", "--path", "path", help="The path of the Nitrokey 3 device")
@click.pass_context
def nkpk(ctx: click.Context, path: Optional[str]) -> None:
    """Interact with Nitrokey Passkey devices, see subcommands."""
    ctx.obj = Context(path)
    trussed.prepare_group()


# shared Trussed commands
trussed.add_commands(nkpk, has_app_reset=False)


def _list() -> None:
    trussed._list(Context(None))
