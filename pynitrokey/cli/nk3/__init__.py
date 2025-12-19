# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import logging
from typing import Optional

import click
from nitrokey.nk3 import NK3, NK3Bootloader
from nitrokey.trussed import Model, should_default_ccid

from pynitrokey.cli import trussed
from pynitrokey.cli.trussed.test import TestCase
from pynitrokey.helpers import local_print


class Context(trussed.Context[NK3Bootloader, NK3]):
    def __init__(self, path: Optional[str], protocol_is_ccid: bool) -> None:
        super().__init__(path, NK3Bootloader, NK3, Model.NK3, protocol_is_ccid)  # type: ignore[type-abstract]

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
@click.option(
    "--use-ccid",
    "use_ccid",
    help="Use CCID  to communicate with the Nitrokey Passkey",
    default=False,
    flag_value=True,
)
@click.option(
    "--use-ctaphid",
    "use_ctaphid",
    help="Use CTAPHID to communicate with the Nitrokey Passkey",
    default=False,
    flag_value=True,
)
@click.pass_context
def nk3(
    ctx: click.Context,
    path: Optional[str],
    use_ctaphid: bool,
    use_ccid: bool,
) -> None:
    """Interact with Nitrokey 3 devices, see subcommands."""

    protocol_is_ccid = should_default_ccid()
    if use_ccid and not use_ctaphid:
        protocol_is_ccid = True
    elif use_ctaphid and not use_ccid:
        protocol_is_ccid = False
    elif use_ctaphid and use_ccid:
        local_print(
            "--use-ccid and --use-ctaphid cannot be used at the same time, please chose one option"
        )
        raise click.Abort()
    elif use_ccid and path is not None:
        local_print(
            "--use-ccid and -p/--path cannot be used at the same time",
        )
        raise click.Abort()

    logger = logging.getLogger(__name__)
    logger.info(f"Protocol is {'ccid' if protocol_is_ccid else 'ctaphid'}")

    ctx.obj = Context(path, protocol_is_ccid)
    trussed.prepare_group()


# shared Trussed commands
trussed.add_commands(nk3)


def _list() -> None:
    trussed._list(Context(None, should_default_ccid()))


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
