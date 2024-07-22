# -*- coding: utf-8 -*-
#
# Copyright 2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import Optional

import click

from pynitrokey.cli.trussed.test import TestCase
from pynitrokey.nkpk import NKPK_DATA, NitrokeyPasskeyBootloader, NitrokeyPasskeyDevice
from pynitrokey.trussed.base import NitrokeyTrussedBase
from pynitrokey.trussed.bootloader import Device

from . import trussed


class Context(trussed.Context[NitrokeyPasskeyBootloader, NitrokeyPasskeyDevice]):
    def __init__(self, path: Optional[str]) -> None:
        super().__init__(
            path,
            NitrokeyPasskeyBootloader,
            NitrokeyPasskeyDevice,
            Device.NITROKEY_PASSKEY,
            NKPK_DATA,
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

    def open(self, path: str) -> Optional[NitrokeyTrussedBase]:
        from pynitrokey.nkpk import open

        return open(path)

    def list_all(self) -> list[NitrokeyTrussedBase]:
        from pynitrokey.nkpk import list

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
