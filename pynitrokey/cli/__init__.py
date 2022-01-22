# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import os
import sys
import warnings

import click

import pynitrokey
import pynitrokey.fido2.operations
from pynitrokey.cli.fido2 import fido2
from pynitrokey.cli.nethsm import nethsm
from pynitrokey.cli.pro import pro
from pynitrokey.cli.start import start
from pynitrokey.cli.storage import storage
from pynitrokey.confconsts import LOG_FN, LOG_FORMAT

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from pynitrokey.cli.nk3 import nk3

    NK3_ENABLED = True
except ImportError:
    NK3_ENABLED = False

# from . import _patches  # noqa  (since otherwise "unused")


def check_root():
    if (os.name == "posix") and os.environ.get("ALLOW_ROOT") is None:
        if os.geteuid() == 0:
            print("THIS COMMAND SHOULD NOT BE RUN AS ROOT!")
            print()
            print(
                "Please install udev rules and run `nitropy` as regular user (without sudo)."
            )
            print(
                "We suggest using: https://raw.githubusercontent.com/Nitrokey/libnitrokey/master/data/41-nitrokey.rules"
            )
            print()
            print(
                "For more information, see: https://www.nitrokey.com/documentation/installation#p:nitrokey-fido2&os:linux"
            )


@click.group()
def nitropy():
    handler = logging.FileHandler(filename=LOG_FN, delay=True)
    logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG, handlers=[handler])

    print(
        "Nitrokey tool for Nitrokey FIDO2, Nitrokey Start, Nitrokey 3 & NetHSM",
        file=sys.stderr,
    )
    check_root()


@click.command(
    name="nk3",
    hidden=True,
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def nk3_fallback():
    raise click.ClickException(
        "The nk3 command requires the nk3 extra.  You can install it using:\n"
        "  pip install pynitrokey[nk3]"
    )


nitropy.add_command(fido2)
nitropy.add_command(nethsm)
nitropy.add_command(nk3 if NK3_ENABLED else nk3_fallback)
nitropy.add_command(start)
nitropy.add_command(storage)
nitropy.add_command(pro)


@click.command()
def version():
    """Version of pynitrokey library and tool."""
    print(pynitrokey.__version__)


nitropy.add_command(version)


@click.command()
def ls():
    """List Nitrokey keys (in firmware or bootloader mode)"""

    fido2.commands["list"].callback()
    start.commands["list"].callback()
    if NK3_ENABLED:
        nk3.commands["list"].callback()


nitropy.add_command(ls)
