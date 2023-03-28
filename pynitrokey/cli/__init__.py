# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import os
import platform
import sys
import warnings
from datetime import datetime
from importlib.metadata import version as package_version

import click

import pynitrokey
import pynitrokey.fido2.operations
from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.fido2 import fido2
from pynitrokey.cli.nethsm import nethsm
from pynitrokey.cli.nk3 import nk3
from pynitrokey.cli.pro import pro
from pynitrokey.cli.start import start
from pynitrokey.cli.storage import storage
from pynitrokey.confconsts import LOG_FN, LOG_FORMAT
from pynitrokey.helpers import local_critical

# from . import _patches  # noqa  (since otherwise "unused")

logger = logging.getLogger(__name__)


def check_root():
    if (os.name == "posix") and os.environ.get("ALLOW_ROOT") is None:
        if os.geteuid() == 0:
            print("THIS COMMAND SHOULD NOT BE RUN AS ROOT!")
            subcommand = sys.argv[1]
            if subcommand != "nethsm":
                print()
                print(
                    "Please install udev rules and run `nitropy` as regular user (without sudo)."
                )
                print(
                    "We suggest using: https://raw.githubusercontent.com/Nitrokey/libnitrokey/master/data/41-nitrokey.rules"
                )
                print(
                    "For more information, see: https://docs.nitrokey.com/software/nitropy/linux/udev.html"
                )
                print()
            print("Set ALLOW_ROOT=1 environment variable to disable this warning.")
            print()


@click.group()
def nitropy():
    handler = logging.FileHandler(filename=LOG_FN, delay=True, encoding="utf-8")
    logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG, handlers=[handler])

    logger.info(f"Timestamp: {datetime.now()}")
    logger.info(f"OS: {platform.uname()}")
    logger.info(f"Python version: {platform.python_version()}")
    pymodules = [
        "pynitrokey",
        "cryptography",
        "ecdsa",
        "fido2",
        "pyusb",
        "spsdk",
    ]
    for x in pymodules:
        logger.info(f"{x} version: {package_version(x)}")

    print(
        f"Command line tool to interact with Nitrokey devices {pynitrokey.__version__}",
        file=sys.stderr,
    )

    check_root()


nitropy.add_command(fido2)
nitropy.add_command(nethsm)
nitropy.add_command(nk3)
nitropy.add_command(start)
nitropy.add_command(storage)
nitropy.add_command(pro)


@click.command()
def version():
    """Version of pynitrokey library and tool."""
    print(pynitrokey.__version__)


nitropy.add_command(version)


def _list():
    fido2.commands["list"].callback()
    start.commands["list"].callback()
    nk3.commands["list"].callback()
    # TODO add other handled models


@click.command()
def list():
    """List Nitrokey devices (in firmware or bootloader mode)"""
    _list()


@click.command(hidden=True)
def ls():
    warnings.warn("The ls command is deprecated. Please use list instead.")
    _list()


nitropy.add_command(list)
nitropy.add_command(ls)


def main() -> None:
    development = os.environ.get("NKDEV")
    try:
        nitropy()
    except CliException as e:
        if development:
            raise
        e.show()
    except Exception as e:
        if development:
            raise
        logger.warning("An unhandled exception occurred", exc_info=True)
        local_critical("An unhandled exception occurred", e)
