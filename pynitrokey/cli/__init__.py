# Copyright 2019 SoloKeys Developers
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import logging
import os
import platform
import sys
import warnings
from datetime import datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version

import click

import pynitrokey
from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.fido2 import fido2
from pynitrokey.cli.nethsm import nethsm
from pynitrokey.cli.nk3 import nk3
from pynitrokey.cli.nkpk import nkpk
from pynitrokey.cli.pro import pro
from pynitrokey.cli.start import start
from pynitrokey.cli.storage import storage
from pynitrokey.confconsts import LOG_FN, LOG_FORMAT
from pynitrokey.helpers import filter_sensitive_parameters, local_critical

logger = logging.getLogger(__name__)


def check_root() -> None:
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


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
def nitropy() -> None:
    handler = logging.FileHandler(filename=LOG_FN, delay=True, encoding="utf-8")
    logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG, handlers=[handler])

    logger.info(f"Timestamp: {datetime.now()}")
    logger.info(f"OS: {platform.uname()}")
    logger.info(f"Python version: {platform.python_version()}")
    logger.info(f"Cli arguments: {filter_sensitive_parameters(sys.argv[1:])}")
    pymodules = [
        "pynitrokey",
        "cryptography",
        "fido2",
        "nethsm",
        "nitrokey",
        "pyusb",
    ]
    for x in pymodules:
        try:
            logger.info(f"{x} version: {package_version(x)}")
        except PackageNotFoundError:
            logger.warning(f"package {x} not found")

    version = package_version("pynitrokey")
    print(
        f"Command line tool to interact with Nitrokey devices {version}",
        file=sys.stderr,
    )

    check_root()


from . import nkfido2

nkfido2.add_commands(fido2)

nitropy.add_command(fido2)
nitropy.add_command(nethsm)
nitropy.add_command(nk3)
nitropy.add_command(nkpk)
nitropy.add_command(start)
nitropy.add_command(storage)
nitropy.add_command(pro)


@click.command()
def version() -> None:
    """Version of pynitrokey library and tool."""
    print(package_version("pynitrokey"))


nitropy.add_command(version)


def _list() -> None:
    from .nk3 import _list as list_nk3
    from .nkpk import _list as list_nkpk

    list_fido2 = fido2.commands["list"].callback
    list_start = start.commands["list"].callback
    assert list_fido2 is not None
    assert list_start is not None

    list_fido2()
    list_start()
    list_nk3()
    list_nkpk()
    # TODO add other handled models


@click.command()
def list() -> None:
    """List Nitrokey devices (in firmware or bootloader mode)"""
    _list()


@click.command(hidden=True)
def ls() -> None:
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
