# -*- coding: utf-8 -*-
#
# Copyright 2020 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.


import click

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import AskUser, local_critical, local_print
from pynitrokey.libnk import BaseLibNitrokey, DeviceNotFound, NitrokeyStorage, RetCode


def connect_nkstorage():
    try:
        nks = NitrokeyStorage()
        nks.connect()
        return nks
    except DeviceNotFound:
        raise CliException("No Nitrokey Storage device found", support_hint=False)


@click.group()
def storage():
    """(experimental) 'Nitrokey Storage' devices, see subcommands."""
    pass


@click.command()
def list():
    """list connected devices"""

    local_print(":: 'Nitrokey Storage' keys:")
    for dct in NitrokeyStorage.list_devices():
        local_print(dct)


@click.command()
def enable_update():
    """enable firmware update for NK Storage device

    If the Firmware Password is not in the environment variable NITROPY_FIRMWARE_PASSWORD, it will be prompted from stdin
    """
    password = AskUser(
        "Firmware Password", envvar="NITROPY_FIRMWARE_PASSWORD", hide_input=True
    ).ask()
    local_print("Enabling firmware update mode")
    nks = connect_nkstorage()
    if nks.enable_firmware_update(password) == 0:
        local_print("setting firmware update mode - success!")


@click.command()
def open_encrypted():
    """Unlock the encrypted volume

    If the User PIN is not in the environment variable NITROPY_USER_PIN, it will be prompted from stdin
    """
    password = AskUser("User PIN", envvar="NITROPY_USER_PIN", hide_input=True).ask()
    nks = connect_nkstorage()
    ret = nks.unlock_encrypted_volume(password)
    if not ret.ok:
        if ret == RetCode.WRONG_PASSWORD:
            raise CliException("Wrong user PIN", support_hint=False)
        else:
            raise CliException(
                "Unexpected error unlocking the encrypted volume {}".format(str(ret))
            )


@click.command()
def close_encrypted():
    """Lock the encrypted volume"""
    nks = connect_nkstorage()
    ret = nks.lock_encrypted_volume()
    if not ret.ok:
        raise CliException("Error closing the encrypted volume: {}".format(str(ret)))


@click.command()
def open_hidden():
    """Unlock an hidden volume

    If the hidden volume passphrase is not in the environment variable NITROPY_HIDDEN_PASSPHRASE, it will be prompted from stdin
    """
    password = AskUser(
        "Hidden volume passphrase", envvar="NITROPY_HIDDEN_PASSPHRASE", hide_input=True
    ).ask()
    nks = connect_nkstorage()
    ret = nks.unlock_hidden_volume(password)
    if not ret.ok:
        if ret == RetCode.WRONG_PASSWORD:
            raise CliException("Wrong hidden volume passphrase", support_hint=False)
        else:
            raise CliException(
                "Unexpected error unlocking the hidden volume: {}".format(str(ret))
            )


@click.command()
def close_hidden():
    """Lock the hidden volumes"""
    nks = connect_nkstorage()
    ret = nks.lock_hidden_volume()
    if not ret.ok:
        raise CliException("Error closing the hidden volume: {}".format(str(ret)))


@click.command()
@click.argument(
    "slot",
    type=int,
)
@click.argument(
    "begin",
    type=int,
)
@click.argument("end", type=int)
def create_hidden(slot, begin, end):
    """Create an hidden volume

    SLOT is the slot used for the hidden volume (1-4)\n
    START is where the volume begins expressed in percent of total available storage (0-99)\n
    END is where the volume ends expressed in percent of total available storage (1-100)\n
    If the hidden volume passphrase is not in the environment variable NITROPY_HIDDEN_PASSPHRASE, it will be prompted from stdin
    """
    if not slot in [1, 2, 3, 4]:
        raise CliException("Error: Slot must be between 1 and 4", support_hint=False)
    elif begin > 99 or begin < 0:
        raise CliException("Error: Begin must be between 0 and 99", support_hint=False)
    elif end < 1 or end > 100:
        raise CliException("Error: End must be between 1 and 100", support_hint=False)
    elif begin >= end:
        raise CliException(
            "Error: END must be strictly superior than START", support_hint=False
        )

    password = AskUser(
        "Hidden volume passphrase", envvar="NITROPY_HIDDEN_PASSPHRASE", hide_input=True
    ).ask()

    nks = connect_nkstorage()
    ret = nks.create_hidden_volume(slot - 1, begin, end, password)
    if not ret.ok:
        raise CliException("Error creating the hidden volume: {}".format(str(ret)))


storage.add_command(list)
storage.add_command(enable_update)
storage.add_command(open_encrypted)
storage.add_command(close_encrypted)
storage.add_command(open_hidden)
storage.add_command(close_hidden)
storage.add_command(create_hidden)
