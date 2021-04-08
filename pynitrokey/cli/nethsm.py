# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import contextlib
import datetime

import click

import pynitrokey.nethsm

DATETIME_TYPE = click.DateTime(formats=["%Y-%m-%dT%H:%M:%S%z"])


def print_row(values, widths):
    row = [value.ljust(width) for (value, width) in zip(values, widths)]
    print(*row, sep="\t")


def print_table(headers, data):
    widths = [len(header) for header in headers]
    for row in data:
        for i in range(len(widths)):
            row[i] = str(row[i])
            widths[i] = max(widths[i], len(row[i]))

    print_row(headers, widths)
    print_row(["-" * width for width in widths], widths)
    for row in data:
        print_row(row, widths)


@click.group()
@click.option(
    "-h", "--host", "host", required=True, help="Set the host of the NetHSM API"
)
@click.option(
    "-v",
    "--api-version",
    "version",
    default="v1",
    help="Set the version of the NetHSM API",
)
@click.option("-u", "--username", "username", help="The NetHSM user name")
@click.option("-p", "--password", "password", help="The NetHSM password")
@click.pass_context
def nethsm(ctx, host, version, username, password):
    """Interact with NetHSM, see subcommands."""
    ctx.ensure_object(dict)

    ctx.obj["NETHSM_HOST"] = host
    ctx.obj["NETHSM_VERSION"] = version
    ctx.obj["NETHSM_USERNAME"] = username
    ctx.obj["NETHSM_PASSWORD"] = password


@contextlib.contextmanager
def connect(ctx, require_auth=True):
    host = ctx.obj["NETHSM_HOST"]
    version = ctx.obj["NETHSM_VERSION"]
    username = None
    password = None
    if require_auth:
        username = ctx.obj["NETHSM_USERNAME"]
        password = ctx.obj["NETHSM_PASSWORD"]
        if not username:
            username = click.prompt(f"[auth] User name for NetHSM {host}")
        if not password:
            password = click.prompt(
                f"[auth] Password for user {username} on NetHSM {host}", hide_input=True
            )

    with pynitrokey.nethsm.connect(host, version, username, password) as nethsm:
        try:
            yield nethsm
        except pynitrokey.nethsm.NetHSMError as e:
            raise click.ClickException(e)


@nethsm.command()
@click.argument("passphrase", required=False)
@click.pass_context
def unlock(ctx, passphrase):
    """Bring a locked NetHSM into operational state."""
    with connect(ctx, require_auth=False) as nethsm:
        if not passphrase:
            passphrase = click.prompt(
                f"Unlock passphrase for NetHSM {nethsm.host}", hide_input=True
            )
        nethsm.unlock(passphrase)
        print(f"NetHSM {nethsm.host} unlocked")


@nethsm.command()
@click.pass_context
def lock(ctx):
    """Bring an operational NetHSM into locked state.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.lock()
        print(f"NetHSM {nethsm.host} locked")


@nethsm.command()
@click.option(
    "-u",
    "--unlock-passphrase",
    hide_input=True,
    confirmation_prompt=True,
    prompt=True,
    help="The unlock passphrase to set",
)
@click.option(
    "-a",
    "--admin-passphrase",
    hide_input=True,
    confirmation_prompt=True,
    prompt=True,
    help="The admin passphrase to set",
)
@click.option(
    "-t",
    "--system-time",
    type=DATETIME_TYPE,
    help="The system time to set (default: the time of this system)",
)
@click.pass_context
def provision(ctx, unlock_passphrase, admin_passphrase, system_time):
    """Initial provisioning of a NetHSM.

    If the unlock or admin passphrases are not set, they have to be entered
    interactively.  If the system time is not set, the current system time is
    used."""
    if not system_time:
        system_time = datetime.datetime.now()
    with connect(ctx, require_auth=False) as nethsm:
        nethsm.provision(unlock_passphrase, admin_passphrase, system_time)
        print(f"NetHSM {nethsm.host} provisioned")


@nethsm.command()
@click.option(
    "--details/--no-details",
    default=True,
    help="Also query the real name and role of the user",
)
@click.pass_context
def list_users(ctx, details):
    """List all users on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        user_ids = nethsm.list_users()

        print(f"Users on NetHSM {nethsm.host}:")
        print()

        headers = ["User ID"]
        if details:
            headers += ["Real name", "Role"]
            data = []
            for user_id in user_ids:
                user = nethsm.get_user(user_id=user_id.value)
                data.append([user_id, user.real_name, user.role.value])
        else:
            data = [[user_id] for user_id in user_ids]

        print_table(headers, data)


@nethsm.command()
@click.argument("user-id")
@click.pass_context
def get_user(ctx, user_id):
    """Query the real name and role for a user ID on the NetHSM.

    This command requires authentication as a user with the Administrator or
    Operator role."""
    with connect(ctx) as nethsm:
        user = nethsm.get_user(user_id=user_id)
        print(f"User {user_id} on NetHSM {nethsm.host}")
        print(f"Real name:  {user.real_name}")
        print(f"Role:       {user.role.value}")
