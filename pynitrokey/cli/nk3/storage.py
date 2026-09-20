# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import os
import sys
from typing import TYPE_CHECKING

import click
from nitrokey.trussed.storage_app import StorageApp, StorageError, StorageException

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import local_print, prompt

if TYPE_CHECKING:
    from . import Context


PIN_RETRIES = 3
MIN_PIN_LENGTH = 6
MAX_PIN_LENGTH = 128
ENV_VAR_PIN = "NITROPY_STORAGE_PIN"
ENV_VAR_NEW_PIN = "NITROPY_STORAGE_NEW_PIN"


def _query_pin(name: str, *, env: bool, env_var: str, confirm: bool = False) -> bytes:
    if env:
        value = os.environ.get(env_var)
        if value is None:
            raise CliException(
                f"Failed to read {name} from environment variable {env_var}.", support_hint=False
            )
        local_print(f"Read value for {name} from environment variable {env_var}.")
    else:
        value = prompt(f"Please enter the {name}", hide_input=True, confirmation_prompt=confirm)
        assert value is not None

    encoded = value.encode()
    if len(encoded) < MIN_PIN_LENGTH:
        raise CliException(
            f"The provided PIN is too short (minimum length: {MIN_PIN_LENGTH})", support_hint=False
        )
    if len(encoded) > MAX_PIN_LENGTH:
        raise CliException(
            f"The provided PIN is too long (maximum length: {MAX_PIN_LENGTH})", support_hint=False
        )

    return encoded


def _require_pin_available(app: StorageApp) -> None:
    status = app.status()
    if not status.pin_set:
        raise CliException("The Storage PIN is not set.", support_hint=False)
    if status.pin_retries == 0:
        raise CliException(
            "The PIN retries have been exceeded and the PIN is now blocked.", support_hint=False
        )
    if status.pin_retries < PIN_RETRIES:
        local_print(f"Warning: Only {status.pin_retries} PIN retries remaining.", file=sys.stderr)


def _handle_pin_exception(operation: str, exception: StorageException) -> Exception:
    msg = None
    if exception.error == StorageError.PIN_TOO_SHORT:
        msg = "PIN too short"
    elif exception.error == StorageError.PIN_TOO_LONG:
        msg = "PIN too long"
    elif exception.error == StorageError.INVALID_PIN:
        msg = "Invalid PIN"
    elif exception.error == StorageError.PIN_BLOCKED:
        msg = "PIN blocked (no retries left)"

    if msg is not None:
        return CliException(f"{operation} failed: {msg}", support_hint=False)
    else:
        return exception


@click.group()
@click.pass_context
def storage(ctx: click.Context) -> None:
    pass


@storage.command()
@click.pass_obj
def status(ctx: "Context") -> None:
    with ctx.connect_device() as device:
        app = StorageApp(device)
        status = app.status()
        print("Storage status:")
        print(f"  unlocked:     {status.unlocked}")
        print(f"  PIN set:      {status.pin_set}")
        print(f"  PIN retries:  {status.pin_retries}")


@storage.command()
@click.option(
    "--env",
    is_flag=True,
    help=f"Read the Storage PIN from the {ENV_VAR_PIN} environment variable instead of an "
    "interactive prompt",
)
@click.pass_obj
def unlock(ctx: "Context", env: bool) -> None:
    with ctx.connect_device() as device:
        app = StorageApp(device)
        _require_pin_available(app)

        pin = _query_pin("Storage PIN", env=env, env_var=ENV_VAR_PIN)
        try:
            app.unlock(pin)
        except StorageException as e:
            raise _handle_pin_exception("Authentication", e)
        local_print("Storage unlocked")


@storage.command()
@click.pass_obj
def lock(ctx: "Context") -> None:
    with ctx.connect_device() as device:
        app = StorageApp(device)
        app.lock()
        local_print("Storage locked")


@storage.command()
@click.option(
    "--env",
    is_flag=True,
    help=f"Read the new Storage PIN from the {ENV_VAR_PIN} environment variable instead of an "
    "interactive prompt",
)
@click.pass_obj
def set_pin(ctx: "Context", env: bool) -> None:
    with ctx.connect_device() as device:
        app = StorageApp(device)
        status = app.status()
        if status.pin_set:
            raise CliException("The Storage PIN is already set.", support_hint=False)

        pin = _query_pin("new Storage PIN", env=env, env_var=ENV_VAR_PIN, confirm=True)
        try:
            app.set_pin(pin)
        except StorageException as e:
            raise _handle_pin_exception("Setting the PIN", e)
        local_print("Storage PIN set successfully")


@storage.command()
@click.option(
    "--env",
    is_flag=True,
    help=f"Read the current Storage PIN from the {ENV_VAR_PIN} and the new Storage PIN from the "
    f"{ENV_VAR_NEW_PIN} environment variable instead of an interactive prompt",
)
@click.pass_obj
def change_pin(ctx: "Context", env: bool) -> None:
    with ctx.connect_device() as device:
        app = StorageApp(device)
        _require_pin_available(app)

        old_pin = _query_pin("current Storage PIN", env=env, env_var=ENV_VAR_PIN)
        new_pin = _query_pin("new Storage PIN", env=env, env_var=ENV_VAR_NEW_PIN, confirm=True)
        try:
            app.change_pin(old_pin, new_pin)
        except StorageException as e:
            raise _handle_pin_exception("Authentication", e)

        local_print("Storage PIN changed successfully")
