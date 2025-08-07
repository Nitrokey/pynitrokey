# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import csv
import io
import json
import sys
import typing
from base64 import b32decode
from typing import Any, Callable, List, Optional

import click
from nitrokey.nk3.secrets_app import (
    ALGORITHM_TO_KIND,
    STRING_TO_KIND,
    SecretsApp,
    SecretsAppException,
    SecretsAppExceptionID,
    SecretsAppHealthCheckException,
)

from pynitrokey.cli.nk3 import Context, nk3
from pynitrokey.helpers import AskUser, b32padding, local_critical, local_print


@nk3.group()
@click.pass_context
def secrets(ctx: click.Context) -> None:
    """Nitrokey Secrets App. Manage OTP and Password Safe secrets on the device.
    Use NITROPY_SECRETS_PASSWORD to pass password for the scripted execution."""
    pass


def repeat_if_pin_needed(func) -> Callable:  # type: ignore[no-untyped-def, type-arg]
    """
    Repeat the call of the decorated function, if PIN is required.
    Decorated function should have at least one argument,
    of which the first one should be an instance of the SecretsApp. Otherwise, a RuntimeError is raised.
    """

    def wrapper(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        assert len(args) >= 1 and isinstance(
            args[0], SecretsApp
        ), "repeat_if_pin_needed: SecretsApp should be passed as an argument to this decorator"
        app: SecretsApp = args[0]

        repeat_if_pin_needed.cached_PIN = getattr(  # type: ignore[attr-defined]
            repeat_if_pin_needed, "cached_PIN", None
        )
        try:
            if app.protocol_v2_confirm_all_requests_with_pin():
                repeat_if_pin_needed.cached_PIN = authenticate_if_needed(  # type: ignore[attr-defined]
                    app, repeat_if_pin_needed.cached_PIN  # type: ignore[attr-defined]
                )
            func(*args, **kwargs)
        except SecretsAppException as e:
            # Behavior below is for the v3 version of the protocol. Bail if v2 is used.
            if app.protocol_v2_confirm_all_requests_with_pin():
                raise

            if e.to_id() == SecretsAppExceptionID.SecurityStatusNotSatisfied:
                local_print("PIN is required to run this command.")
            elif e.to_id() == SecretsAppExceptionID.NotFound:
                if repeat_if_pin_needed.cached_PIN is None:  # type: ignore[attr-defined]
                    local_print(
                        "Credential not found. Please provide PIN below to search in the PIN-protected database."
                    )
            else:
                raise
            # Ask for PIN and retry
            repeat_if_pin_needed.cached_PIN = authenticate_if_needed(  # type: ignore[attr-defined]
                app, repeat_if_pin_needed.cached_PIN  # type: ignore[attr-defined]
            )
            func(*args, **kwargs)

    return wrapper


@secrets.command()
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
@click.argument(
    "new_name",
    type=click.STRING,
)
def rename(
    ctx: Context,
    name: str,
    new_name: str,
) -> None:
    """
    Rename credential.
    """
    with ctx.connect_device() as device:
        app = SecretsApp(device)
        ask_to_touch_if_needed()

        @repeat_if_pin_needed
        def call(app: SecretsApp) -> None:
            app.rename_credential(
                name.encode(),
                new_name.encode(),
            )

        call(app)
        local_print("Done")


@secrets.command()
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
@click.option(
    "--login",
    "login",
    type=click.STRING,
    help="Password Safe Login",
    default=None,
)
@click.option(
    "--password",
    "password",
    type=click.STRING,
    help="Password Safe Password",
    default=None,
)
@click.option(
    "--metadata",
    "metadata",
    type=click.STRING,
    help="Password Safe Metadata - additional field, to which extra information can be encoded",
    default=None,
)
@click.option(
    "--touch-button",
    "touch_button",
    type=click.BOOL,
    help="Activate/deactivate touch button requirement",
    default=None,
)
def update(
    ctx: Context,
    name: str,
    new_name: Optional[bytes] = None,
    login: Optional[bytes] = None,
    password: Optional[bytes] = None,
    metadata: Optional[bytes] = None,
    touch_button: Optional[bool] = None,
) -> None:
    """
    Update credential. Change Static Password fields, or touch button requirement attribute.
    """
    with ctx.connect_device() as device:
        app = SecretsApp(device)
        ask_to_touch_if_needed()

        @repeat_if_pin_needed
        def call(app: SecretsApp) -> None:
            app.update_credential(
                name.encode(),
                new_name=new_name,
                login=login,
                password=password,
                metadata=metadata,
                touch_button=touch_button,
            )

        call(app)
        local_print("Done")


# adapted from click.decorators
_AnyCallable = Callable[..., Any]


def with_options(
    *options: Callable[[_AnyCallable], _AnyCallable]
) -> Callable[[_AnyCallable], _AnyCallable]:
    # based on https://stackoverflow.com/a/67138197
    def decorator(f: _AnyCallable) -> _AnyCallable:
        for option in reversed(options):
            f = option(f)
        return f

    return decorator


add_otp_options = [
    click.argument(
        "name",
        type=click.STRING,
    ),
    click.argument(
        "secret",
        type=click.STRING,
    ),
    click.option(
        "--digits-str",
        "digits_str",
        type=click.Choice(["6", "8"]),
        help="Digits count",
        default="6",
    ),
    click.option(
        "--kind",
        "kind",
        type=click.Choice(choices=STRING_TO_KIND.keys(), case_sensitive=False),
        help="OTP mechanism to use. Case insensitive.",
        default="NOT_SET",
    ),
    click.option(
        "--hash",
        "hash",
        type=click.Choice(choices=ALGORITHM_TO_KIND.keys(), case_sensitive=False),
        help="Hash algorithm to use",
        default="SHA1",
    ),
    click.option(
        "--counter-start",
        "counter_start",
        type=click.INT,
        help="Starting value for the counter (HOTP only)",
        default=0,
    ),
    click.option(
        "--touch-button",
        "touch_button",
        type=click.BOOL,
        help="This credential requires button press before use",
        is_flag=True,
    ),
    click.option(
        "--protect-with-pin",
        "pin_protection",
        type=click.BOOL,
        help="This credential should be additionally encrypted with a PIN, which will be required before each use",
        is_flag=True,
    ),
]


@secrets.command(deprecated="Use 'add-otp' instead.")
@click.pass_obj
@with_options(*add_otp_options)
def register(
    ctx: Context,
    name: str,
    secret: str,
    digits_str: str,
    kind: str,
    hash: str,
    counter_start: int,
    touch_button: bool,
    pin_protection: bool,
) -> None:
    """Register OTP credential.

    Write credential under the NAME.
    Secret should be base32 encoded.
    """
    add_otp_impl(
        ctx,
        name,
        secret,
        digits_str,
        kind,
        hash,
        counter_start,
        touch_button,
        pin_protection,
    )


@secrets.command()
@click.pass_obj
@with_options(*add_otp_options)
def add_otp(
    ctx: Context,
    name: str,
    secret: str,
    digits_str: str,
    kind: str,
    hash: str,
    counter_start: int,
    touch_button: bool,
    pin_protection: bool,
) -> None:
    """Register OTP credential.

    Write credential under the NAME.
    Secret should be base32 encoded.
    """
    add_otp_impl(
        ctx,
        name,
        secret,
        digits_str,
        kind,
        hash,
        counter_start,
        touch_button,
        pin_protection,
    )


def add_otp_impl(
    ctx: Context,
    name: str,
    secret: str,
    digits_str: str,
    kind: str,
    hash: str,
    counter_start: int,
    touch_button: bool,
    pin_protection: bool,
) -> None:
    otp_kind = STRING_TO_KIND[kind.upper()]
    if not secret:
        raise click.ClickException("Please provide secret for the OTP to work")

    digits = int(digits_str)
    secret_bytes = b32decode(b32padding(secret), casefold=True)
    hash_algorithm = ALGORITHM_TO_KIND[hash.upper()]

    with ctx.connect_device() as device:
        app = SecretsApp(device)
        ask_to_touch_if_needed()

        @repeat_if_pin_needed
        def call(app: SecretsApp) -> None:
            app.register(
                name.encode(),
                secret_bytes,
                digits,
                kind=otp_kind,
                algo=hash_algorithm,
                initial_counter_value=counter_start,
                touch_button_required=touch_button,
                pin_based_encryption=pin_protection,
            )

        call(app)
        local_print("Done")


@secrets.command
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
@click.option(
    "--touch-button",
    "touch_button",
    type=click.BOOL,
    help="This credential requires button press before use",
    is_flag=True,
)
@click.option(
    "--protect-with-pin",
    "pin_protection",
    type=click.BOOL,
    help="This credential should be additionally encrypted with a PIN, which will be required before each use",
    is_flag=True,
)
@click.option(
    "--login",
    "login",
    type=click.STRING,
    help="Password Safe Login",
    default=None,
)
@click.option(
    "--password",
    "password",
    type=click.STRING,
    help="Password Safe Password",
    default=None,
)
@click.option(
    "--metadata",
    "metadata",
    type=click.STRING,
    help="Password Safe Metadata - additional field, to which extra information can be encoded",
    default=None,
)
def add_password(
    ctx: Context,
    name: str,
    touch_button: bool,
    pin_protection: bool,
    login: Optional[bytes] = None,
    password: Optional[bytes] = None,
    metadata: Optional[bytes] = None,
) -> None:
    """Register Password Safe credential.

    Write credential under the NAME.

    """

    with ctx.connect_device() as device:
        app = SecretsApp(device)
        abort_if_not_supported(app.feature_pws_support(), "Password Safe")
        ask_to_touch_if_needed()

        @repeat_if_pin_needed
        def call(app: SecretsApp) -> None:
            app.register(
                name.encode(),
                touch_button_required=touch_button,
                pin_based_encryption=pin_protection,
                login=login,
                password=password,
                metadata=metadata,
            )

        call(app)
        local_print("Done")


@secrets.command
@click.pass_obj
@click.argument(
    "slot",
    type=click.Choice(["1", "2"]),
)
@click.argument(
    "secret",
    type=click.STRING,
)
def add_challenge_response(ctx: Context, slot: str, secret: str) -> None:
    """Register Challenge-Response credential."""

    secret_bytes = b32decode(b32padding(secret), casefold=True)
    sl = len(secret_bytes)
    if sl != 20:
        local_critical(f"Secret has to be exactly 20 bytes in length (got {sl})")

    with ctx.connect_device() as device:
        app = SecretsApp(device)
        abort_if_not_supported(app.feature_pws_support(), "Password Safe")
        ask_to_touch_if_needed()

        @repeat_if_pin_needed
        def call(app: SecretsApp) -> None:
            app.register_yk_hmac(int(slot), secret_bytes)

        call(app)
        local_print("Done")


def abort_if_not_supported(cond: bool, name: str = "") -> None:
    if not cond:
        message = (
            f'Feature unsupported by this firmware version{f": {name}" if name else ""}'
        )
        local_print(message)
        raise click.Abort()


def ask_to_touch_if_needed() -> None:
    """Helper function to show common request for the touch if device signalizes it"""
    local_print("Please touch the device if it blinks", file=sys.stderr)


@secrets.command()
@click.pass_obj
@click.option(
    "--hexa",
    "hexa",
    type=click.BOOL,
    help="Use hex representation",
    default=False,
    is_flag=True,
)
def list(ctx: Context, hexa: bool) -> None:
    """List registered OTP credentials."""
    with ctx.connect_device() as device:
        app = SecretsApp(device)
        if app.is_pin_healthy():
            local_print(
                "Please provide PIN to show PIN-protected entries (if any), or press ENTER to skip"
            )
            try:
                ask_to_touch_if_needed()
                authenticate_if_needed(app)
            except click.Abort:
                pass

        credentials_list = sorted(app.list_with_properties(), key=lambda x: x.label)
        for i, credential in enumerate(credentials_list):
            local_print(f"{i+1:02}. {credential}")
        if len(credentials_list) == 0:
            local_print("No credentials found")


@secrets.command()
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
def remove(ctx: Context, name: str) -> None:
    """Remove OTP credential."""
    with ctx.connect_device() as device:
        app = SecretsApp(device)
        ask_to_touch_if_needed()

        @repeat_if_pin_needed
        def call(app: SecretsApp) -> None:
            app.delete(name.encode())

        call(app)
        local_print("Done")


@secrets.command()
@click.pass_obj
@click.option(
    "--force",
    is_flag=True,
    help="Do not ask for confirmation",
)
def reset(ctx: Context, force: bool) -> None:
    """Remove all OTP credentials from the device."""
    confirmed = force or click.confirm("Do you want to continue?")
    if not confirmed:
        raise click.Abort()
    with ctx.connect_device() as device:
        app = SecretsApp(device)
        ask_to_touch_if_needed()
        app.reset()
        local_print("Done")


get_otp_options = [
    click.argument(
        "name",
        type=click.STRING,
    ),
    click.option(
        "--timestamp",
        "timestamp",
        type=click.INT,
        help="The timestamp to use instead of the local time (TOTP only)",
        default=0,
    ),
    click.option(
        "--period",
        "period",
        type=click.INT,
        help="The period to use in seconds (TOTP only)",
        default=30,
    ),
]


@secrets.command(deprecated="Use 'get-otp' instead.")
@click.pass_obj
@with_options(*get_otp_options)
def get(
    ctx: Context,
    name: str,
    timestamp: int,
    period: int,
) -> None:
    """Generate OTP code from registered credential."""
    get_otp_impl(ctx, name, timestamp, period)


@secrets.command()
@click.pass_obj
@with_options(*get_otp_options)
def get_otp(
    ctx: Context,
    name: str,
    timestamp: int,
    period: int,
) -> None:
    """Generate OTP code from registered credential."""
    get_otp_impl(ctx, name, timestamp, period)


def get_otp_impl(
    ctx: Context,
    name: str,
    timestamp: int,
    period: int,
) -> None:
    # TODO: for TOTP get the time from a timeserver via NTP, instead of the local clock

    from datetime import datetime

    timestamp = timestamp if timestamp else int(datetime.timestamp(datetime.now()))
    with ctx.connect_device() as device:
        app = SecretsApp(device)
        ask_to_touch_if_needed()

        @repeat_if_pin_needed
        def call(app: SecretsApp) -> None:
            code = app.calculate(name.encode(), timestamp // period)
            local_print(
                f"Timestamp: {datetime.isoformat(datetime.fromtimestamp(timestamp), timespec='seconds')} ({timestamp}), period: {period}",
                file=sys.stderr,
            )
            local_print(code.decode())

        try:
            call(app)
        except SecretsAppException as e:
            local_critical(
                f"Device returns error: {e}. \n"
                f"This credential id might not be registered, or its not allowed to be used here.",
                support_hint=False,
            )


@secrets.command()
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
@click.option(
    "--password",
    is_flag=True,
    help="Print password only",
)
@click.option(
    "--format",
    type=click.Choice(["json", "csv"]),
    help="Format of the output",
)
def get_password(
    ctx: Context,
    name: str,
    password: bool,
    format: str,
) -> None:
    """Get Password Safe Entry"""
    with ctx.connect_device() as device:
        app = SecretsApp(device)
        abort_if_not_supported(app.feature_pws_support(), "Password Safe")
        ask_to_touch_if_needed()

        def decode_if_bytes(x: typing.Union[bytes, str], on_empty: str = "") -> str:
            if not x:
                return on_empty
            if isinstance(x, bytes):
                return x.decode()
            elif isinstance(x, str):
                return x
            raise ValueError("Invalid type")

        @repeat_if_pin_needed
        def call(app: SecretsApp) -> None:
            cred = app.get_credential(name.encode())
            data = {k: decode_if_bytes(v) for k, v in cred.__dict__.items()}
            if password:
                if cred.password:
                    local_print(decode_if_bytes(cred.password))
            elif format == "json":
                js = json.dumps(data)
                local_print(js)
            elif format == "csv":
                si = io.StringIO()
                writer = csv.DictWriter(si, fieldnames=data)
                writer.writeheader()
                writer.writerow(data)
                local_print(si.getvalue().strip())
            else:
                for f, v in data.items():
                    # f: str
                    # v: bytes
                    local_print(f"{f:20}: {decode_if_bytes(v, '---')}")

        try:
            call(app)

        except SecretsAppException as e:
            local_print(
                f"Device returns error: {e}. \n"
                f"This credential id might not be registered, or its not allowed to be used here."
            )


@secrets.command()
@click.pass_obj
@click.argument(
    "name",
    type=click.STRING,
)
@click.argument(
    "code",
    type=click.INT,
)
def verify(ctx: Context, name: str, code: int) -> None:
    """Proceed with the incoming OTP code verification (aka reverse HOTP).
    Use the "register" command to create the credential for this action.
    """
    with ctx.connect_device() as device:
        app = SecretsApp(device)
        ask_to_touch_if_needed()

        @repeat_if_pin_needed
        def call(app: SecretsApp) -> None:
            app.verify_code(name.encode(), code)

        try:
            call(app)
        except SecretsAppException as e:
            local_print(
                f"Device returns error: {e}. \n"
                f"This credential id might not be registered, is of wrong type, or the provided HOTP code has not passed verification."
            )


def ask_for_passphrase_if_needed(app: SecretsApp) -> Optional[str]:
    health_check = helper_secrets_app_health_check(app)
    if health_check:
        local_print(*health_check)
    if not app.is_pin_healthy():
        raise SecretsAppHealthCheckException("PIN not available to use")
    passphrase = AskUser(
        f"Current PIN ({app.select().pin_attempt_counter} attempts left)",
        envvar="NITROPY_SECRETS_PASSWORD",
        hide_input=True,
    ).ask()
    return passphrase


def authenticate_if_needed(
    app: SecretsApp, passphrase: Optional[str] = None
) -> Optional[str]:
    try:
        passphrase = (
            ask_for_passphrase_if_needed(app) if passphrase is None else passphrase
        )
        if passphrase:
            ask_to_touch_if_needed()
            app.verify_pin_raw(passphrase)
        else:
            local_print("No PIN provided")
    except SecretsAppHealthCheckException:
        raise click.Abort()
    except Exception as e:
        local_print(
            f'Authentication failed with error: "{e}" \n'
            "Please make sure the provided PIN is correct."
        )
        raise click.Abort()
    return passphrase


@secrets.command()
@click.pass_obj
@click.password_option()
def set_pin(ctx: Context, password: str) -> None:
    """Set or change the PIN used to authenticate to other commands."""
    new_password = password

    with ctx.connect_device() as device:
        try:
            app = SecretsApp(device)
            ask_to_touch_if_needed()

            if app.select().pin_attempt_counter is None:
                app.set_pin_raw(new_password)
                local_print("Password set")
                return

            current_password = ask_for_passphrase_if_needed(app)
            if current_password is None:
                raise click.Abort()
            app.change_pin_raw(current_password, new_password)
            local_print("Password changed")
        except SecretsAppException as e:
            local_print(
                f"Device returns error: {e}. \n" f"The new or current PIN is invalid."
            )


@secrets.command()
@click.pass_obj
def status(ctx: Context) -> None:
    """Show application status"""
    with ctx.connect_device() as device:
        app = SecretsApp(device)
        r = app.select()
        local_print(f"{r}")
        local_print(*helper_secrets_app_health_check(app))


def helper_secrets_app_health_check(app: SecretsApp) -> List[str]:
    messages = []
    r = app.select()
    if r.pin_attempt_counter is None:
        messages.append(
            "- Application does not have a PIN. Set PIN before the first use."
        )
    if r.pin_attempt_counter == 0:
        messages.append(
            "- All attempts on the PIN counter are used. Call factory reset to use the PIN feature of the secrets application again."
        )
    if (
        app.feature_challenge_response_support()
        or app.feature_old_application_version()
    ):
        messages.append("- This application version is outdated.")

    if messages:
        messages.insert(0, "Health check notes:")
    return messages
