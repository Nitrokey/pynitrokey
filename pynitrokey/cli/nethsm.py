# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import base64
import contextlib
import datetime
import json
import logging
import mimetypes
import os
import os.path
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Iterator, Optional, Protocol, Sequence

import click
import nethsm as nethsm_sdk
from click import Context
from nethsm import Authentication, Base64, NetHSM, State
from nethsm.backup import EncryptedBackup

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import prompt


class EnumMeta(Protocol):
    def __iter__(self) -> Iterator[Enum]: ...


def make_enum_type(enum_cls: EnumMeta) -> click.Choice[Enum]:
    return click.Choice([variant.value for variant in enum_cls], case_sensitive=False)


def base64_input(s: str) -> Base64:
    return Base64.from_encoded(s, ignore_whitespace=True)


DATETIME_TYPE = click.DateTime(formats=["%Y-%m-%dT%H:%M:%S%z"])
ROLE_TYPE = make_enum_type(nethsm_sdk.Role)
LOG_LEVEL_TYPE = make_enum_type(nethsm_sdk.LogLevel)
UNATTENDED_BOOT_STATUS_TYPE = make_enum_type(nethsm_sdk.UnattendedBootStatus)
TYPE_TYPE = make_enum_type(nethsm_sdk.KeyType)
TYPE_TLS_KEY_TYPE = make_enum_type(nethsm_sdk.TlsKeyType)
MECHANISM_TYPE = make_enum_type(nethsm_sdk.KeyMechanism)
ENCRYPT_MODE_TYPE = make_enum_type(nethsm_sdk.EncryptMode)
DECRYPT_MODE_TYPE = make_enum_type(nethsm_sdk.DecryptMode)
SIGN_MODE_TYPE = make_enum_type(nethsm_sdk.SignMode)


def prompt_str(
    msg: str, default: Optional[str] = None, hide_input: bool = False
) -> str:
    value = prompt(msg, default=default, hide_input=hide_input)
    assert isinstance(value, str)
    return value


def print_row(values: Iterable[str], widths: Iterable[int]) -> None:
    row = [value.ljust(width) for (value, width) in zip(values, widths)]
    print(*row, sep="\t")


def print_table(headers: Sequence[str], data: Iterable[Sequence[Any]]) -> None:
    widths = [len(header) for header in headers]
    str_data = []
    for row in data:
        str_row = []
        for i in range(len(widths)):
            str_value = str(row[i])
            str_row.append(str_value)
            widths[i] = max(widths[i], len(str_value))
        str_data.append(str_row)

    print_row(headers, widths)
    print_row(["-" * width for width in widths], widths)
    for row in str_data:
        print_row(row, widths)


@dataclass
class Config:
    host: Optional[str]
    username: Optional[str]
    password: Optional[str]
    verify_tls: bool
    ca_certs: Optional[str]
    debug: bool


@click.group()
@click.option("-h", "--host", "host", help="Set the host of the NetHSM API")
@click.option("-u", "--username", "username", help="The NetHSM user name")
@click.option("-p", "--password", "password", help="The NetHSM password")
@click.option(
    "--verify-tls/--no-verify-tls",
    default=True,
    help="Whether to verify the TLS certificate of the NetHSM",
)
@click.option(
    "--ca-certs",
    help="Path to the CA certs to use for the TLS verification",
)
@click.option("--debug", is_flag=True, help="Enable debug log messages")
@click.pass_context
def nethsm(
    ctx: Context,
    host: Optional[str],
    username: Optional[str],
    password: Optional[str],
    verify_tls: bool,
    ca_certs: Optional[str],
    debug: bool,
) -> None:
    """Interact with NetHSM devices, see subcommands."""

    ctx.obj = Config(
        host=host,
        username=username,
        password=password,
        verify_tls=verify_tls,
        ca_certs=ca_certs,
        debug=debug,
    )


@contextlib.contextmanager
def connect(ctx: Context, require_auth: bool = True) -> Iterator[NetHSM]:
    config = ctx.obj
    assert isinstance(config, Config)

    host = config.host
    if host is None:
        v = "NETHSM_HOST"
        if v not in os.environ:
            raise CliException(
                "Missing NetHSM host: set the --host option or the "
                f"{v} environment variable",
                support_hint=False,
            )
        host = os.environ[v]

    auth = None
    if require_auth:
        username = config.username
        password = config.password
        if not username:
            username = prompt_str(f"[auth] User name for NetHSM {host}")
        if not password:
            password = prompt_str(
                f"[auth] Password for user {username} on NetHSM {host}",
                hide_input=True,
            )
        auth = Authentication(username=username, password=password)

    nethsm = NetHSM(
        host, auth=auth, verify_tls=config.verify_tls, ca_certs=config.ca_certs
    )
    if config.debug:
        loggers = ["nethsm.client", "urllib3"]
        for logger in loggers:
            logging.getLogger(logger).setLevel(logging.DEBUG)
    try:
        yield nethsm
    except nethsm_sdk.NetHSMError as e:
        raise click.ClickException(f"NetHSM request failed: {e}")
    except nethsm_sdk.NetHSMRequestError as e:
        if e.type == nethsm_sdk.RequestErrorType.SSL_ERROR:
            raise click.ClickException(
                f"Could not connect to the NetHSM: {e.reason}\nIf you use a self-signed certificate, please set the --no-verify-tls option."
            )
        else:
            raise click.ClickException(
                f"Cound not connect to the NetHSM: {e.reason}\nIs the NetHSM running and reachable?"
            )
    finally:
        nethsm.close()


@nethsm.command()
@click.argument("passphrase", required=False)
@click.pass_context
def unlock(ctx: Context, passphrase: Optional[str]) -> None:
    """Bring a locked NetHSM into operational state."""
    with connect(ctx, require_auth=False) as nethsm:
        if not passphrase:
            passphrase = prompt_str(
                f"Unlock passphrase for NetHSM {nethsm.host}", hide_input=True
            )
        nethsm.unlock(passphrase)
        print(f"NetHSM {nethsm.host} unlocked")


@nethsm.command()
@click.pass_context
def lock(ctx: Context) -> None:
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
def provision(
    ctx: Context,
    unlock_passphrase: str,
    admin_passphrase: str,
    system_time: Optional[datetime.datetime],
) -> None:
    """Initial provisioning of a NetHSM.

    If the unlock or admin passphrases are not set, they have to be entered
    interactively.  If the system time is not set, the current system time is
    used."""
    if not system_time:
        system_time = datetime.datetime.now(datetime.timezone.utc)

    print(
        "Warning: The unlock passphrase cannot be reset without knowing the current value. If the "
        "unlock passphrase is lost, neither can it be reset to a new value nor can the NetHSM be "
        "unlocked.",
        file=sys.stderr,
    )

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
def list_users(ctx: Context, details: bool) -> None:
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
                user = nethsm.get_user(user_id=user_id)
                data.append([user_id, user.real_name, user.role.value])
        else:
            data = [[user_id] for user_id in user_ids]

        print_table(headers, data)


@nethsm.command()
@click.argument("user-id")
@click.pass_context
def get_user(ctx: Context, user_id: str) -> None:
    """Query the real name and role for a user ID on the NetHSM.

    This command requires authentication as a user with the Administrator or
    Operator role."""
    with connect(ctx) as nethsm:
        user = nethsm.get_user(user_id=user_id)
        print(f"User {user_id} on NetHSM {nethsm.host}")
        print(f"Real name:  {user.real_name}")
        print(f"Role:       {user.role.value}")


@nethsm.command()
@click.option("-n", "--real-name", prompt=True, help="The real name of the new user")
@click.option(
    "-r", "--role", type=ROLE_TYPE, prompt=True, help="The role of the new user"
)
@click.option(
    "-p",
    "--passphrase",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="The passphrase of the new user",
)
@click.option("-u", "--user-id", help="The user ID of the new user")
@click.option("-N", "--namespace", help="The namespace of the new user")
@click.option(
    "--create-namespace",
    is_flag=True,
    help="Create the namespace after adding the user",
)
@click.pass_context
def add_user(
    ctx: Context,
    real_name: str,
    role: str,
    passphrase: str,
    user_id: Optional[str],
    namespace: Optional[str],
    create_namespace: bool,
) -> None:
    """Create a new user on the NetHSM.

    If the real name, role or passphrase are not specified, they have to be
    specified interactively.  If the user ID is not set, it is generated by the
    NetHSM.

    If a namespace is specified, the user will be created within the namespace.
    This means that the resulting user name will follow the pattern
    namespace~userid, i. e. the same user ID can be used in different
    namespaces.

    If the --create-namespace option is set and a namespace is specified, the
    namespace will be created after the user has been added.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        user_id = nethsm.add_user(
            real_name, nethsm_sdk.Role.from_string(role), passphrase, user_id, namespace
        )
        print(f"User {user_id} added to NetHSM {nethsm.host}")

        if namespace and nethsm.auth is not None and "~" not in nethsm.auth.username:
            # user added to non-existing namespace
            if create_namespace:
                nethsm.add_namespace(namespace)
                print(f"Namespace {namespace} added to NetHSM {nethsm.host}")
            else:
                print(
                    f"Warning: The namespace {namespace} does not exist.  Add it to the NetHSM with ",
                    file=sys.stderr,
                )
                print(f"    nitropy nethsm add-namespace {namespace}", file=sys.stderr)
                print(
                    "to be able to use it.  Once the namespace has been added, it can only be managed "
                    "by users in the same namespace.",
                    file=sys.stderr,
                )


@nethsm.command()
@click.argument("user-id")
@click.pass_context
def delete_user(ctx: Context, user_id: str) -> None:
    """Delete the user with the given user ID on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.delete_user(user_id)
        print(f"User {user_id} deleted on NetHSM {nethsm.host}")


@nethsm.command()
@click.pass_context
def list_namespaces(ctx: Context) -> None:
    """List all namespaces on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        namespaces = nethsm.list_namespaces()

        print(f"Namespaces on NetHSM {nethsm.host}:")
        for namespace in namespaces:
            print(f"- {namespace}")


@nethsm.command()
@click.argument("namespace")
@click.pass_context
def add_namespace(ctx: Context, namespace: str) -> None:
    """Add a new namespace on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.add_namespace(namespace)
        print(f"Namespace {namespace} added to NetHSM {nethsm.host}")


@nethsm.command()
@click.argument("namespace")
@click.pass_context
def delete_namespace(ctx: Context, namespace: str) -> None:
    """Delete a namespace on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.delete_namespace(namespace)
        print(f"Namespace {namespace} deleted on NetHSM {nethsm.host}")


@nethsm.command()
@click.option("-u", "--user-id", help="The user ID of the user")
@click.option(
    "-p",
    "--passphrase",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="The new passphrase of the user",
)
@click.pass_context
def set_passphrase(ctx: Context, user_id: Optional[str], passphrase: str) -> None:
    """Set the passphrase for the user with the given ID (or the current user).

    This command requires authentication as a user with the Administrator or
    Operator role.  Users with the Operator role can only change their own
    passphrase."""
    with connect(ctx) as nethsm:
        if not user_id:
            assert nethsm.auth is not None
            user_id = nethsm.auth.username
        nethsm.set_passphrase(user_id, passphrase)
        print(f"Updated the passphrase for user {user_id} on NetHSM {nethsm.host}")


@nethsm.command()
@click.argument("user-id")
@click.pass_context
def list_operator_tags(ctx: Context, user_id: str) -> None:
    """List the tags for an operator user ID on the NetHSM.

    This command requires authentication as a user with the Administrator role."""
    with connect(ctx) as nethsm:
        tags = nethsm.list_operator_tags(user_id=user_id)
        if tags:
            print(f"Tags for user {user_id}:")
            for tag in tags:
                print(f"- {tag}")
        else:
            print(f"No tags set for user {user_id}.")


@nethsm.command()
@click.argument("user-id")
@click.argument("tag")
@click.pass_context
def add_operator_tag(ctx: Context, user_id: str, tag: str) -> None:
    """Add a tag for an operator user on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.add_operator_tag(user_id=user_id, tag=tag)
        print(f"Added tag {tag} for user {user_id} on the NetHSM {nethsm.host}")


@nethsm.command()
@click.argument("user-id")
@click.argument("tag")
@click.pass_context
def delete_operator_tag(ctx: Context, user_id: str, tag: str) -> None:
    """Delete a tag for an operator user on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.delete_operator_tag(user_id=user_id, tag=tag)
        print(f"Deleted tag {tag} for user {user_id} on the NetHSM {nethsm.host}")


@nethsm.command()
@click.argument("key_id")
@click.argument("tag")
@click.pass_context
def add_key_tag(ctx: Context, key_id: str, tag: str) -> None:
    """Add a tag for a key on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.add_key_tag(key_id=key_id, tag=tag)
        print(f"Added tag {tag} for key {key_id} on the NetHSM {nethsm.host}")


@nethsm.command()
@click.argument("key_id")
@click.argument("tag")
@click.pass_context
def delete_key_tag(ctx: Context, key_id: str, tag: str) -> None:
    """Delete a tag for a key on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.delete_key_tag(key_id=key_id, tag=tag)
        print(f"Deleted tag {tag} for key {key_id} on the NetHSM {nethsm.host}")


@nethsm.command()
@click.pass_context
def info(ctx: Context) -> None:
    """Query the vendor and product information for a NetHSM."""
    with connect(ctx, require_auth=False) as nethsm:
        info = nethsm.get_info()
        print(f"Host:    {nethsm.host}")
        print(f"Vendor:  {info.vendor}")
        print(f"Product: {info.product}")


@nethsm.command()
@click.pass_context
def state(ctx: Context) -> None:
    """Query the state of a NetHSM."""
    with connect(ctx, require_auth=False) as nethsm:
        state = nethsm.get_state()
        print(f"NetHSM {nethsm.host} is {state.value}")


@nethsm.command()
@click.argument("length", type=int)
@click.pass_context
def random(ctx: Context, length: int) -> None:
    """Retrieve random bytes from the NetHSM as a Base64 string.

    This command requires authentication as a user with the Operator role."""
    with connect(ctx) as nethsm:
        print(nethsm.get_random_data(length))


@nethsm.command()
@click.pass_context
def metrics(ctx: Context) -> None:
    """Query the metrics of a NetHSM.

    This command requires authentication as a user with the Metrics role."""
    with connect(ctx) as nethsm:
        headers = ["Metric", "Value"]
        data = nethsm.get_metrics()
        print_table(headers, [list(row) for row in sorted(data.items())])


@nethsm.command()
@click.option(
    "--details/--no-details",
    default=True,
    help="Also query the key data",
)
@click.option(
    "-f",
    "--filter",
    type=str,
    help="Filter keys by tags for respective user",
)
@click.option("-p", "--prefix", type=str, help="Only list keys with the given prefix")
@click.pass_context
def list_keys(
    ctx: Context, details: bool, filter: Optional[str], prefix: Optional[str]
) -> None:
    """List all keys on the NetHSM.

    This command requires authentication as a user with the Administrator or
    Operator role."""
    with connect(ctx) as nethsm:
        key_ids = nethsm.list_keys(filter, prefix=prefix)

        print(f"Keys on NetHSM {nethsm.host}:")
        print()

        headers = ["Key ID"]
        if details:
            headers += ["Type", "Mechanisms", "Operations", "Tags"]
            data = []
            for key_id in key_ids:
                key = nethsm.get_key(key_id=key_id)
                data.append(
                    [
                        key_id,
                        key.type.value,
                        ", ".join([m.value for m in key.mechanisms]),
                        key.operations,
                        ", ".join(key.tags) if key.tags is not None else "",
                    ]
                )
        else:
            data = [[key_id] for key_id in key_ids]

        print_table(headers, data)


@nethsm.command()
@click.argument("key_id")
@click.option("--public-key", is_flag=True, help="Query the public key as a PEM file")
@click.pass_context
def get_key(ctx: Context, key_id: str, public_key: bool) -> None:
    """Get information about a key on the NetHSM.

    This command requires authentication as a user with the Administrator or
    Operator role."""
    with connect(ctx) as nethsm:
        if public_key:
            print(nethsm.get_key_public_key(key_id))
        else:
            key = nethsm.get_key(key_id)
            mechanisms = ", ".join([str(m.value) for m in key.mechanisms])
            print(f"Key {key_id} on NetHSM {nethsm.host}:")
            print(f"Type:            {key.type.value}")
            print(f"Mechanisms:      {mechanisms}")
            print(f"Operations:      {key.operations}")
            if key.tags:
                tags = ", ".join(key.tags)
                print(f"Tags:            {tags}")

            if isinstance(key.public_key, nethsm_sdk.RsaPublicKey):
                print(f"Modulus:         {key.public_key.modulus}")
                print(f"Public exponent: {key.public_key.public_exponent}")
            elif isinstance(key.public_key, nethsm_sdk.EcPublicKey):
                print(f"Data:            {key.public_key.data}")
            elif key.public_key is not None:
                print(f"Public key:      {key.public_key}")


@nethsm.command()
@click.argument("old-key-id")
@click.argument("new-key-id")
@click.pass_context
def move_key(ctx: Context, old_key_id: str, new_key_id: str) -> None:
    """Move the key pair with the given old key ID to the new key ID (requires NetHSM v3).

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.move_key(old_key_id, new_key_id)
        print(f"Key {old_key_id} moved to {new_key_id} on NetHSM {nethsm.host}")


@nethsm.command()
@click.argument("key-id")
@click.pass_context
def delete_key(ctx: Context, key_id: str) -> None:
    """Delete the key pair with the given key ID on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.delete_key(key_id)
        print(f"Key {key_id} deleted on NetHSM {nethsm.host}")


def prompt_mechanisms(type: str) -> list[str]:
    # We assume that key type X corresponds to the mechanisms starting with X.
    # This is no longer true for curves, so we have to adapt the type
    if type == nethsm_sdk.KeyType.CURVE25519.value:
        type = "EdDSA"
    elif type.startswith("EC_"):
        type = "ECDSA"

    available_mechanisms = []
    print("Supported mechanisms for this key type:")
    for mechanism in nethsm_sdk.KeyMechanism:
        if mechanism.value.startswith(type):
            available_mechanisms.append(mechanism.value)
            print(f"  {mechanism.value}")

    # If there is only one matching algorithm, we can choose it and don’t have
    # to ask the user.
    if len(available_mechanisms) == 1:
        print(f"Automatically selecting the key mechanism {available_mechanisms[0]}")
        return available_mechanisms

    print(
        "Please enter at least one mechanism.  Enter an empty string to "
        "finish the list of mechanisms."
    )

    mechanism_type = click.Choice(available_mechanisms, case_sensitive=False)
    mechanisms: list[str] = []
    cont = True
    while cont:
        default = None
        prompt_text = "Add mechanism"
        if mechanisms:
            prompt_text += " (or empty string to continue)"
            default = ""
        mechanism = prompt(
            prompt_text,
            type=mechanism_type,
            default=default,
            show_choices=False,
            show_default=False,
        )

        if "" not in available_mechanisms:
            available_mechanisms.append("")

        assert isinstance(mechanism, str)
        if mechanism:
            mechanisms.append(mechanism)
            available_mechanisms.remove(mechanism)
        else:
            cont = False

    if not mechanisms:
        raise click.ClickException("No key mechanisms selected!")

    return mechanisms


@nethsm.command()
@click.option(
    "-t",
    "--type",
    type=TYPE_TYPE,
    prompt=True,
    help="The type for the new key",
)
@click.option(
    "-m",
    "--mechanism",
    "mechanisms",
    type=MECHANISM_TYPE,
    multiple=True,
    help="The mechanisms for the new key",
)
@click.option(
    "--tags",
    type=str,
    multiple=True,
    help="The tags for the new key",
)
@click.option(
    "-p",
    "--prime-p",
    help="The prime p for RSA keys, base64-encoded",
)
@click.option(
    "-q",
    "--prime-q",
    help="The prime q for RSA keys, base64-encoded",
)
@click.option(
    "-e",
    "--public-exponent",
    help="The public exponent for RSA keys, base64-encoded",
)
@click.option(
    "-d",
    "--data",
    help="The key data for ED25519 or ECDSA_* keys, base64-encoded",
)
@click.option(
    "-k",
    "--key-id",
    help="The ID of the new key",
)
@click.pass_context
def add_key(
    ctx: Context,
    type: str,
    mechanisms: list[str],
    tags: list[str],
    prime_p: Optional[str],
    prime_q: Optional[str],
    public_exponent: Optional[str],
    data: Optional[str],
    key_id: Optional[str],
) -> None:
    """Add a key pair on the NetHSM.

    If the key ID is not set, it is generated by the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    key_type = nethsm_sdk.KeyType.from_string(type)
    mechanisms = list(mechanisms) or prompt_mechanisms(type)

    private_key: nethsm_sdk.PrivateKey
    if key_type == nethsm_sdk.KeyType.RSA:
        if data:
            raise click.ClickException("-d/--data must not be set for RSA keys")
        if not prime_p:
            prime_p = prompt_str("Prime p")
        if not prime_q:
            prime_q = prompt_str("Prime q")
        if not public_exponent:
            public_exponent = prompt_str("Public exponent")
        private_key = nethsm_sdk.RsaPrivateKey(
            prime_p=base64_input(prime_p),
            prime_q=base64_input(prime_q),
            public_exponent=base64_input(public_exponent),
        )
    else:
        if prime_p:
            raise click.ClickException("-p/--prime-p may only be set for RSA keys")
        if prime_q:
            raise click.ClickException("-q/--prime-q may only be set for RSA keys")
        if public_exponent:
            raise click.ClickException(
                "-e/--public-exponent may only be set for RSA keys"
            )
        if not data:
            data = prompt_str("Key data")
        private_key = nethsm_sdk.GenericPrivateKey(data=base64_input(data))

    with connect(ctx) as nethsm:
        key_id = nethsm.add_key(
            key_id=key_id,
            type=key_type,
            mechanisms=[nethsm_sdk.KeyMechanism.from_string(m) for m in mechanisms],
            tags=tags,
            private_key=private_key,
        )
        print(f"Key {key_id} added to NetHSM {nethsm.host}")


@nethsm.command()
@click.option(
    "-m",
    "--mechanism",
    "mechanisms",
    type=MECHANISM_TYPE,
    multiple=True,
    help="The mechanisms for the new key",
)
@click.option(
    "--tags",
    type=str,
    multiple=True,
    help="The tags for the new key",
)
@click.option(
    "-k",
    "--key-id",
    help="The ID of the new key",
)
@click.argument("filename")
@click.pass_context
def import_key(
    ctx: Context,
    mechanisms: list[str],
    tags: list[str],
    key_id: Optional[str],
    filename: str,
) -> None:
    """Import a key pair from a PEM file into the NetHSM.

    If the key ID is not set, it is generated by the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    mechanisms = list(mechanisms)

    with open(filename) as f:
        private_key = f.read()

    with connect(ctx) as nethsm:
        key_id = nethsm.add_key_pem(
            key_id=key_id,
            mechanisms=[nethsm_sdk.KeyMechanism.from_string(m) for m in mechanisms],
            tags=tags,
            private_key=private_key,
        )
        print(f"Key {key_id} added to NetHSM {nethsm.host}")


@nethsm.command()
@click.option(
    "type",
    "-t",
    "--type",
    type=TYPE_TYPE,
    prompt=True,
    help="The type for the generated key",
)
@click.option(
    "-m",
    "--mechanism",
    "mechanisms",
    type=MECHANISM_TYPE,
    multiple=True,
    help="The mechanisms for the generated key",
)
@click.option(
    "-l",
    "--length",
    type=int,
    prompt=True,
    help="The length of the generated key",
)
@click.option(
    "-k",
    "--key-id",
    help="The ID of the generated key",
)
@click.pass_context
def generate_key(
    ctx: Context, type: str, mechanisms: list[str], length: int, key_id: Optional[str]
) -> None:
    """Generate a key pair on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    mechanisms = list(mechanisms) or prompt_mechanisms(type)
    with connect(ctx) as nethsm:
        key_id = nethsm.generate_key(
            nethsm_sdk.KeyType.from_string(type),
            [nethsm_sdk.KeyMechanism.from_string(m) for m in mechanisms],
            length,
            key_id,
        )
        print(f"Key {key_id} generated on NetHSM {nethsm.host}")


@nethsm.command()
@click.option("--logging", is_flag=True, help="Query the logging configuration")
@click.option("--network", is_flag=True, help="Query the network configuration")
@click.option("--time", is_flag=True, help="Query the system time")
@click.option(
    "--unattended-boot", is_flag=True, help="Query the unattended boot configuration"
)
@click.option("--public-key", is_flag=True, help="Query the public key")
@click.option("--certificate", is_flag=True, help="Query the certificate")
@click.pass_context
def get_config(
    ctx: Context,
    logging: bool,
    network: bool,
    time: bool,
    unattended_boot: bool,
    public_key: bool,
    certificate: bool,
) -> None:
    """Query the configuration of a NetHSM.

    Only the configuration items selected with the corresponding option are
    queried.  If no option is set, all items are queried.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        print(f"Configuration for NetHSM {nethsm.host}:")
        show_all = not any(
            [logging, network, time, unattended_boot, public_key, certificate]
        )

        if show_all or logging:
            logging_config = nethsm.get_config_logging()
            print("  Logging:")
            print("    IP address:   ", logging_config.ip_address)
            print("    Port:         ", logging_config.port)
            print("    Log level:    ", logging_config.log_level)

        if show_all or network:
            network_config = nethsm.get_config_network()
            print("  Network:")
            print("    IP address:   ", network_config.ip_address)
            print("    Netmask:      ", network_config.netmask)
            print("    Gateway:      ", network_config.gateway)

        if show_all or time:
            time_config = nethsm.get_config_time()
            print("  Time:           ", time_config)

        if show_all or unattended_boot:
            unattended_boot_config = nethsm.get_config_unattended_boot()
            print("  Unattended boot:", unattended_boot_config)

        if show_all or public_key:
            public_key_config = nethsm.get_public_key()
            print("  Public key:")
            for line in public_key_config.splitlines():
                print(f"    {line}")

        if show_all or certificate:
            certificate_config = nethsm.get_certificate()
            print("  Certificate:")
            for line in certificate_config.splitlines():
                print(f"    {line}")


@nethsm.command()
@click.option(
    "-n",
    "--new-passphrase",
    hide_input=True,
    confirmation_prompt=True,
    prompt=True,
    help="The new backup passphrase",
)
@click.option(
    "-p",
    "--current-passphrase",
    help="The current backup passphrase (or an empty string if not set)",
)
@click.option(
    "-f",
    "--force",
    is_flag=True,
    help="Do not ask for confirmation before changing the passphrase",
)
@click.pass_context
def set_backup_passphrase(
    ctx: Context, new_passphrase: str, current_passphrase: Optional[str], force: bool
) -> None:
    """Set the backup passphrase of a NetHSM.

    Changing the backup passphrase requires the current passphrase (if set,
    empty string otherwise).

    This command requires authentication as a user with the Administrator
    role."""

    print(
        "Warning: The backup passphrase cannot be reset without knowing the current value. If the "
        "backup passphrase is lost, neither can it be reset to a new value nor can the created "
        "backups be restored.",
        file=sys.stderr,
    )

    confirmed = force or click.confirm("Do you want to continue?")
    if not confirmed:
        raise click.Abort()

    if not current_passphrase:
        current_passphrase = prompt_str(
            "The current backup passphrase (or an empty string if not set)",
            hide_input=True,
            default="",
        )
    with connect(ctx) as nethsm:
        nethsm.set_backup_passphrase(
            new_passphrase=new_passphrase, current_passphrase=current_passphrase
        )
        print(f"Updated the backup passphrase for NetHSM {nethsm.host}")


@nethsm.command()
@click.option(
    "-n",
    "--new-passphrase",
    hide_input=True,
    confirmation_prompt=True,
    prompt=True,
    help="The new unlock passphrase",
)
@click.option(
    "-p",
    "--current-passphrase",
    hide_input=True,
    prompt=True,
    help="The current unlock passphrase",
)
@click.option(
    "-f",
    "--force",
    is_flag=True,
    help="Do not ask for confirmation before changing the passphrase",
)
@click.pass_context
def set_unlock_passphrase(
    ctx: Context, new_passphrase: str, current_passphrase: str, force: bool
) -> None:
    """Set the unlock passphrase of a NetHSM.

    Changing the unlock passphrase requires the current passphrase.

    This command requires authentication as a user with the Administrator
    role."""

    print(
        "Warning: The unlock passphrase cannot be reset without knowing the current value. If the "
        "unlock passphrase is lost, neither can it be reset to a new value nor can the NetHSM be "
        "unlocked.",
        file=sys.stderr,
    )

    confirmed = force or click.confirm("Do you want to continue?")
    if not confirmed:
        raise click.Abort()

    with connect(ctx) as nethsm:
        nethsm.set_unlock_passphrase(
            new_passphrase=new_passphrase, current_passphrase=current_passphrase
        )
        print(f"Updated the unlock passphrase for NetHSM {nethsm.host}")


@nethsm.command()
@click.option(
    "-a",
    "--ip-address",
    help="The IP address of the new logging destination",
    required=True,
)
@click.option(
    "-p",
    "--port",
    type=int,
    help="The port of the new logging destination",
    required=True,
)
@click.option(
    "-l",
    "--log-level",
    type=LOG_LEVEL_TYPE,
    help="The new log level",
    required=True,
)
@click.pass_context
def set_logging_config(
    ctx: Context, ip_address: str, port: int, log_level: str
) -> None:
    """Set the logging configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.set_logging_config(
            ip_address, port, nethsm_sdk.LogLevel.from_string(log_level)
        )
        print(f"Updated the logging configuration for NetHSM {nethsm.host}")


@nethsm.command()
@click.option(
    "-a",
    "--ip-address",
    help="The new IP address",
    required=True,
)
@click.option(
    "-n",
    "--netmask",
    help="The new netmask",
    required=True,
)
@click.option(
    "-g",
    "--gateway",
    help="The new gateway",
    required=True,
)
@click.pass_context
def set_network_config(
    ctx: Context, ip_address: str, netmask: str, gateway: str
) -> None:
    """Set the network configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.set_network_config(ip_address, netmask, gateway)
        print(f"Updated the network configuration for NetHSM {nethsm.host}")


@nethsm.command()
@click.argument(
    "time",
    type=DATETIME_TYPE,
    required=False,
)
@click.pass_context
def set_time(ctx: Context, time: Optional[datetime.datetime]) -> None:
    """Set the system time of a NetHSM.

    If the time is not given as an argument, the system time of this system is used.

    This command requires authentication as a user with the Administrator
    role."""
    if not time:
        time = datetime.datetime.now(datetime.timezone.utc)
    with connect(ctx) as nethsm:
        nethsm.set_time(time)
        print(f"Updated the system time for NetHSM {nethsm.host}")


@nethsm.command()
@click.argument(
    "status",
    type=UNATTENDED_BOOT_STATUS_TYPE,
)
@click.pass_context
def set_unattended_boot(ctx: Context, status: str) -> None:
    """Set the unattended boot configuration of a NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.set_unattended_boot(nethsm_sdk.UnattendedBootStatus.from_string(status))
        print(f"Updated the unattended boot configuration for NetHSM {nethsm.host}")


def get_api_or_key_id(api: bool, key_id: Optional[str]) -> tuple[bool, Optional[str]]:
    """Helper method for operations that can be executed either for the API
    certificate or for the certificate stored for a key."""
    if api and key_id:
        raise click.ClickException("--api and --key-id are mutually exclusive")

    if not api and not key_id:
        choice = click.Choice(["api", "key"], case_sensitive=False)
        method = prompt(
            "For stored key or for NetHSM TLS interface?",
            type=choice,
        )
        if method == "api":
            api = True
        elif method == "key":
            key_id = prompt("Key ID")
        else:
            raise ValueError("Unexpected method")

    return (api, key_id)


@nethsm.command()
@click.option(
    "-a", "--api", is_flag=True, help="Set the certificate for the NetHSM TLS interface"
)
@click.option("-k", "--key-id", help="The ID of the key to set the certificate for")
@click.argument("filename")
@click.pass_context
def set_certificate(
    ctx: Context, api: bool, key_id: Optional[str], filename: str
) -> None:
    """Set a certificate on the NetHSM.

    If the --api option is set, the certificate used for the NetHSM TLS interface
    is set.  If the --key-id option is set, the certificate for a key stored on
    the NetHSM is set.

    This command requires authentication as a user with the Administrator
    role."""
    (api, key_id) = get_api_or_key_id(api, key_id)
    with connect(ctx) as nethsm:
        with open(filename, "rb") as f:
            if key_id:
                nethsm.set_key_certificate(key_id, f)
                print(
                    f"Updated the certificate for key {key_id} on NetHSM {nethsm.host}"
                )
            else:
                nethsm.set_certificate(f)
                print(f"Updated the API certificate for NetHSM {nethsm.host}")


@nethsm.command()
@click.option(
    "-a", "--api", is_flag=True, help="Get the certificate for the NetHSM TLS interface"
)
@click.option("-k", "--key-id", help="The ID of the key to get the certificate for")
@click.pass_context
def get_certificate(ctx: Context, api: bool, key_id: Optional[str]) -> None:
    """Get a certificate from the NetHSM.

    If the --api option is set, the certificate used for the NetHSM TLS interface
    is queried.  If the --key-id option is set, the certificate for a key stored on
    the NetHSM is queried.

    This command requires authentication as a user with the Administrator role.
    The certificate for a key can also be queried by a user with the Operator
    role."""
    (api, key_id) = get_api_or_key_id(api, key_id)
    with connect(ctx) as nethsm:
        if key_id:
            cert = nethsm.get_key_certificate(key_id)
            try:
                print(cert.decode())
            except UnicodeError:
                print(cert)
        else:
            print(nethsm.get_certificate())


@nethsm.command()
@click.option(
    "-k",
    "--key-id",
    prompt=True,
    help="The ID of the key to delete the certificate for",
)
@click.pass_context
def delete_certificate(ctx: Context, key_id: str) -> None:
    """Delete a certificate for a stored key from the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.delete_key_certificate(key_id)
        print(f"Deleted certificate for key {key_id} on NetHSM {nethsm.host}")


@nethsm.command()
@click.option(
    "-a", "--api", is_flag=True, help="Generate a CSR for the NetHSM TLS interface"
)
@click.option("-k", "--key-id", help="The ID of the key to generate the CSR for")
@click.option("--country", default="", prompt=True, help="The country name")
@click.option(
    "--state-or-province", default="", prompt=True, help="The state or province name"
)
@click.option("--locality", default="", prompt=True, help="The locality name")
@click.option("--organization", default="", prompt=True, help="The organization name")
@click.option(
    "--organizational-unit", default="", prompt=True, help="The organization unit name"
)
@click.option("--common-name", default="", prompt=True, help="The common name")
@click.option("--email-address", default="", prompt=True, help="The email address")
@click.pass_context
def csr(
    ctx: Context,
    api: bool,
    key_id: Optional[str],
    country: str,
    state_or_province: str,
    locality: str,
    organization: str,
    organizational_unit: str,
    common_name: str,
    email_address: str,
) -> None:
    """Generate a certificate signing request.

    If the --api option is set, the CSR is generated for the NetHSM, for
    example to replace the self-signed initial certificate.  If the --key-id
    option is set, the CSR is generated for a key stored on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    (api, key_id) = get_api_or_key_id(api, key_id)
    with connect(ctx) as nethsm:
        if key_id:
            csr = nethsm.key_csr(
                key_id=key_id,
                country=country,
                state_or_province=state_or_province,
                locality=locality,
                organization=organization,
                organizational_unit=organizational_unit,
                common_name=common_name,
                email_address=email_address,
            )
        else:
            csr = nethsm.csr(
                country=country,
                state_or_province=state_or_province,
                locality=locality,
                organization=organization,
                organizational_unit=organizational_unit,
                common_name=common_name,
                email_address=email_address,
            )
        print(csr)


@nethsm.command()
@click.option(
    "type",
    "-t",
    "--type",
    type=TYPE_TLS_KEY_TYPE,
    prompt=True,
    help="The type for the generated key",
)
@click.option(
    "-l",
    "--length",
    type=int,
    help="The length of the generated key",
)
@click.pass_context
def generate_tls_key(ctx: Context, type: str, length: Optional[int]) -> None:
    """Generate key pair for NetHSM TLS interface.

    This command requires authentication as a user with the Administrator
    role."""
    key_type = nethsm_sdk.TlsKeyType.from_string(type)
    if key_type == nethsm_sdk.TlsKeyType.RSA:
        if not length:
            length = click.prompt("Length", type=int)
    else:
        if length:
            raise click.ClickException("-l/--length may only be set for RSA keys")

    with connect(ctx) as nethsm:
        nethsm.generate_tls_key(key_type, length)
        print(f"Key for TLS interface generated on NetHSM {nethsm.host}")


@nethsm.command()
@click.pass_context
def system_info(ctx: Context) -> None:
    """Get system information for a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        info = nethsm.get_system_info()
        print(f"Host:             {nethsm.host}")
        print(f"Firmware version: {info.firmware_version}")
        print(f"Software version: {info.software_version}")
        print(f"Hardware version: {info.hardware_version}")
        print(f"Build tag:        {info.build_tag}")
        if info.tpm.attestation_keys:
            print("Attestation keys")
            for key, value in info.tpm.attestation_keys.items():
                print(f"  {key}:           {value}")
        if info.tpm.platform_configuration_registers:
            print("Platform Configuration Registers")
            for key, value in info.tpm.platform_configuration_registers.items():
                print(f"  {key}:              {value}")


@nethsm.command()
@click.argument("filename")
@click.pass_context
def backup(ctx: Context, filename: str) -> None:
    """Make a backup of a NetHSM instance and write it to a file.

    This command requires authentication as a user with the Backup role."""
    if os.path.exists(filename):
        raise click.ClickException(f"Backup file {filename} already exists")
    with connect(ctx) as nethsm:
        data = nethsm.backup()
        with open(filename, "xb") as f:
            f.write(data)
            print(f"Backup for {nethsm.host} written to {filename}")
        try:
            EncryptedBackup.parse(data)
        except ValueError as e:
            raise CliException(f"Failed to validate backup: {e}", support_hint=False)


@nethsm.command()
@click.option(
    "-p",
    "--backup-passphrase",
    hide_input=True,
    prompt=True,
    help="The backup passphrase",
)
@click.option(
    "-t",
    "--system-time",
    type=DATETIME_TYPE,
    help="The system time to set (default: the time of this system)",
)
@click.option(
    "-f",
    "--force",
    is_flag=True,
    help="Restore the backup even if validation fails",
)
@click.argument("filename")
@click.pass_context
def restore(
    ctx: Context,
    backup_passphrase: str,
    system_time: Optional[datetime.datetime],
    force: bool,
    filename: str,
) -> None:
    """Restore a backup of a NetHSM instance from a file.

    If the system time is not set, the current system time is used."""
    if not system_time:
        system_time = datetime.datetime.now(datetime.timezone.utc)

    with open(filename, "rb") as f:
        data = f.read()
    try:
        EncryptedBackup.parse(data).decrypt(backup_passphrase)
    except ValueError as e:
        if force:
            print(f"Failed to validate backup: {e}")
            print("Backup is restored anyway as --force is set")
        else:
            raise CliException(
                f"Failed to validate backup (use --force to restore anyway): {e}",
                support_hint=False,
            )

    require_auth = False
    with connect(ctx, require_auth=False) as nethsm:
        state = nethsm.get_state()
        if state == State.OPERATIONAL:
            require_auth = True

    with connect(ctx, require_auth=require_auth) as nethsm:
        with open(filename, "rb") as f:
            nethsm.restore(data, backup_passphrase, system_time)
        print(f"Backup restored on NetHSM {nethsm.host}")


@nethsm.command()
@click.option(
    "-p",
    "--backup-passphrase",
    help="The backup passphrase for decryption (default: only the unencrypted metadata is validated)",
)
@click.argument("filename")
def validate_backup(backup_passphrase: Optional[str], filename: str) -> None:
    """Validate a NetHSM backup file.

    Per default, only the metadata of the encrypted backup is validated.  If
    the backup passphrase is set, the backup is decrypted and the content is
    also validated."""

    with open(filename, "rb") as f:
        data = f.read()
    try:
        encrypted = EncryptedBackup.parse(data)
    except ValueError as e:
        raise CliException(
            f"Failed to validate backup metadata: {e}", support_hint=False
        )

    if backup_passphrase:
        try:
            encrypted.decrypt(backup_passphrase)
        except ValueError as e:
            raise CliException(
                f"Failed to validate backup content: {e}", support_hint=False
            )
        print("Backup metadata and content are valid.")
    else:
        print("Backup metadata is valid.")


@nethsm.command()
@click.option(
    "-p",
    "--backup-passphrase",
    hide_input=True,
    prompt=True,
    help="The backup passphrase",
)
@click.argument("filename")
def export_backup(backup_passphrase: str, filename: str) -> None:
    """Export the content of a NetHSM backup file.

    The key-value data stored in the backup file is printed to the standard
    output as a JSON object using the base64 encoding for binary data.
    Additionally, the .locked-domain-key and .version keys are set with the
    domain key and version info extracted from the backup file."""

    with open(filename, "rb") as f:
        data = f.read()
    try:
        encrypted = EncryptedBackup.parse(data)
    except ValueError as e:
        raise CliException(f"Failed to parse backup metadata: {e}", support_hint=False)

    try:
        decrypted = encrypted.decrypt(backup_passphrase)
    except ValueError as e:
        raise CliException(f"Failed to decrypt backup content: {e}", support_hint=False)

    values: dict[str, Any] = {}
    values[".locked-domain-key"] = base64.b64encode(decrypted.domain_key).decode()
    values[".version"] = decrypted.version
    for key, value in decrypted.data.items():
        values[key] = base64.b64encode(value).decode()

    json.dump(values, sys.stdout, indent=4)
    print()


@nethsm.command()
@click.argument("filename")
@click.pass_context
def update(ctx: Context, filename: str) -> None:
    """Load an update to a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        with open(filename, "rb") as f:
            release_notes = nethsm.update(f)
        print(f"Image {filename} uploaded to NetHSM {nethsm.host}")
        if release_notes:
            print("Release notes:")
            print("  " + release_notes)


@nethsm.command()
@click.pass_context
def cancel_update(ctx: Context) -> None:
    """Cancel a queued update on a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.cancel_update()
        print(f"Update successfully cancelled on NetHSM {nethsm.host}")


@nethsm.command()
@click.pass_context
def commit_update(ctx: Context) -> None:
    """Commit a queued update on a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        nethsm.commit_update()
        print(f"Update successfully committed on NetHSM {nethsm.host}")


@nethsm.command()
@click.option(
    "-f",
    "--force",
    is_flag=True,
    help="Force reboot",
)
@click.pass_context
def reboot(ctx: Context, force: bool) -> None:
    """Reboot a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        print(f"NetHSM {nethsm.host} will be rebooted.")
        reboot = force or click.confirm("Do you want to continue?")

        if reboot:
            nethsm.reboot()
            print(f"NetHSM {nethsm.host} is about to reboot")
        else:
            print(f"Reboot on NetHSM {nethsm.host} cancelled")


@nethsm.command()
@click.option(
    "-f",
    "--force",
    is_flag=True,
    help="Force shutdown",
)
@click.pass_context
def shutdown(ctx: Context, force: bool) -> None:
    """Shutdown a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    require_auth = False
    with connect(ctx, require_auth=require_auth) as nethsm:
        state = nethsm.get_state()
        if state == State.OPERATIONAL:
            require_auth = True

    with connect(ctx, require_auth=require_auth) as nethsm:
        print(f"NetHSM {nethsm.host} will be shutdown.")
        shutdown = force or click.confirm("Do you want to continue?")

        if shutdown:
            nethsm.shutdown()
            print(f"NetHSM {nethsm.host} is about to shutdown")
        else:
            print(f"Shutdown on NetHSM {nethsm.host} cancelled")


@nethsm.command()
@click.option(
    "-f",
    "--force",
    is_flag=True,
    help="Force factory reset",
)
@click.pass_context
def factory_reset(ctx: Context, force: bool) -> None:
    """Perform a factory reset for a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role."""
    with connect(ctx) as nethsm:
        print(f"NetHSM {nethsm.host} will be set to factory defaults.")
        print(f"All data will be lost!")
        factory_reset = force or click.confirm("Do you want to continue?")

        if factory_reset:
            nethsm.factory_reset()
            print(f"NetHSM {nethsm.host} is about to perform a factory reset")
        else:
            print(f"Factory reset on NetHSM {nethsm.host} cancelled")


@nethsm.command()
@click.option(
    "-k",
    "--key-id",
    prompt=True,
    help="The ID of the key to encrypt the data with",
)
@click.option(
    "-d",
    "--data",
    prompt=True,
    help="The data in Base64 encoding",
)
@click.option(
    "-m",
    "--mode",
    type=ENCRYPT_MODE_TYPE,
    prompt=True,
    help="The encrypt mode",
)
@click.option(
    "-iv",
    "--initialization-vector",
    "iv",
    type=str,
    help="The initialization vector in Base64 encoding",
)
@click.pass_context
def encrypt(ctx: Context, key_id: str, data: str, mode: str, iv: Optional[str]) -> None:
    """Encrypt data with an asymmetric secret key on the NetHSM and print the encrypted message.

    This command requires authentication as a user with the Operator role."""
    with connect(ctx) as nethsm:
        encrypted = nethsm.encrypt(
            key_id,
            base64_input(data),
            nethsm_sdk.EncryptMode.from_string(mode),
            iv=base64_input(iv) if iv else None,
        )
        print(f"Encrypted: {encrypted.encrypted.data}")
        print(f"Initialization vector: {encrypted.iv.data}")


@nethsm.command()
@click.option(
    "-k",
    "--key-id",
    prompt=True,
    help="The ID of the key to decrypt the data width",
)
@click.option(
    "-d",
    "--data",
    prompt=True,
    help="The encrypted data in Base64 encoding",
)
@click.option(
    "-m",
    "--mode",
    type=DECRYPT_MODE_TYPE,
    prompt=True,
    help="The decrypt mode",
)
@click.option(
    "-iv",
    "--initialization-vector",
    "iv",
    type=str,
    help="The initialization vector in Base64 encoding",
)
@click.pass_context
def decrypt(ctx: Context, key_id: str, data: str, mode: str, iv: Optional[str]) -> None:
    """Decrypt data with a secret key on the NetHSM and print the decrypted message.

    This command requires authentication as a user with the Operator role."""
    with connect(ctx) as nethsm:
        decrypted = nethsm.decrypt(
            key_id,
            base64_input(data),
            nethsm_sdk.DecryptMode.from_string(mode),
            base64_input(iv) if iv else None,
        )
        print(decrypted.data)


@nethsm.command()
@click.option(
    "-k",
    "--key-id",
    prompt=True,
    help="The ID of the key to sign the data width",
)
@click.option(
    "-d",
    "--data",
    prompt=True,
    help="The data to sign encoded using Base64",
)
@click.option(
    "-m",
    "--mode",
    type=SIGN_MODE_TYPE,
    prompt=True,
    help="The sign mode",
)
@click.pass_context
def sign(ctx: Context, key_id: str, data: str, mode: str) -> None:
    """Sign data with a secret key on the NetHSM and print the signature.

    This command requires authentication as a user with the Operator role."""
    with connect(ctx) as nethsm:
        signature = nethsm.sign(
            key_id, base64_input(data), nethsm_sdk.SignMode.from_string(mode)
        )
        print(signature.data)
