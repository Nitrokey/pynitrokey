import logging
import os
from functools import wraps
from typing import Any, Callable, Optional

import click
from nitrokey.trussed._bootloader.nrf52_upload.dfu.nrfutils import (
    keygen,
    pkg_gen,
    pubview,
    usb_serial,
)
from nitrokey.trussed._bootloader.nrf52_upload.dfu.signing import Signing

from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.nethsm import Config
from pynitrokey.cli.nethsm_signer import NetHSM_Signing
from pynitrokey.helpers import local_critical

logger = logging.getLogger(__name__)


def get_signer(
    use_nethsm: bool,
    nethsm_host: Optional[str] = None,
    nethsm_username: Optional[str] = None,
    nethsm_password: Optional[str] = None,
    verify_tls: bool = True,
    ca_certs: Optional[str] = None,
) -> Signing:
    if not use_nethsm:
        return Signing()

    config = Config(
        host=nethsm_host,
        username=nethsm_username,
        password=nethsm_password,
        verify_tls=verify_tls,
        ca_certs=ca_certs,
        debug=False,
    )
    return NetHSM_Signing(config)


_AnyCallable = Callable[..., Any]


def with_signer(f: _AnyCallable) -> _AnyCallable:
    """Decorator that adds signer options and injects the signer object."""

    @click.option("--use-nethsm", is_flag=True, default=False, help="Use NetHSM for signing.")
    @click.option(
        "--nethsm-host",
        default=None,
        help="NetHSM host address. Leave empty if environment variable is set",
    )
    @click.option("--nethsm-username", default=None, help="NetHSM username.")
    @click.option("--nethsm-password", default=None, help="NetHSM password.")
    @click.option(
        "--verify-tls", is_flag=True, default=False, help="Enable TLS certificate verification."
    )
    @click.option("--ca-certs", default=None, help="CA Certificates.")
    @wraps(f)
    def wrapper(
        use_nethsm: bool,
        nethsm_host: Optional[str] = None,
        nethsm_username: Optional[str] = None,
        nethsm_password: Optional[str] = None,
        verify_tls: bool = True,
        ca_certs: Optional[str] = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        signer = get_signer(
            use_nethsm=use_nethsm,
            nethsm_host=nethsm_host,
            nethsm_username=nethsm_username,
            nethsm_password=nethsm_password,
            verify_tls=verify_tls,
            ca_certs=ca_certs,
        )
        return f(*args, signer=signer, **kwargs)

    return wrapper


@click.group()
def nrf() -> None:
    """Nordic nRF52 DFU/signing utilities."""


@nrf.group()
def keys() -> None:
    """Key generation and inspection."""


@keys.command("generate")
@click.argument("key_file")
@with_signer
def keys_generate(key_file: str, signer: Signing) -> None:
    """Generate a new signing key and write it to KEY_FILE."""
    keygen(key_file, signer=signer)


@keys.command("display")
@click.option("--format", "fmt", required=True, type=click.Choice(["code", "pem"]))
@click.option("--key-file", "priv_file", required=True)
@click.option("--out-file", "out_file", required=True)
@with_signer
def keys_display(fmt: str, priv_file: str, out_file: str, signer: Signing) -> None:
    """Display/export the public key derived from KEY_FILE in the given format."""
    pubview(fmt, priv_file, out_file, signer=signer)


@nrf.group()
def dfu() -> None:
    """Perform a DFU transfer."""


@dfu.command("usb-serial")
@click.option("--package", "-pkg", required=True)
@click.option("--port", "-p", required=True)
def dfu_usb_serial(package: str, port: str) -> None:
    """Send a DFU package over a USB serial port."""
    usb_serial(package, port)


@nrf.group()
def pkg() -> None:
    """Generate DFU packages."""


@pkg.command("generate")
@click.option("--hw-version", required=True, type=int)
@click.option("--sd-req", required=True)
@click.option("--key-file", required=True)
@click.option("--application-version", "app_version", type=int, default=None)
@click.option("--bootloader-version", type=int, default=None)
@click.option("--application", "application", default=None)
@click.option("--bootloader", "bootloader", default=None)
@click.option(
    "--app-boot-validation",
    "ecdsa_validation",
    is_flag=True,
    default=False,
    help="Set to enable VALIDATE_ECDSA_P256_SHA256.",
)
@click.argument("out_path")
@with_signer
def pkg_generate(
    hw_version: int,
    sd_req: str,
    key_file: str,
    app_version: Optional[int],
    bootloader_version: Optional[int],
    application: Optional[str],
    bootloader: Optional[str],
    ecdsa_validation: bool,
    out_path: str,
    signer: Signing,
) -> None:
    """Generate an application and/or bootloader DFU package."""
    pkg_gen(
        hw_version=hw_version,
        sd_req=sd_req,
        key_file=key_file,
        out_path=out_path,
        app_version=app_version,
        bootloader_version=bootloader_version,
        application=application,
        bootloader=bootloader,
        ecdsa_validation=ecdsa_validation,
        signer=signer,
    )


def main() -> None:
    development = os.environ.get("NKDEV")
    try:
        nrf()
    except CliException as e:
        if development:
            raise
        e.show()
    except Exception as e:
        if development:
            raise
        logger.warning("An unhandled exception occurred", exc_info=True)
        local_critical("An unhandled exception occurred", e)
