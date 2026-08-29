import logging
import os
import re
from functools import wraps
from typing import Any, Callable, Optional

import click
from cryptography.hazmat.primitives.asymmetric import ec
from nitrokey.trussed._bootloader.nrf52_upload.dfu.nrfutils import pkg_gen, pubview, usb_serial
from nitrokey.trussed._bootloader.nrf52_upload.dfu.signing import Signing

from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.nethsm import Config
from pynitrokey.cli.nethsm_pvtkey import NetHSMKey
from pynitrokey.helpers import local_critical

logger = logging.getLogger(__name__)


def get_pvt_key(
    use_nethsm: bool,
    nethsm_host: Optional[str] = None,
    nethsm_username: Optional[str] = None,
    nethsm_password: Optional[str] = None,
    verify_tls: bool = True,
    ca_certs: Optional[str] = None,
    key_id: str = "",
) -> ec.EllipticCurvePrivateKey:
    if not use_nethsm:
        return Signing.get_key_from_file(key_id)

    config = Config(
        host=nethsm_host,
        username=nethsm_username,
        password=nethsm_password,
        verify_tls=verify_tls,
        ca_certs=ca_certs,
        debug=False,
    )
    return NetHSMKey(config, key_id)


_AnyCallable = Callable[..., Any]


def _extract_key_id(text: str) -> str:  # Extract from NetHSM output
    # Pattern explanation:
    # ^Key\s+           Starts with "Key" followed by spaces
    # ([a-fA-F0-9]+)    Captures the hex Key ID (Group 1)
    # \s+generated on NetHSM\s+ Matches middle label
    # \S+$              Matches the host URL at the end
    pattern = r"^Key\s+([a-fA-F0-9]+)\s+generated on NetHSM\s+\S+$"
    match = re.search(pattern, text.strip())
    if match:
        return match.group(1)
    return text


def with_signer(f: _AnyCallable) -> _AnyCallable:
    """Decorator that adds signer options and injects the signer object."""

    @click.option(
        "--key", required=True, help="Key file for file from disk, key id for using NetHSM"
    )
    @click.option("--use-nethsm", is_flag=True, default=False, help="Use NetHSM for signing.")
    @click.option(
        "--use-key-file",
        is_flag=True,
        default=False,
        help="Use if --key parameter has a file pointing to NetHSM key id.",
    )
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
        key: str,
        use_nethsm: bool,
        use_key_file: bool,
        nethsm_host: Optional[str] = None,
        nethsm_username: Optional[str] = None,
        nethsm_password: Optional[str] = None,
        verify_tls: bool = True,
        ca_certs: Optional[str] = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        if use_key_file:
            with open(key, "r") as fl:
                key = _extract_key_id(fl.read())
        signer = get_pvt_key(
            use_nethsm=use_nethsm,
            nethsm_host=nethsm_host,
            nethsm_username=nethsm_username,
            nethsm_password=nethsm_password,
            verify_tls=verify_tls,
            ca_certs=ca_certs,
            key_id=key,
        )
        return f(*args, signer=signer, **kwargs)

    return wrapper


@click.group()
def nrf() -> None:
    """Nordic nRF52 DFU/signing utilities."""


@nrf.group()
def keys() -> None:
    """Key generation and inspection."""


@keys.command("display")
@click.option("--format", "fmt", required=True, type=click.Choice(["code", "pem"]))
@click.option("--out-file", "out_file", required=True)
@with_signer
def keys_display(fmt: str, out_file: str, signer: ec.EllipticCurvePrivateKey) -> None:
    """Display/export the public key derived from KEY_FILE in the given format."""
    pubview(fmt, signer, out_file)


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
    app_version: Optional[int],
    bootloader_version: Optional[int],
    application: Optional[str],
    bootloader: Optional[str],
    ecdsa_validation: bool,
    out_path: str,
    signer: ec.EllipticCurvePrivateKey,
) -> None:
    """Generate an application and/or bootloader DFU package."""
    pkg_gen(
        hw_version=hw_version,
        sd_req=sd_req,
        key_file=signer,
        out_path=out_path,
        app_version=app_version,
        bootloader_version=bootloader_version,
        application=application,
        bootloader=bootloader,
        ecdsa_validation=ecdsa_validation,
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
