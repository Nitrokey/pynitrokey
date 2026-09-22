import logging
import os
from typing import Optional

import click
from nitrokey.trussed._bootloader.nrf52_upload.dfu.nrfutils import (
    keygen,
    pkg_gen,
    pubview,
    usb_serial,
)

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import local_critical

logger = logging.getLogger(__name__)


@click.group()
def nrf() -> None:
    """Nordic nRF52 DFU/signing utilities."""


@nrf.group()
def keys() -> None:
    """Key generation and inspection."""


@keys.command("generate")
@click.argument("key_file")
def keys_generate(key_file: str) -> None:
    """Generate a new signing key and write it to KEY_FILE."""
    keygen(key_file)


@keys.command("display")
@click.option("--format", "fmt", required=True, type=click.Choice(["code", "pem"]))
@click.option("--key-file", "priv_file", required=True)
@click.option("--out-file", "out_file", required=True)
def keys_display(fmt: str, priv_file: str, out_file: str) -> None:
    """Display/export the public key derived from KEY_FILE in the given format."""
    pubview(fmt, priv_file, out_file)


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
