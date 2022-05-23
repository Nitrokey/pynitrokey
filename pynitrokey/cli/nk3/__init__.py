# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import os.path
import platform
from typing import List, Optional, Tuple, Type, TypeVar

import click
from spsdk.mboot.exceptions import McuBootConnectionError

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import (
    DownloadProgressBar,
    ProgressBar,
    Retries,
    confirm,
    local_print,
)
from pynitrokey.nk3 import list as list_nk3
from pynitrokey.nk3 import open as open_nk3
from pynitrokey.nk3.base import Nitrokey3Base
from pynitrokey.nk3.bootloader import (
    RKHT,
    FirmwareMetadata,
    Nitrokey3Bootloader,
    check_firmware_image,
)
from pynitrokey.nk3.device import BootMode, Nitrokey3Device
from pynitrokey.nk3.exceptions import TimeoutException
from pynitrokey.nk3.updates import get_repo
from pynitrokey.nk3.utils import Version
from pynitrokey.updates import OverwriteError

T = TypeVar("T", bound=Nitrokey3Base)

logger = logging.getLogger(__name__)


class Context:
    def __init__(self, path: Optional[str]) -> None:
        self.path = path

    def list(self) -> List[Nitrokey3Base]:
        if self.path:
            device = open_nk3(self.path)
            if device:
                return [device]
            else:
                return []
        else:
            return list_nk3()

    def _select_unique(self, name: str, devices: List[T]) -> T:
        if len(devices) == 0:
            msg = f"No {name} device found"
            if self.path:
                msg += f" at path {self.path}"
            raise CliException(msg)

        if len(devices) > 1:
            raise CliException(
                f"Multiple {name} devices found -- use the --path option to select one"
            )

        return devices[0]

    def connect(self) -> Nitrokey3Base:
        return self._select_unique("Nitrokey 3", self.list())

    def connect_device(self) -> Nitrokey3Device:
        devices = [
            device for device in self.list() if isinstance(device, Nitrokey3Device)
        ]
        return self._select_unique("Nitrokey 3", devices)

    def _await(self, name: str, ty: Type[T]) -> T:
        for t in Retries(10):
            logger.debug(f"Searching {name} device ({t})")
            devices = [device for device in self.list() if isinstance(device, ty)]
            if len(devices) == 0:
                logger.debug(f"No {name} device found, continuing")
                continue
            if len(devices) > 1:
                raise CliException(f"Multiple {name} devices found")
            return devices[0]

        raise CliException(f"No {name} device found")

    def await_device(self) -> Nitrokey3Device:
        return self._await("Nitrokey 3", Nitrokey3Device)

    def await_bootloader(self) -> Nitrokey3Bootloader:
        return self._await("Nitrokey 3 bootloader", Nitrokey3Bootloader)


@click.group()
@click.option("-p", "--path", "path", help="The path of the Nitrokey 3 device")
@click.pass_context
def nk3(ctx: click.Context, path: Optional[str]) -> None:
    """Interact with Nitrokey 3 devices, see subcommands."""
    ctx.obj = Context(path)


@nk3.command()
def list() -> None:
    """List all Nitrokey 3 devices."""
    local_print(":: 'Nitrokey 3' keys")
    for device in list_nk3():
        with device as device:
            uuid = device.uuid()
            if uuid:
                local_print(f"{device.path}: {device.name} {device.uuid():X}")
            else:
                local_print(f"{device.path}: {device.name}")


@nk3.command()
@click.option(
    "--bootloader",
    is_flag=True,
    help="Reboot a Nitrokey 3 device into bootloader mode",
)
@click.pass_obj
def reboot(ctx: Context, bootloader: bool) -> None:
    """
    Reboot the key.

    Per default, the key will reboot into regular firmware mode.  If the --bootloader option
    is set, a key can boot from firmware mode to bootloader mode.  Booting into
    bootloader mode has to be confirmed by pressing the touch button.
    """
    with ctx.connect() as device:
        if bootloader:
            if isinstance(device, Nitrokey3Device):
                _reboot_to_bootloader(device)
            else:
                raise CliException(
                    "A Nitrokey 3 device in bootloader mode can only reboot into firmware mode.",
                    support_hint=False,
                )
        else:
            device.reboot()


def _reboot_to_bootloader(device: Nitrokey3Device) -> None:
    local_print(
        "Please press the touch button to reboot the device into bootloader mode ..."
    )
    try:
        device.reboot(BootMode.BOOTROM)
    except TimeoutException:
        raise CliException(
            "The reboot was not confirmed with the touch button.",
            support_hint=False,
        )


@nk3.command()
@click.option(
    "-l",
    "--length",
    "length",
    default=57,
    help="The length of the generated data (default: 57)",
)
@click.pass_obj
def rng(ctx: Context, length: int) -> None:
    """Generate random data on the device."""
    with ctx.connect_device() as device:
        while length > 0:
            rng = device.rng()
            local_print(rng[:length].hex())
            length -= len(rng)


@nk3.command()
@click.option(
    "--pin",
    "pin",
    help="The FIDO2 PIN of the device (if enabled)",
)
@click.pass_obj
def test(ctx: Context, pin: Optional[str]) -> None:
    """Run some tests on all connected Nitrokey 3 devices."""
    from .test import TestContext, log_devices, log_system, run_tests

    log_system()
    devices = ctx.list()

    if len(devices) == 0:
        log_devices()
        raise CliException("No connected Nitrokey 3 devices found")

    local_print(f"Found {len(devices)} Nitrokey 3 device(s):")
    for device in devices:
        local_print(f"- {device.name} at {device.path}")

    results = []
    test_ctx = TestContext(pin=pin)
    for device in devices:
        results.append(run_tests(test_ctx, device))

    n = len(devices)
    success = sum(results)
    failure = n - success
    local_print("")
    local_print(
        f"Summary: {n} device(s) tested, {success} successful, {failure} failed"
    )

    if failure > 0:
        local_print("")
        raise CliException(f"Test failed for {failure} device(s)")


@nk3.command()
@click.argument("path", default=".")
@click.option(
    "-f",
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite the firmware image if it already exists",
)
@click.option("--version", help="Download this version instead of the latest one")
def fetch_update(path: str, force: bool, version: Optional[str]) -> None:
    """
    Fetches a firmware update for the Nitrokey 3 and stores it at the given path.

    If no path is given, the firmware image stored in the current working
    directory.  If the given path is a directory, the image is stored under
    that directory.  Otherwise it is written to the path.  Existing files are
    only overwritten if --force is set.

    Per default, the latest firmware release is fetched.  If you want to
    download a specific version, use the --version option.
    """
    try:
        update = get_repo().get_update_or_latest(version)
    except Exception as e:
        if version:
            raise CliException(f"Failed to find firmware update {version}", e)
        else:
            raise CliException("Failed to find latest firmware update", e)

    bar = DownloadProgressBar(desc=update.tag)

    try:
        if os.path.isdir(path):
            path = update.download_to_dir(path, overwrite=force, callback=bar.update)
        else:
            if not force and os.path.exists(path):
                raise OverwriteError(path)
            with open(path, "wb") as f:
                update.download(f, callback=bar.update)

        bar.close()

        local_print(f"Successfully downloaded firmware release {update.tag} to {path}")
    except OverwriteError as e:
        raise CliException(
            f"{e.path} already exists.  Use --force to overwrite the file.",
            support_hint=False,
        )
    except Exception as e:
        raise CliException(f"Failed to download firmware update {update.tag}", e)


@nk3.command()
@click.argument("image")
def validate_update(image: str) -> None:
    """
    Validates the given firmware image and prints the firmware version and the signer.
    """
    with open(image, "rb") as f:
        data = f.read()

    try:
        metadata = FirmwareMetadata.from_image_data(data)
    except Exception as e:
        raise CliException("Failed to parse and validate firmware image", e)

    if metadata.rkht:
        if metadata.rkht == RKHT:
            signature = "Nitrokey"
        else:
            signature = f"unknown issuer (RKHT: {metadata.rkht.hex()})"
    else:
        signature = "unsigned"

    print(f"version:    {metadata.version}")
    print(f"signed by:  {signature}")


@nk3.command()
@click.argument("image", required=False)
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
    hidden=True,
)
@click.pass_obj
def update(ctx: Context, image: Optional[str], experimental: bool) -> None:
    """
    Update the firmware of the device using the given image.

    This command requires that exactly one Nitrokey 3 in bootloader or firmware mode is connected.
    The user is asked to confirm the operation before the update is started.  The Nitrokey 3 may
    not be removed during the update.  Also, additional Nitrokey 3 devices may not be connected
    during the update.

    If no firmware image is given, the latest firmware release is downloaded automatically.

    If the connected Nitrokey 3 device is in firmware mode, the user is prompted to touch the
    device’s button to confirm rebooting to bootloader mode.
    """

    if experimental:
        "The --experimental switch is not required to run this command anymore and can be safely removed."

    with ctx.connect() as device:
        release_version = None
        if image:
            with open(image, "rb") as f:
                data = f.read()
        else:
            release_version, data = _download_latest_update(device)

        metadata = check_firmware_image(data)
        if release_version and release_version != metadata.version:
            raise CliException(
                f"The firmware image for the release {release_version} has the unexpected product "
                f"version {metadata.version}."
            )

        if isinstance(device, Nitrokey3Device):
            if not release_version:
                current_version = device.version()
                _print_version_warning(metadata, current_version)
            _print_update_warning()

            local_print("")
            _reboot_to_bootloader(device)
            local_print("")

            if platform.system() == "Darwin":
                # Currently there is an issue with device enumeration after reboot on macOS, see
                # <https://github.com/Nitrokey/pynitrokey/issues/145>.  To avoid this issue, we
                # cancel the command now and ask the user to run it again.
                local_print(
                    "Bootloader mode enabled. Please repeat this command to apply the update."
                )
                raise click.Abort()

            exc = None
            for t in Retries(3):
                logger.debug(f"Trying to connect to bootloader ({t})")
                try:
                    with ctx.await_bootloader() as bootloader:
                        _perform_update(bootloader, data)
                    break
                except McuBootConnectionError as e:
                    logger.debug("Received connection error", exc_info=True)
                    exc = e
            else:
                msgs = ["Failed to connect to Nitrokey 3 bootloader"]
                if platform.system() == "Linux":
                    msgs += ["Are the Nitrokey udev rules installed and active?"]
                raise CliException(*msgs, exc)
        elif isinstance(device, Nitrokey3Bootloader):
            _print_version_warning(metadata)
            _print_update_warning()
            _perform_update(device, data)
        else:
            raise CliException(f"Unexpected Nitrokey 3 device: {device}")

    local_print("")
    with ctx.await_device() as device:
        version = device.version()
        if version == metadata.version:
            local_print(f"Successfully updated the firmware to version {version}.")
        else:
            raise CliException(
                f"The firmware update to {metadata.version} was successful, but the firmware "
                f"is still reporting version {version}."
            )


def _download_latest_update(device: Nitrokey3Base) -> Tuple[Version, bytes]:
    try:
        update = get_repo().get_latest_update()
        logger.info(f"Latest firmware version: {update.tag}")
    except Exception as e:
        raise CliException("Failed to find latest firmware update", e)

    try:
        release_version = Version.from_v_str(update.tag)

        if isinstance(device, Nitrokey3Device):
            current_version = device.version()
            _print_download_warning(release_version, current_version)
        else:
            _print_download_warning(release_version)
    except ValueError as e:
        logger.warning("Failed to parse version from release tag", e)

    try:
        logger.info(f"Trying to download firmware update from URL: {update.url}")

        bar = DownloadProgressBar(desc=update.tag)
        data = update.read(callback=bar.update)
        bar.close()

        return (release_version, data)
    except Exception as e:
        raise CliException(f"Failed to download latest firmware update {update.tag}", e)


def _print_download_warning(
    release_version: Version,
    current_version: Optional[Version] = None,
) -> None:
    current_version_str = str(current_version) if current_version else "[unknown]"
    local_print(f"Current firmware version:  {current_version_str}")
    local_print(f"Latest firmware version:   {release_version}")

    if current_version and current_version > release_version:
        raise CliException(
            "The latest firmare release is older than the firmware on the device.",
            support_hint=False,
        )
    elif current_version and current_version == release_version:
        confirm(
            "You are already running the latest firmware release on the device.  Do you want "
            f"to continue and download the firmware version {release_version} anyway?",
            abort=True,
        )
    else:
        confirm(
            f"Do you want to download the firmware version {release_version}?",
            default=True,
            abort=True,
        )


def _print_version_warning(
    metadata: FirmwareMetadata,
    current_version: Optional[Version] = None,
) -> None:
    current_version_str = str(current_version) if current_version else "[unknown]"
    local_print(f"Current firmware version:  {current_version_str}")
    local_print(f"Updated firmware version:  {metadata.version}")

    if current_version:
        if current_version > metadata.version:
            raise CliException(
                "The firmware image is older than the firmware on the device.",
                support_hint=False,
            )
        elif current_version == metadata.version:
            if not confirm(
                "The version of the firmware image is the same as on the device.  Do you want "
                "to continue anyway?"
            ):
                raise click.Abort()


def _print_update_warning() -> None:
    local_print("")
    local_print(
        "Please do not remove the Nitrokey 3 or insert any other Nitrokey 3 devices "
        "during the update. Doing so may damage the Nitrokey 3."
    )
    if not confirm("Do you want to perform the firmware update now?"):
        logger.info("Update cancelled by user")
        raise click.Abort()


def _perform_update(device: Nitrokey3Bootloader, image: bytes) -> None:
    logger.debug("Starting firmware update")
    with ProgressBar(
        desc="Performing firmware update", unit="B", unit_scale=True
    ) as bar:
        result = device.update(image, callback=bar.update_sum)
    logger.debug(f"Firmware update finished with status {device.status}")

    if result:
        logger.debug("Firmware update finished successfully")
        device.reboot()
    else:
        (code, message) = device.status
        raise CliException(f"Firmware update failed with status code {code}: {message}")


@nk3.command()
@click.pass_obj
def version(ctx: Context) -> None:
    """Query the firmware version of the device."""
    with ctx.connect_device() as device:
        version = device.version()
        local_print(version)


@nk3.command()
@click.pass_obj
def wink(ctx: Context) -> None:
    """Send wink command to the device (blinks LED a few times)."""
    with ctx.connect_device() as device:
        device.wink()
