# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import itertools
import logging
import os.path
import platform
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, TypeVar

import click
from spsdk.mboot.exceptions import McuBootConnectionError

from pynitrokey.helpers import ProgressBar, local_critical, local_print
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
from pynitrokey.nk3.updates import get_latest_update, get_update
from pynitrokey.nk3.utils import Version

T = TypeVar("T", bound="Nitrokey3Base")

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
            local_critical(msg)

        if len(devices) > 1:
            local_critical(
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


@click.group()
@click.option("-p", "--path", "path", help="The path of the Nitrokey 3 device")
@click.pass_context
def nk3(ctx: click.Context, path: Optional[str]) -> None:
    """Interact with Nitrokey 3, see subcommands."""
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
                local_print(
                    "Please press the touch button to reboot the device into bootloader mode ..."
                )
                try:
                    device.reboot(BootMode.BOOTROM)
                except TimeoutException:
                    local_critical(
                        "The reboot was not confirmed with the touch button.",
                        support_hint=False,
                    )
            else:
                local_critical(
                    "A Nitrokey 3 device in bootloader mode can only reboot into firmware mode."
                )
        else:
            device.reboot()


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
    """Generate random data on the key."""
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
        local_critical("No connected Nitrokey 3 devices found")

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
        local_critical(f"Test failed for {failure} device(s)")


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
    if version:
        try:
            update = get_update(version)
        except Exception as e:
            local_critical(f"Failed to find firmware update {version}", e)
    else:
        try:
            update = get_latest_update()
        except Exception as e:
            local_critical("Failed to find latest firmware update", e)

    bar = ProgressBar(desc=f"Download {update.tag}", unit="B", unit_scale=True)

    try:
        if os.path.isdir(path):
            path = update.download_to_dir(path, overwrite=force, callback=bar.update)
        else:
            if not force and os.path.exists(path):
                local_critical(
                    f"{path} already exists.  Use --force to overwrite the file."
                )
            else:
                with open(path, "wb") as f:
                    update.download(f, callback=bar.update)

        bar.close()

        local_print(f"Successfully downloaded firmware release {update.tag} to {path}")
    except Exception as e:
        local_critical(f"Failed to download firmware update {update.tag}", e)


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
        local_critical("Failed to parse and validate firmware image", e)

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

    This feature is experimental on MS Windows.
    """

    if platform.system() == "Windows" and not experimental:
        local_critical(
            "We experience some issues with this operation on Windows. "
            "If possible please run it on another operating system or wait for the further updates. "
            "Please pass --experimental switch to force running it anyway."
        )
        raise click.Abort()

    with ctx.connect() as device:
        release_version = None
        if image:
            with open(image, "rb") as f:
                data = f.read()
        else:
            try:
                update = get_latest_update()
                logger.info(f"Latest firmware version: {update.tag}")
            except Exception as e:
                local_critical("Failed to find latest firmware update", e)

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
                logger.info(
                    f"Trying to download firmware update from URL: {update.url}"
                )

                bar = ProgressBar(
                    desc=f"Download {update.tag}", unit="B", unit_scale=True
                )
                data = update.read(callback=bar.update)
                bar.close()
            except Exception as e:
                local_critical(
                    f"Failed to download latest firmware update {update.tag}", e
                )
                return

        metadata = check_firmware_image(data)
        if release_version and release_version != metadata.version:
            local_critical(
                f"The firmware image for the release {release_version} has the unexpected product "
                f"version {metadata.version}."
            )

        if isinstance(device, Nitrokey3Device):
            if not release_version:
                current_version = device.version()
                _print_version_warning(metadata, current_version)
            _print_update_warning()

            local_print("")
            local_print(
                "Please press the touch button to reboot the device into bootloader mode ..."
            )
            try:
                device.reboot(BootMode.BOOTROM)
            except TimeoutException:
                local_critical(
                    "The reboot was not confirmed with the touch button.",
                    support_hint=False,
                )

            local_print("")

            if platform.system() == "Darwin":
                # Currently there is an issue with device enumeration after reboot on macOS, see
                # <https://github.com/Nitrokey/pynitrokey/issues/145>.  To avoid this issue, we
                # cancel the command now and ask the user to run it again.
                local_print(
                    "Bootloader mode enabled. Please repeat this command to apply the update."
                )
                raise click.Abort()

            retries = 3
            exc = None
            for i in range(retries):
                logger.debug(
                    f"Trying to connect to bootloader, try {i + 1} of {retries}"
                )
                try:
                    with _await_bootloader(ctx) as bootloader:
                        _perform_update(bootloader, data)
                    break
                except McuBootConnectionError as e:
                    logger.debug("Received connection error", exc_info=True)
                    exc = e
                    if i + 1 < retries:
                        time.sleep(0.5)
            else:
                msgs = ["Failed to connect to Nitrokey 3 bootloader"]
                if platform.system() == "Linux":
                    msgs += ["Are the Nitrokey udev rules installed and active?"]
                local_critical(
                    *msgs,
                    exc,
                )
        elif isinstance(device, Nitrokey3Bootloader):
            _print_version_warning(metadata)
            _print_update_warning()
            _perform_update(device, data)
        else:
            local_critical(f"Unexpected Nitrokey 3 device: {device}")

    local_print("")
    with _await_device(ctx) as device:
        version = device.version()
        if version == metadata.version:
            local_print(f"Successfully updated the firmware to version {version}.")
        else:
            local_critical(
                f"The firmware update to {metadata.version} was successful, but the firmware "
                f"is still reporting version {version}."
            )


def _await_device(ctx: Context) -> Nitrokey3Device:
    # TODO: refactor into context
    logger.debug("Waiting for device ...")
    retries = 10
    for i in range(retries):
        logger.debug(f"Try {i + 1} of {retries}")
        bootloaders = [
            device for device in ctx.list() if isinstance(device, Nitrokey3Device)
        ]
        if len(bootloaders) == 0:
            time.sleep(0.5)
            logger.debug("No device found, continuing")
            continue
        if len(bootloaders) > 1:
            local_critical("Multiple devices found")
        return bootloaders[0]

    local_critical("No Nitrokey 3 device found.")
    raise Exception("Unreachable")


def _await_bootloader(ctx: Context) -> Nitrokey3Bootloader:
    logger.debug("Waiting for bootloader ...")
    retries = 10
    for i in range(retries):
        logger.debug(f"Try {i + 1} of {retries}")
        bootloaders = [
            device for device in ctx.list() if isinstance(device, Nitrokey3Bootloader)
        ]
        if len(bootloaders) == 0:
            time.sleep(0.5)
            logger.debug("No bootloader device found, continuing")
            continue
        if len(bootloaders) > 1:
            local_critical("Multiple bootloader devices found")
        return bootloaders[0]

    local_critical("No Nitrokey 3 bootloader device found.")
    raise Exception("Unreachable")


def _print_download_warning(
    release_version: Version,
    current_version: Optional[Version] = None,
) -> None:
    current_version_str = str(current_version) if current_version else "[unknown]"
    local_print(f"Current firmware version:  {current_version_str}")
    local_print(f"Latest firmware version:   {release_version}")

    if current_version and current_version > release_version:
        local_critical(
            "The latest firmare release is older than the firmware on the device.",
            support_hint=False,
        )
    elif current_version and current_version == release_version:
        click.confirm(
            "You are already running the latest firmware release on the device.  Do you want "
            f"to continue and download the firmware version {release_version} anyway?",
            abort=True,
        )
    else:
        click.confirm(
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
            local_critical(
                "The firmware image is older than the firmware on the device.",
                support_hint=False,
            )
        elif current_version == metadata.version:
            if not click.confirm(
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
    if not click.confirm("Do you want to perform the firmware update now?"):
        logger.info("Update cancelled by user")
        raise click.Abort()


def _perform_update(device: Nitrokey3Bootloader, image: bytes) -> None:
    logger.debug("Starting firmware update")

    with ThreadPoolExecutor() as executor:
        indicators = itertools.cycle(["/", "-", "\\", "|"])
        future = executor.submit(device.update, image)
        while not future.done():
            print(
                f"\r[{next(indicators)}] Performing firmware update "
                "(may take several minutes) ... ",
                end="",
            )
            time.sleep(0.1)
        print("done")

        if future.result():
            logger.debug("Firmware update finished successfully")
            device.reboot()
        else:
            (code, message) = device.status
            local_critical(f"Firmware update failed with status code {code}: {message}")


@nk3.command()
@click.pass_obj
def version(ctx: Context) -> None:
    """Query the firmware version of the key."""
    with ctx.connect_device() as device:
        version = device.version()
        local_print(version)


@nk3.command()
@click.pass_obj
def wink(ctx: Context) -> None:
    """Send wink command to the key (blinks LED a few times)."""
    with ctx.connect_device() as device:
        device.wink()
