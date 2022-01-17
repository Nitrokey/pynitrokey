# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import itertools
import logging
import platform
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, TypeVar

import click

from pynitrokey.helpers import local_critical, local_print
from pynitrokey.nk3 import list as list_nk3
from pynitrokey.nk3 import open as open_nk3
from pynitrokey.nk3.base import Nitrokey3Base
from pynitrokey.nk3.bootloader import (
    FirmwareMetadata,
    Nitrokey3Bootloader,
    check_firmware_image,
)
from pynitrokey.nk3.device import BootMode, Nitrokey3Device
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
                device.reboot(BootMode.BOOTROM)
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
@click.argument("image")
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
)
@click.pass_obj
def update(ctx: Context, image: str, experimental: bool) -> None:
    """
    Update the firmware of the device using the given image.

    This command requires that exactly one Nitrokey 3 in bootloader or firmware mode is connected.
    The user is asked to confirm the operation before the update is started.  The Nitrokey 3 may
    not be removed during the update.  Also, additional Nitrokey 3 devices may not be connected
    during the update.

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

    with open(image, "rb") as f:
        data = f.read()
    metadata = check_firmware_image(data)

    with ctx.connect() as device:
        if isinstance(device, Nitrokey3Device):
            current_version = device.version()
            _print_update_warning(metadata, current_version)

            local_print("")
            local_print(
                "Please press the touch button to reboot the device into bootloader mode ..."
            )
            device.reboot(BootMode.BOOTROM)

            local_print("")

            if platform.system() == "Darwin":
                # Currently there is an issue with device enumeration after reboot on macOS, see
                # <https://github.com/Nitrokey/pynitrokey/issues/145>.  To avoid this issue, we
                # cancel the command now and ask the user to run it again.
                local_print(
                    "Bootloader mode enabled. Please repeat this command to apply the update."
                )
                raise click.Abort()

            with _await_bootloader(ctx) as bootloader:
                _perform_update(bootloader, data)
        elif isinstance(device, Nitrokey3Bootloader):
            _print_update_warning(metadata)
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


def _print_update_warning(
    metadata: FirmwareMetadata,
    current_version: Optional[Version] = None,
) -> None:
    current_version_str = str(current_version) if current_version else "[unknown]"
    local_print(f"Current firmware version:  {current_version_str}")
    local_print(f"Updated firmware version:  {metadata.version}")
    if current_version and current_version > metadata.version:
        local_critical(
            "The firmware image is older than the firmware on the device.",
            support_hint=False,
        )
    local_print("")
    local_print(
        "Please do not remove the Nitrokey 3 or insert any other Nitrokey 3 devices "
        "during the update."
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
