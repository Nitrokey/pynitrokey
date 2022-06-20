# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import platform
from typing import Optional, Tuple

import click
from spsdk.mboot.exceptions import McuBootConnectionError

from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.nk3 import Context, reboot_to_bootloader
from pynitrokey.helpers import (
    DownloadProgressBar,
    ProgressBar,
    Retries,
    confirm,
    local_print,
)
from pynitrokey.nk3.base import Nitrokey3Base
from pynitrokey.nk3.bootloader import (
    FirmwareMetadata,
    Nitrokey3Bootloader,
    check_firmware_image,
)
from pynitrokey.nk3.device import Nitrokey3Device
from pynitrokey.nk3.updates import REPOSITORY, get_firmware_update
from pynitrokey.nk3.utils import Version

logger = logging.getLogger(__name__)


def update(ctx: Context, image: Optional[str]) -> Version:
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
            reboot_to_bootloader(device)
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

        return metadata.version


def _download_latest_update(device: Nitrokey3Base) -> Tuple[Version, bytes]:
    try:
        release = REPOSITORY.get_latest_release()
        logger.info(f"Latest firmware version: {release.tag}")
    except Exception as e:
        raise CliException("Failed to find latest firmware release", e)

    try:
        release_version = Version.from_v_str(release.tag)

        if isinstance(device, Nitrokey3Device):
            current_version = device.version()
            _print_download_warning(release_version, current_version)
        else:
            _print_download_warning(release_version)
    except ValueError as e:
        logger.warning("Failed to parse version from release tag", e)

    try:
        update = get_firmware_update(release)
    except Exception as e:
        raise CliException("Failed to find firmware update for release {release}", e)

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
