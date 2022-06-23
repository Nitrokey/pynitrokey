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
from typing import Optional, Tuple, Union

import click
from spsdk.mboot.exceptions import McuBootConnectionError

from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.nk3 import VARIANT_CHOICE, Context, reboot_to_bootloader
from pynitrokey.helpers import (
    DownloadProgressBar,
    ProgressBar,
    Retries,
    confirm,
    local_print,
    prompt,
)
from pynitrokey.nk3.bootloader import (
    FirmwareMetadata,
    Nitrokey3Bootloader,
    Variant,
    detect_variant,
    validate_firmware_image,
)
from pynitrokey.nk3.device import Nitrokey3Device
from pynitrokey.nk3.updates import REPOSITORY, get_firmware_update
from pynitrokey.nk3.utils import Version
from pynitrokey.updates import Release

logger = logging.getLogger(__name__)


def update(ctx: Context, image: Optional[str], variant: Optional[Variant]) -> Version:
    with ctx.connect() as device:
        current_version = (
            device.version() if isinstance(device, Nitrokey3Device) else None
        )
        firmware_or_release = _prepare_update(image, current_version, variant)
        _print_update_warning()

        if isinstance(device, Nitrokey3Device):
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
                        metadata, data = _get_update(
                            firmware_or_release, current_version, bootloader.variant
                        )
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
            metadata, data = _get_update(
                firmware_or_release, current_version, bootloader.variant
            )
            _perform_update(device, data)
        else:
            raise CliException(f"Unexpected Nitrokey 3 device: {device}")

        return metadata.version


def _prepare_update(
    image: Optional[str], current_version: Optional[Version], variant: Optional[Variant]
) -> Union[Tuple[FirmwareMetadata, bytes], Release]:
    if image:
        if not variant:
            variant = detect_variant(image)
        if not variant:
            variant = Variant.from_str(
                prompt("Firmware image variant", type=VARIANT_CHOICE)
            )

        with open(image, "rb") as f:
            data = f.read()
        metadata = validate_firmware_image(variant, data)
        _print_version_warning(metadata, current_version)
        return (metadata, data)
    else:
        try:
            release = REPOSITORY.get_latest_release()
            logger.info(f"Latest firmware version: {release}")
        except Exception as e:
            raise CliException("Failed to find latest firmware release", e)

        try:
            release_version = Version.from_v_str(release.tag)
        except ValueError as e:
            raise CliException("Failed to parse version from release tag", e)
        _print_download_warning(release_version, current_version)
        return release


def _get_update(
    firmware_or_release: Union[Tuple[FirmwareMetadata, bytes], Release],
    current_version: Optional[Version],
    variant: Variant,
) -> Tuple[FirmwareMetadata, bytes]:
    if isinstance(firmware_or_release, Release):
        release = firmware_or_release
        return _download_update(release, current_version, variant)
    else:
        return firmware_or_release


def _download_update(
    release: Release, current_version: Optional[Version], variant: Variant
) -> Tuple[FirmwareMetadata, bytes]:
    try:
        update = get_firmware_update(release, variant)
    except Exception as e:
        raise CliException(
            f"Failed to find firmware image for release {release} and variant {variant}",
            e,
        )

    try:
        logger.info(f"Trying to download firmware update from URL: {update.url}")

        bar = DownloadProgressBar(desc=update.tag)
        data = update.read(callback=bar.update)
        bar.close()
    except Exception as e:
        raise CliException(f"Failed to download latest firmware update {update.tag}", e)

    metadata = validate_firmware_image(variant, data)
    if Version.from_v_str(release.tag) != metadata.version:
        raise CliException(
            f"The firmware image for the release {release} has the unexpected product "
            f"version {metadata.version}."
        )

    return (metadata, data)


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
    with ProgressBar(desc="Perform firmware update", unit="B", unit_scale=True) as bar:
        try:
            device.update(image, callback=bar.update_sum)
        except Exception as e:
            raise CliException("Failed to perform firmware update", e)
    logger.debug("Firmware update finished successfully")
