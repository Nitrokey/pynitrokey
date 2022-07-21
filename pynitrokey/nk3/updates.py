# -*- coding: utf-8 -*-
#
# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import platform
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional, Tuple, Union

from spsdk.mboot.exceptions import McuBootConnectionError

from pynitrokey.helpers import Retries
from pynitrokey.nk3 import Nitrokey3Base
from pynitrokey.nk3.bootloader import (
    FirmwareMetadata,
    Nitrokey3Bootloader,
    Variant,
    detect_variant,
    get_firmware_filename_pattern,
    validate_firmware_image,
)
from pynitrokey.nk3.device import BootMode, Nitrokey3Device
from pynitrokey.nk3.exceptions import TimeoutException
from pynitrokey.nk3.utils import Version
from pynitrokey.updates import Asset, Release, Repository

logger = logging.getLogger(__name__)

REPOSITORY_OWNER = "Nitrokey"
REPOSITORY_NAME = "nitrokey-3-firmware"
REPOSITORY = Repository(owner=REPOSITORY_OWNER, name=REPOSITORY_NAME)


def get_firmware_update(release: Release, variant: Variant) -> Asset:
    pattern = get_firmware_filename_pattern(variant)
    return release.require_asset(pattern)


class UpdateUi(ABC):
    @abstractmethod
    def error(self, *msgs: Any) -> Exception:
        pass

    @abstractmethod
    def abort(self, *msgs: Any) -> Exception:
        pass

    @abstractmethod
    def abort_downgrade(self, current: Version, image: Version) -> Exception:
        pass

    @abstractmethod
    def confirm_download(self, current: Optional[Version], new: Version) -> None:
        pass

    @abstractmethod
    def confirm_update(self, current: Optional[Version], new: Version) -> None:
        pass

    @abstractmethod
    def confirm_update_same_version(self, version: Version) -> None:
        pass

    @abstractmethod
    def request_repeated_update(self) -> Exception:
        pass

    @abstractmethod
    def request_bootloader_confirmation(self) -> None:
        pass

    @abstractmethod
    def prompt_variant(self) -> Variant:
        pass

    @abstractmethod
    @contextmanager
    def download_progress_bar(self, desc: str) -> Iterator[Callable[[int, int], None]]:
        pass

    @abstractmethod
    @contextmanager
    def update_progress_bar(self) -> Iterator[Callable[[int, int], None]]:
        pass


class Updater:
    def __init__(
        self, ui: UpdateUi, await_bootloader: Callable[[], Nitrokey3Bootloader]
    ) -> None:
        self.ui = ui
        self.await_bootloader = await_bootloader

    def update(
        self,
        device: Nitrokey3Base,
        image: Optional[str],
        variant: Optional[Variant],
    ) -> Version:
        current_version = (
            device.version() if isinstance(device, Nitrokey3Device) else None
        )
        logger.info(f"Firmware version before update: {current_version or ''}")
        (new_version, firmware_or_release) = self._prepare_update(
            image, current_version, variant
        )
        self.ui.confirm_update(current_version, new_version)

        if isinstance(device, Nitrokey3Device):
            self.ui.request_bootloader_confirmation()
            try:
                device.reboot(BootMode.BOOTROM)
            except TimeoutException:
                raise self.ui.abort(
                    "The reboot was not confirmed with the touch button"
                )

            if platform.system() == "Darwin":
                # Currently there is an issue with device enumeration after reboot on macOS, see
                # <https://github.com/Nitrokey/pynitrokey/issues/145>.  To avoid this issue, we
                # cancel the command now and ask the user to run it again.
                raise self.ui.request_repeated_update()

            exc = None
            for t in Retries(3):
                logger.debug(f"Trying to connect to bootloader ({t})")
                try:
                    with self.await_bootloader() as bootloader:
                        metadata, data = self._get_update(
                            firmware_or_release, current_version, bootloader.variant
                        )
                        self._perform_update(bootloader, data)
                    break
                except McuBootConnectionError as e:
                    logger.debug("Received connection error", exc_info=True)
                    exc = e
            else:
                msgs = ["Failed to connect to Nitrokey 3 bootloader"]
                if platform.system() == "Linux":
                    msgs += ["Are the Nitrokey udev rules installed and active?"]
                raise self.ui.error(*msgs, exc)
        elif isinstance(device, Nitrokey3Bootloader):
            metadata, data = self._get_update(
                firmware_or_release, current_version, device.variant
            )
            self._perform_update(device, data)
        else:
            raise self.ui.error(f"Unexpected Nitrokey 3 device: {device}")

        return metadata.version

    def _prepare_update(
        self,
        image: Optional[str],
        current_version: Optional[Version],
        variant: Optional[Variant],
    ) -> Tuple[Version, Union[Tuple[FirmwareMetadata, bytes], Release]]:
        if image:
            if not variant:
                variant = detect_variant(image)
            if not variant:
                variant = self.ui.prompt_variant()

            with open(image, "rb") as f:
                data = f.read()
            metadata = validate_firmware_image(variant, data)
            self._validate_version(current_version, metadata.version)
            return (metadata.version, (metadata, data))
        else:
            try:
                release = REPOSITORY.get_latest_release()
                logger.info(f"Latest firmware version: {release}")
            except Exception as e:
                raise self.ui.error("Failed to find latest firmware release", e)

            try:
                release_version = Version.from_v_str(release.tag)
            except ValueError as e:
                raise self.ui.error("Failed to parse version from release tag", e)
            self._validate_version(current_version, release_version)
            self.ui.confirm_download(current_version, release_version)
            return (release_version, release)

    def _get_update(
        self,
        firmware_or_release: Union[Tuple[FirmwareMetadata, bytes], Release],
        current_version: Optional[Version],
        variant: Variant,
    ) -> Tuple[FirmwareMetadata, bytes]:
        if isinstance(firmware_or_release, Release):
            release = firmware_or_release
            return self._download_update(release, current_version, variant)
        else:
            return firmware_or_release

    def _download_update(
        self, release: Release, current_version: Optional[Version], variant: Variant
    ) -> Tuple[FirmwareMetadata, bytes]:
        try:
            update = get_firmware_update(release, variant)
        except Exception as e:
            raise self.ui.error(
                f"Failed to find firmware image for release {release} and variant {variant}",
                e,
            )

        try:
            logger.info(f"Trying to download firmware update from URL: {update.url}")

            with self.ui.download_progress_bar(update.tag) as callback:
                data = update.read(callback=callback)
        except Exception as e:
            raise self.ui.error(
                f"Failed to download latest firmware update {update.tag}", e
            )

        metadata = validate_firmware_image(variant, data)
        if Version.from_v_str(release.tag) != metadata.version:
            raise self.ui.error(
                f"The firmware image for the release {release} has the unexpected product "
                f"version {metadata.version}."
            )

        return (metadata, data)

    def _validate_version(
        self,
        current_version: Optional[Version],
        new_version: Version,
    ) -> None:
        logger.info(f"Current firmware version: {current_version}")
        logger.info(f"Updated firmware version: {new_version}")

        if current_version:
            if current_version > new_version:
                raise self.ui.abort_downgrade(current_version, new_version)
            elif current_version == new_version:
                self.ui.confirm_update_same_version(current_version)

    def _perform_update(self, device: Nitrokey3Bootloader, image: bytes) -> None:
        logger.debug("Starting firmware update")
        with self.ui.update_progress_bar() as callback:
            try:
                device.update(image, callback=callback)
            except Exception as e:
                raise self.ui.error("Failed to perform firmware update", e)
        logger.debug("Firmware update finished successfully")
