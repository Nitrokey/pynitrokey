# -*- coding: utf-8 -*-
#
# Copyright 2021-2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
from contextlib import contextmanager
from typing import Any, Callable, Iterator, List, Optional

from click import Abort

from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.nk3 import Context
from pynitrokey.helpers import DownloadProgressBar, ProgressBar, confirm, local_print
from pynitrokey.nk3.updates import Updater, UpdateUi
from pynitrokey.nk3.utils import Version

logger = logging.getLogger(__name__)


class UpdateCli(UpdateUi):
    def __init__(self) -> None:
        self._version_printed = False

    def error(self, *msgs: Any) -> Exception:
        return CliException(*msgs)

    def abort(self, *msgs: Any) -> Exception:
        return CliException(*msgs, support_hint=False)

    def abort_downgrade(self, current: Version, image: Version) -> Exception:
        self._print_firmware_versions(current, image)
        return self.abort(
            "The firmware image is older than the firmware on the device."
        )

    def abort_pynitrokey_version(
        self, current: Version, required: Version
    ) -> Exception:
        return self.abort(
            f"This update requires pynitrokey version {required} (current: {current}). "
            "Please update pynitrokey to install the update."
        )

    def confirm_download(self, current: Optional[Version], new: Version) -> None:
        confirm(
            f"Do you want to download the firmware version {new}?",
            default=True,
            abort=True,
        )

    def confirm_pynitrokey_version(self, current: Version, required: Version) -> None:
        local_print(
            f"This update requires pynitrokey version {required} (current: {current})."
        )
        local_print("Using an outdated pynitrokey version is strongly discouraged.")
        if not confirm(
            "Do you want to continue with an outdated pynitrokey version at your own risk?"
        ):
            logger.info("Update cancelled by user")
            raise Abort()

    def confirm_update(self, current: Optional[Version], new: Version) -> None:
        self._print_firmware_versions(current, new)
        local_print("")
        local_print(
            "Please do not remove the Nitrokey 3 or insert any other Nitrokey 3 devices "
            "during the update. Doing so may damage the Nitrokey 3."
        )
        if not confirm("Do you want to perform the firmware update now?"):
            logger.info("Update cancelled by user")
            raise Abort()

    def confirm_update_same_version(self, version: Version) -> None:
        self._print_firmware_versions(version, version)
        if not confirm(
            "The version of the firmware image is the same as on the device.  Do you want "
            "to continue anyway?"
        ):
            raise Abort()

    def confirm_extra_information(self, txt: List[str]) -> None:
        if txt:
            local_print("\n".join(txt))
            if not confirm("Have you read these information? Do you want to continue?"):
                raise Abort()

    def request_repeated_update(self) -> Exception:
        local_print(
            "Bootloader mode enabled. Please repeat this command to apply the update."
        )
        return Abort()

    def request_bootloader_confirmation(self) -> None:
        local_print("")
        local_print(
            "Please press the touch button to reboot the device into bootloader mode ..."
        )
        local_print("")

    @contextmanager
    def download_progress_bar(self, desc: str) -> Iterator[Callable[[int, int], None]]:
        with DownloadProgressBar(desc) as bar:
            yield bar.update

    @contextmanager
    def update_progress_bar(self) -> Iterator[Callable[[int, int], None]]:
        with ProgressBar(
            desc="Perform firmware update", unit="B", unit_scale=True
        ) as bar:
            yield bar.update_sum

    @contextmanager
    def finalization_progress_bar(self) -> Iterator[Callable[[int, int], None]]:
        with ProgressBar(desc="Finalize upgrade", unit="%", unit_scale=False) as bar:
            yield bar.update_sum

    def _print_firmware_versions(
        self, current: Optional[Version], new: Optional[Version]
    ) -> None:
        if not self._version_printed:
            current_str = str(current) if current else "[unknown]"
            local_print(f"Current firmware version:  {current_str}")
            local_print(f"Updated firmware version:  {new}")
            self._version_printed = True


def update(
    ctx: Context,
    image: Optional[str],
    version: Optional[str],
    ignore_pynitrokey_version: bool,
) -> Version:
    with ctx.connect() as device:
        updater = Updater(UpdateCli(), ctx.await_bootloader, ctx.await_device)
        return updater.update(device, image, version, ignore_pynitrokey_version)
