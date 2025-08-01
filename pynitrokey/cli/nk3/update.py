# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import logging
from collections.abc import Set
from contextlib import contextmanager
from typing import Any, Callable, Iterator, List, Optional

from click import Abort
from nitrokey.trussed import Model, TrussedBootloader, TrussedDevice, Version
from nitrokey.trussed.admin_app import Status
from nitrokey.trussed.updates import DeviceHandler, Updater, UpdateUi, Warning

from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.nk3 import Context
from pynitrokey.helpers import DownloadProgressBar, ProgressBar, confirm, local_print

logger = logging.getLogger(__name__)


class UpdateCli(UpdateUi):
    def __init__(self, confirm_continue: bool = False) -> None:
        self._version_printed = False
        self._confirm_continue = confirm_continue

    def error(self, *msgs: Any) -> Exception:
        return CliException(*msgs)

    def abort(self, *msgs: Any) -> Exception:
        return CliException(*msgs, support_hint=False)

    def raise_warning(self, warning: Warning) -> Exception:
        return self.abort(
            f"{warning.message}\nTo ignore this warning and install the update at your own risk,"
            f" set the --ignore-warning {warning.value} option."
        )

    def show_warning(self, warning: Warning) -> None:
        logger.warning(f"Ignoring warning {warning.value}")
        local_print(f"Warning: {warning.message}")
        local_print(
            f"Note: The update will continue as --ignore-warning {warning.value} has been set."
        )

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
        if self._confirm_continue:
            return

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

        if self._confirm_continue:
            return

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

    def pre_bootloader_hint(self) -> None:
        pass

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


class ContextDeviceHandler(DeviceHandler):
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    def await_bootloader(self, model: Model) -> TrussedBootloader:
        assert model == self.ctx.model
        return self.ctx.await_bootloader()

    def await_device(
        self,
        model: Model,
        wait_retries: Optional[int],
        callback: Optional[Callable[[int, int], None]],
    ) -> TrussedDevice:
        assert model == self.ctx.model
        return self.ctx.await_device(wait_retries, callback)


def update(
    ctx: Context,
    image: Optional[str],
    version: Optional[str],
    ignore_pynitrokey_version: bool,
    ignore_warnings: Set[Warning],
    confirm_continue: bool,
) -> tuple[Version, Status]:
    with ctx.connect() as device:
        updater = Updater(
            ui=UpdateCli(confirm_continue),
            device_handler=ContextDeviceHandler(ctx),
            ignore_warnings=ignore_warnings,
        )
        return updater.update(device, image, version, ignore_pynitrokey_version)
