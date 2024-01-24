# -*- coding: utf-8 -*-
#
# Copyright 2021-2024 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
from abc import ABC, abstractmethod
from typing import Callable, Generic, Optional, Sequence, TypeVar

import click

from pynitrokey.cli.exceptions import CliException
from pynitrokey.helpers import Retries, local_print, require_windows_admin
from pynitrokey.trussed.admin_app import BootMode
from pynitrokey.trussed.base import NitrokeyTrussedBase
from pynitrokey.trussed.bootloader import NitrokeyTrussedBootloader
from pynitrokey.trussed.device import NitrokeyTrussedDevice
from pynitrokey.trussed.exceptions import TimeoutException

from .test import TestCase

T = TypeVar("T", bound=NitrokeyTrussedBase)
Bootloader = TypeVar("Bootloader", bound=NitrokeyTrussedBootloader)
Device = TypeVar("Device", bound=NitrokeyTrussedDevice)

logger = logging.getLogger(__name__)


class Context(ABC, Generic[Bootloader, Device]):
    def __init__(
        self,
        path: Optional[str],
        bootloader_type: type[Bootloader],
        device_type: type[Device],
    ) -> None:
        self.path = path
        self.bootloader_type = bootloader_type
        self.device_type = device_type

    @property
    @abstractmethod
    def device_name(self) -> str:
        ...

    @property
    @abstractmethod
    def test_cases(self) -> Sequence[TestCase]:
        ...

    @abstractmethod
    def open(self, path: str) -> Optional[NitrokeyTrussedBase]:
        ...

    @abstractmethod
    def list_all(self) -> Sequence[NitrokeyTrussedBase]:
        ...

    def list(self) -> Sequence[NitrokeyTrussedBase]:
        if self.path:
            device = self.open(self.path)
            if device:
                return [device]
            else:
                return []
        else:
            return self.list_all()

    def connect(self) -> NitrokeyTrussedBase:
        return self._select_unique(self.device_name, self.list())

    def connect_device(self) -> Device:
        devices = [
            device for device in self.list() if isinstance(device, self.device_type)
        ]
        return self._select_unique(self.device_name, devices)

    def await_device(
        self,
        retries: Optional[int] = None,
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> Device:
        return self._await(self.device_name, self.device_type, retries, callback)

    def await_bootloader(
        self,
        retries: Optional[int] = None,
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> Bootloader:
        # mypy does not allow abstract types here, but this is still valid
        return self._await(
            f"{self.device_name} bootloader", self.bootloader_type, retries, callback
        )

    def _select_unique(self, name: str, devices: Sequence[T]) -> T:
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

    def _await(
        self,
        name: str,
        ty: type[T],
        retries: Optional[int],
        callback: Optional[Callable[[int, int], None]] = None,
    ) -> T:
        if retries is None:
            retries = 30
        for t in Retries(retries):
            logger.debug(f"Searching {name} device ({t})")
            devices = [device for device in self.list() if isinstance(device, ty)]
            if len(devices) == 0:
                if callback:
                    callback(int((t.i / retries) * 100), 100)
                logger.debug(f"No {name} device found, continuing")
                continue
            if len(devices) > 1:
                raise CliException(f"Multiple {name} devices found")
            if callback:
                callback(100, 100)
            return devices[0]

        raise CliException(f"No {name} device found")


def prepare_group() -> None:
    require_windows_admin()


def add_commands(group: click.Group) -> None:
    group.add_command(list)
    group.add_command(reboot)
    group.add_command(rng)
    group.add_command(status)
    group.add_command(test)
    group.add_command(version)


@click.command()
@click.pass_obj
def list(ctx: Context[Bootloader, Device]) -> None:
    """List all devices."""
    local_print(f":: '{ctx.device_name}' keys")
    for device in ctx.list_all():
        with device as device:
            uuid = device.uuid()
            if uuid:
                local_print(f"{device.path}: {device.name} {uuid}")
            else:
                local_print(f"{device.path}: {device.name}")


@click.command()
@click.option(
    "--bootloader",
    is_flag=True,
    help="Reboot the device into bootloader mode",
)
@click.pass_obj
def reboot(ctx: Context[Bootloader, Device], bootloader: bool) -> None:
    """
    Reboot the key.

    Per default, the key will reboot into regular firmware mode.  If the --bootloader option
    is set, a key can boot from firmware mode to bootloader mode.  Booting into
    bootloader mode has to be confirmed by pressing the touch button.
    """
    with ctx.connect() as device:
        if bootloader:
            if isinstance(device, NitrokeyTrussedDevice):
                success = reboot_to_bootloader(device)
            else:
                raise CliException(
                    "A device in bootloader mode can only reboot into firmware mode.",
                    support_hint=False,
                )
        else:
            success = device.reboot()

    if not success:
        raise CliException(
            "The connected device cannot be rebooted automatically.  Remove and reinsert the "
            "device to reboot it.",
            support_hint=False,
        )


def reboot_to_bootloader(device: NitrokeyTrussedDevice) -> bool:
    local_print(
        "Please press the touch button to reboot the device into bootloader mode ..."
    )
    try:
        return device.admin.reboot(BootMode.BOOTROM)
    except TimeoutException:
        raise CliException(
            "The reboot was not confirmed with the touch button.",
            support_hint=False,
        )


@click.command()
@click.option(
    "-l",
    "--length",
    "length",
    default=57,
    help="The length of the generated data (default: 57)",
)
@click.pass_obj
def rng(ctx: Context[Bootloader, Device], length: int) -> None:
    """Generate random data on the device."""
    with ctx.connect_device() as device:
        while length > 0:
            rng = device.admin.rng()
            local_print(rng[:length].hex())
            length -= len(rng)


@click.command()
@click.pass_obj
def status(ctx: Context[Bootloader, Device]) -> None:
    """Query the device status."""
    with ctx.connect_device() as device:
        uuid = device.uuid()
        if uuid is not None:
            local_print(f"UUID:               {uuid}")

        version = device.admin.version()
        local_print(f"Firmware version:   {version}")

        status = device.admin.status()
        if status.init_status is not None:
            local_print(f"Init status:        {status.init_status}")
        if status.ifs_blocks is not None:
            local_print(f"Free blocks (int):  {status.ifs_blocks}")
        if status.efs_blocks is not None:
            local_print(f"Free blocks (ext):  {status.efs_blocks}")
        if status.variant is not None:
            local_print(f"Variant:            {status.variant.name}")


@click.command()
@click.option(
    "--pin",
    "pin",
    help="The FIDO2 PIN of the device (if enabled)",
)
@click.option(
    "--only",
    "only",
    help="Run only the specified tests (may not be used with --all, --include or --exclude)",
)
@click.option(
    "--all",
    "all",
    is_flag=True,
    default=False,
    help="Run all tests (except those specified with --exclude)",
)
@click.option(
    "--include",
    "include",
    help="Also run the specified tests",
)
@click.option(
    "--exclude",
    "exclude",
    help="Do not run the specified tests",
)
@click.option(
    "--list",
    "list_",
    is_flag=True,
    default=False,
    help="List the selected tests instead of running them",
)
@click.pass_obj
def test(
    ctx: Context[Bootloader, Device],
    pin: Optional[str],
    only: Optional[str],
    all: bool,
    include: Optional[str],
    exclude: Optional[str],
    list_: bool,
) -> None:
    """Run some tests on all connected devices."""
    from pynitrokey.cli.trussed.test import (
        TestContext,
        TestSelector,
        list_tests,
        log_devices,
        log_system,
        run_tests,
    )

    test_selector = TestSelector(all=all)
    if only:
        if all or include or exclude:
            raise CliException(
                "--only may not be used together with --all, --include or --exclude.",
                support_hint=False,
            )
        test_selector.only = only.split(",")
    if include:
        test_selector.include = include.split(",")
    if exclude:
        test_selector.exclude = exclude.split(",")

    if list_:
        list_tests(test_selector, ctx.test_cases)
        return

    log_system()
    devices = ctx.list()

    if len(devices) == 0:
        log_devices()
        raise CliException(f"No connected {ctx.device_name} devices found")

    local_print(f"Found {len(devices)} {ctx.device_name} device(s):")
    for device in devices:
        local_print(f"- {device.name} at {device.path}")

    results = []
    test_ctx = TestContext(pin=pin)
    for device in devices:
        results.append(
            run_tests(
                test_ctx,
                device,
                test_selector,
                ctx.test_cases,
            )
        )

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


@click.command()
@click.pass_obj
def version(ctx: Context[Bootloader, Device]) -> None:
    """Query the firmware version of the device."""
    with ctx.connect_device() as device:
        version = device.admin.version()
        local_print(version)
