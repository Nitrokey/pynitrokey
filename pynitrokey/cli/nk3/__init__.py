# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from typing import List, Optional, TypeVar

import click

from pynitrokey.helpers import local_critical, local_print
from pynitrokey.nk3 import list as list_nk3
from pynitrokey.nk3.base import Nitrokey3Base
from pynitrokey.nk3.device import Nitrokey3Device

T = TypeVar("T", bound="Nitrokey3Base")


class Context:
    def __init__(self, path: Optional[str]) -> None:
        self.path = path

    def list(self) -> List[Nitrokey3Base]:
        devices = []
        for device in list_nk3():
            if not self.path or self.path == device.path:
                devices.append(device)
        return devices

    def _select_unique(self, name: str, devices: List[T]) -> T:
        if len(devices) == 0:
            msg = f"No {name} device found"
            if self.path:
                msg += f" at path {self.path}"
            raise click.ClickException(msg)

        if len(devices) > 1:
            raise click.ClickException(
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
@click.pass_obj
def reboot(ctx: Context) -> None:
    """Reboot the key."""
    with ctx.connect() as device:
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
@click.pass_obj
def test(ctx: Context) -> None:
    """Run some tests on all connected Nitrokey 3 devices."""
    from .test import log_devices, run_tests

    devices = ctx.list()

    if len(devices) == 0:
        log_devices()
        local_critical("No connected Nitrokey 3 devices found")

    local_print(f"Found {len(devices)} Nitrokey 3 device(s):")
    for device in devices:
        local_print(f"- {device.name} at {device.path}")

    results = []
    for device in devices:
        results.append(run_tests(device))

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
