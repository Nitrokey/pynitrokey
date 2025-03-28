# Copyright 2019 SoloKeys Developers
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT


class BasePyNKException(Exception):
    pass


class NonUniqueDeviceError(Exception):
    """When specifying a potentially destructive command...

    we check that either there is exactly one applicable device,
    or demand passing the serial number (same for ST DFU bootloader
    and Nitrokey bootloader+firmware.
    """

    pass


class NoSoloFoundError(Exception):
    """Can signify no Solo, or missing udev rule on Linux."""

    pass
