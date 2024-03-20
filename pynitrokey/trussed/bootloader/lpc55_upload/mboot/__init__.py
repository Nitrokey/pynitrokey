#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing communication with the MCU Bootloader."""

from typing import Union

from .interfaces.buspal import MbootBuspalI2CInterface, MbootBuspalSPIInterface
from .interfaces.sdio import MbootSdioInterface
from .interfaces.uart import MbootUARTInterface
from .interfaces.usb import MbootUSBInterface
from .interfaces.usbsio import MbootUsbSioI2CInterface, MbootUsbSioSPIInterface
from .mcuboot import McuBoot

MbootDeviceTypes = Union[
    MbootBuspalI2CInterface,
    MbootBuspalSPIInterface,
    MbootSdioInterface,
    MbootUARTInterface,
    MbootUSBInterface,
    MbootUsbSioI2CInterface,
    MbootUsbSioSPIInterface,
]
