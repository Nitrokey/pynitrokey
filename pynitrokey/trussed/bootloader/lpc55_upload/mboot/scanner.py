#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Helper module used for scanning the existing devices."""
from typing import List, Optional

from spsdk.exceptions import SPSDKError
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.interfaces.scanner_helper import InterfaceParams, parse_plugin_config


def get_mboot_interface(
    port: Optional[str] = None,
    usb: Optional[str] = None,
    sdio: Optional[str] = None,
    buspal: Optional[str] = None,
    lpcusbsio: Optional[str] = None,
    plugin: Optional[str] = None,
    timeout: int = 5000,
) -> MbootProtocolBase:
    """Get appropriate interface.

    'port', 'usb', 'sdio', 'lpcusbsio' parameters are mutually exclusive; one of them is required.

    :param port: name and speed of the serial port (format: name[,speed]), defaults to None
    :param usb: PID,VID of the USB interface, defaults to None
    :param sdio: SDIO path of the SDIO interface, defaults to None
    :param buspal: buspal interface settings, defaults to None
    :param timeout: timeout in milliseconds
    :param lpcusbsio: LPCUSBSIO spi or i2c config string
    :param plugin: Additional plugin to be used
    :return: Selected interface instance
    :raises SPSDKError: Only one of the appropriate interfaces must be specified
    :raises SPSDKError: When SPSDK-specific error occurs
    """
    # check that one and only one interface is defined
    interface_params: List[InterfaceParams] = []
    plugin_params = parse_plugin_config(plugin) if plugin else ("Unknown", "")
    interface_params.extend(
        [
            InterfaceParams(identifier="usb", is_defined=bool(usb), params=usb),
            InterfaceParams(identifier="uart", is_defined=bool(port and not buspal), params=port),
            InterfaceParams(
                identifier="buspal_spi",
                is_defined=bool(port and buspal and "spi" in buspal),
                params=port,
                extra_params=buspal,
            ),
            InterfaceParams(
                identifier="buspal_i2c",
                is_defined=bool(port and buspal and "i2c" in buspal),
                params=port,
                extra_params=buspal,
            ),
            InterfaceParams(
                identifier="usbsio_spi",
                is_defined=bool(lpcusbsio and "spi" in lpcusbsio),
                params=lpcusbsio,
            ),
            InterfaceParams(
                identifier="usbsio_i2c",
                is_defined=bool(lpcusbsio and "i2c" in lpcusbsio),
                params=lpcusbsio,
            ),
            InterfaceParams(identifier="sdio", is_defined=bool(sdio), params=sdio),
            InterfaceParams(
                identifier=plugin_params[0], is_defined=bool(plugin), params=plugin_params[1]
            ),
        ]
    )
    interface_params = [ifce for ifce in interface_params if ifce.is_defined]
    if len(interface_params) == 0:
        raise SPSDKError(
            "One of '--port', '--usb', '--sdio', '--lpcusbsio' or '--plugin' must be specified."
        )
    if len(interface_params) > 1:
        raise SPSDKError(
            "Only one of '--port', '--usb', '--sdio', '--lpcusbsio' or '--plugin must be specified."
        )
    interface = MbootProtocolBase.get_interface(interface_params[0].identifier)
    assert interface_params[0].params
    devices = interface.scan_from_args(
        params=interface_params[0].params,
        extra_params=interface_params[0].extra_params,
        timeout=timeout,
    )
    if len(devices) == 0:
        raise SPSDKError(f"Selected '{interface_params[0].identifier}' device not found.")
    if len(devices) > 1:
        raise SPSDKError(
            f"Multiple '{interface_params[0].identifier}' devices found: {len(devices)}"
        )
    return devices[0]
