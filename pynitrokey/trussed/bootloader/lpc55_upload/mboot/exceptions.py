#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Exceptions used in the MBoot module."""

from ..exceptions import SPSDKError
from .error_codes import StatusCode

########################################################################################################################
# McuBoot Exceptions
########################################################################################################################


class McuBootError(SPSDKError):
    """MBoot Module: Base Exception."""

    fmt = "MBoot: {description}"


class McuBootCommandError(McuBootError):
    """MBoot Module: Command Exception."""

    fmt = "MBoot: {cmd_name} interrupted -> {description}"

    def __init__(self, cmd: str, value: int) -> None:
        """Initialize the Command Error exception.

        :param cmd: Name of the command causing the exception
        :param value: Response value causing the exception
        """
        super().__init__()
        self.cmd_name = cmd
        self.error_value = value
        self.description = (
            StatusCode.get_description(value)
            if value in StatusCode.tags()
            else f"Unknown Error 0x{value:08X}"
        )

    def __str__(self) -> str:
        return self.fmt.format(cmd_name=self.cmd_name, description=self.description)


class McuBootDataAbortError(McuBootError):
    """MBoot Module: Data phase aborted by sender."""

    fmt = "Mboot: Data aborted by sender"


class McuBootConnectionError(McuBootError):
    """MBoot Module: Connection Exception."""

    fmt = "MBoot: Connection issue -> {description}"
