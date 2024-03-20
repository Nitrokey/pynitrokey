#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Generic commands implementation."""
from abc import ABC, abstractmethod


class CmdResponseBase(ABC):
    """Response base format class."""

    @abstractmethod
    def __str__(self) -> str:
        """Get object info."""

    @property
    @abstractmethod
    def value(self) -> int:
        """Return a integer representation of the response."""


class CmdPacketBase(ABC):
    """COmmand protocol base."""

    @abstractmethod
    def to_bytes(self, padding: bool = True) -> bytes:
        """Serialize CmdPacket into bytes.

        :param padding: If True, add padding to specific size
        :return: Serialized object into bytes
        """
