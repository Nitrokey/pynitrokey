#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""MBoot protocol base."""
from spsdk.utils.interfaces.protocol.protocol_base import ProtocolBase


class MbootProtocolBase(ProtocolBase):
    """MBoot protocol base class."""

    allow_abort: bool = False
    need_data_split: bool = True
