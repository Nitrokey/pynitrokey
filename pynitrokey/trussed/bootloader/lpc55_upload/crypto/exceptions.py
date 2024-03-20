#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Exceptions used in the Crypto module."""

from spsdk.exceptions import SPSDKError


class SPSDKPCryptoError(SPSDKError):
    """General SPSDK Crypto Error."""


class SPSDKKeysNotMatchingError(SPSDKPCryptoError):
    """Key pair not matching error."""
