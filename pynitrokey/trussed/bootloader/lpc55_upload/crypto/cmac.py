#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation for CMAC packet authentication."""

# Used security modules
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import cmac as cmac_cls
from cryptography.hazmat.primitives.ciphers import algorithms


def cmac(key: bytes, data: bytes) -> bytes:
    """Return a CMAC from data with specified key and algorithm.

    :param key: The key in bytes format
    :param data: Input data in bytes format
    :return: CMAC bytes
    """
    cmac_obj = cmac_cls.CMAC(algorithm=algorithms.AES(key))
    cmac_obj.update(data)
    return cmac_obj.finalize()


def cmac_validate(key: bytes, data: bytes, signature: bytes) -> bool:
    """Return a CMAC from data with specified key and algorithm.

    :param key: The key in bytes format
    :param data: Input data in bytes format
    :param signature: CMAC signature to validate
    :return: CMAC bytes
    """
    cmac_obj = cmac_cls.CMAC(algorithm=algorithms.AES(key))
    cmac_obj.update(data)
    try:
        cmac_obj.verify(signature=signature)
        return True
    except InvalidSignature:
        return False
