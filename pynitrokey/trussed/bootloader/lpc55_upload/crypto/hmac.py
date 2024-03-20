#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation for HMAC packet authentication."""

from cryptography.exceptions import InvalidSignature

# Used security modules
from cryptography.hazmat.primitives import hmac as hmac_cls

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash_algorithm


def hmac(key: bytes, data: bytes, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256) -> bytes:
    """Return a HMAC from data with specified key and algorithm.

    :param key: The key in bytes format
    :param data: Input data in bytes format
    :param algorithm: Algorithm type for HASH function (sha256, sha384, sha512, ...)
    :return: HMAC bytes
    """
    hmac_obj = hmac_cls.HMAC(key, get_hash_algorithm(algorithm))
    hmac_obj.update(data)
    return hmac_obj.finalize()


def hmac_validate(
    key: bytes,
    data: bytes,
    signature: bytes,
    algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256,
) -> bool:
    """Return a HMAC from data with specified key and algorithm.

    :param key: The key in bytes format
    :param data: Input data in bytes format
    :param signature: HMAC signature to validate
    :param algorithm: Algorithm type for HASH function (sha256, sha384, sha512, ...)
    :return: HMAC bytes
    """
    hmac_obj = hmac_cls.HMAC(key=key, algorithm=get_hash_algorithm(algorithm))
    hmac_obj.update(data)
    try:
        hmac_obj.verify(signature=signature)
        return True
    except InvalidSignature:
        return False
