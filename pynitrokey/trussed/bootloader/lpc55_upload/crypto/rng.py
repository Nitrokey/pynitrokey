#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Implementation for getting random numbers."""

# Used security modules


from secrets import randbelow, token_bytes, token_hex


def random_bytes(length: int) -> bytes:
    """Return a random byte string with specified length.

    :param length: The length in bytes
    :return: Random bytes
    """
    return token_bytes(length)


def random_hex(length: int) -> str:
    """Return a random hex string with specified length.

    :param length: The length in bytes
    :return: Random hex
    """
    return token_hex(length)


def rand_below(upper_bound: int) -> int:
    """Return a random number in range [0, upper_bound].

    :param upper_bound: Upper bound
    :return: Random number
    """
    return randbelow(upper_bound)
