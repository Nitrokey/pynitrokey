#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Helper module used for supporting the scanning."""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from ...exceptions import SPSDKKeyError


def parse_plugin_config(plugin_conf: str) -> Tuple[str, str]:
    """Extract 'identifier' from plugin params and build the params back to original format.

    :param plugin_conf: Plugin configuration string as given on command line
    :return: Tuple with identifier and params
    """
    params_dict: Dict[str, str] = dict([tuple(p.split("=")) for p in plugin_conf.split(",")])  # type: ignore
    if "identifier" not in params_dict:
        raise SPSDKKeyError("Plugin parameter must contain 'identifier' key")
    identifier = params_dict.pop("identifier")
    params = ",".join([f"{key}={value}" for key, value in params_dict.items()])
    return identifier, params


@dataclass
class InterfaceParams:
    """Interface input parameters."""

    identifier: str
    is_defined: bool
    params: Optional[str] = None
    extra_params: Optional[str] = None
