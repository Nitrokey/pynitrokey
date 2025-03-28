# Copyright 2019 SoloKeys Developers
# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Python Library for Nitrokey devices."""

import pathlib

__version_path__ = pathlib.Path(__file__).parent.resolve().absolute() / "VERSION"
__version__ = open(__version_path__).read().strip()


del pathlib
__all__ = ["client", "commands", "dfu", "enums", "exceptions", "helpers", "operations"]
