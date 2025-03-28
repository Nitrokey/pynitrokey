# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from typing import Iterable

from .Card import Card

def readers() -> Iterable[Card]: ...
