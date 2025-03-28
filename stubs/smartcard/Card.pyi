# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from .CardConnection import CardConnection

class Card:
    def createConnection(self) -> CardConnection: ...
