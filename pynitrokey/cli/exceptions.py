# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

from typing import Any

from pynitrokey.helpers import local_critical


class CliException(Exception):
    def __init__(
        self,
        *messages: Any,
        support_hint: bool = True,
        ret_code: int = 1,
        **kwargs: Any,
    ) -> None:
        super().__init__("\n".join([str(message) for message in messages]))

        self.messages = messages
        self.support_hint = support_hint
        self.ret_code = ret_code
        self.kwargs = kwargs

    def show(self) -> None:
        local_critical(
            *self.messages,
            support_hint=self.support_hint,
            ret_code=self.ret_code,
            **self.kwargs,
        )
