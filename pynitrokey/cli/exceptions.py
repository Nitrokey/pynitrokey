# -*- coding: utf-8 -*-
#
# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from pynitrokey.helpers import local_critical


class CliException(Exception):
    def __init__(
        self, *messages, support_hint: bool = True, ret_code: int = 1, **kwargs
    ):
        super().__init__("\n".join([str(message) for message in messages]))

        self.messages = messages
        self.support_hint = support_hint
        self.ret_code = ret_code
        self.kwargs = kwargs

    def show(self):
        local_critical(
            *self.messages,
            support_hint=self.support_hint,
            ret_code=self.ret_code,
            **self.kwargs,
        )
