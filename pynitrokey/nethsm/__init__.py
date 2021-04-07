# -*- coding: utf-8 -*-
#
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import contextlib
import enum

from . import client
from .client import ApiException


class Role(enum.Enum):
    ADMINISTRATOR = "Administrator"
    OPERATOR = "Operator"
    METRICS = "Metrics"
    BACKUP = "Backup"


class State(enum.Enum):
    UNPROVISIONED = "Unprovisioned"
    LOCKED = "Locked"
    OPERATIONAL = "Operational"


def _handle_api_exception(e, messages={}, roles=[], state=None):
    if e.status == 403 and roles:
        roles = [role.value for role in roles]
        message = "Access denied -- this operation requires the role " + roles.join(
            " or "
        )
    elif e.status == 412 and state:
        message = f"Precondition failed -- this operation can only be used on a NetHSM in the state {state.value}"
    elif e.status in messages:
        message = messages[e.status]
    else:
        message = f"Unexpected API error {e.status}: {e.reason}"

    raise NetHSMError(message)


class NetHSMError(Exception):
    def __init__(self, message):
        super().__init__(message)


class NetHSM:
    def __init__(self, host, version, username, password):
        self.host = host
        self.version = version
        self.username = username
        self.password = password

        base_url = f"https://{host}/api/{version}"
        config = client.Configuration(
            host=base_url, username=username, password=password
        )
        self.client = client.ApiClient(configuration=config)

    def close(self):
        self.client.close()

    def get_api(self):
        from .client.api.default_api import DefaultApi

        return DefaultApi(self.client)

    def unlock(self, passphrase):
        from .client.model.passphrase import Passphrase
        from .client.model.unlock_request_data import UnlockRequestData

        body = UnlockRequestData(Passphrase(passphrase))
        try:
            self.get_api().unlock_post(body=body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.LOCKED,
                messages={
                    403: "Access denied -- wrong unlock passphrase",
                },
            )

    def lock(self):
        try:
            self.get_api().lock_post()
        except ApiException as e:
            # TODO: API docs say 403, but demo server gives 401, see nethsm issue #99
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={401: "Access denied"},
            )


@contextlib.contextmanager
def connect(host, version, username, password):
    nethsm = NetHSM(host, version, username, password)
    try:
        yield nethsm
    finally:
        nethsm.close()
