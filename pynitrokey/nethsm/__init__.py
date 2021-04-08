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
from .client.model.passphrase import Passphrase


class Role(enum.Enum):
    ADMINISTRATOR = "Administrator"
    OPERATOR = "Operator"
    METRICS = "Metrics"
    BACKUP = "Backup"

    @staticmethod
    def from_model(model_role):
        return Role.from_string(model_role.value)

    @staticmethod
    def from_string(s):
        for role in Role:
            if role.value == s:
                return role
        raise ValueError(f"Unsupported user role {s}")


class State(enum.Enum):
    UNPROVISIONED = "Unprovisioned"
    LOCKED = "Locked"
    OPERATIONAL = "Operational"


class User:
    def __init__(self, user_id, real_name, role):
        self.user_id = user_id
        self.real_name = real_name
        self.role = role


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

    def provision(self, unlock_passphrase, admin_passphrase, system_time):
        from .client.model.provision_request_data import ProvisionRequestData

        body = ProvisionRequestData(
            unlock_passphrase=Passphrase(unlock_passphrase),
            admin_passphrase=Passphrase(admin_passphrase),
            system_time=system_time,
        )
        try:
            self.get_api().provision_post(body=body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.UNPROVISIONED,
                messages={
                    400: "Malformed request data -- e. g. weak passphrase",
                },
            )

    def list_users(self):
        try:
            data = self.get_api().users_get()
            return [item["user"] for item in data.value]
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    401: "Invalid user name and/or password",
                },
            )

    def get_user(self, user_id):
        try:
            user = self.get_api().users_user_id_get(user_id=user_id)
            return User(
                user_id=user_id,
                real_name=user.real_name,
                role=Role.from_model(user.role),
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                message={
                    404: f"User {user_id} not found",
                },
            )

    def add_user(self, real_name, role, passphrase, user_id=None):
        from .client.model.user_post_data import UserPostData
        from .client.model.user_role import UserRole

        body = UserPostData(
            real_name=real_name,
            role=UserRole(role),
            passphrase=Passphrase(passphrase),
        )
        try:
            if user_id:
                self.get_api().users_user_id_put(user_id=user_id, body=body)
                return user_id
            else:
                self.get_api().users_post(body=body)
                # TODO: determine the user ID generated by the NetHSM
                return "[randomly generated user ID]"
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- e. g. weak passphrase",
                    409: f"Conflict -- a user with the ID {user_id} already exists",
                },
            )


@contextlib.contextmanager
def connect(host, version, username, password):
    nethsm = NetHSM(host, version, username, password)
    try:
        yield nethsm
    finally:
        nethsm.close()
