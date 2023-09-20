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
import json
import re

import click
import requests

from . import client
from .client import ApiException


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

    @staticmethod
    def from_model(model_state):
        return State.from_string(model_state.value)

    @staticmethod
    def from_string(s):
        for state in State:
            if state.value == s:
                return state
        raise ValueError(f"Unsupported system state {s}")


class LogLevel(enum.Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    @staticmethod
    def from_model(model_log_level):
        return LogLevel.from_string(model_log_level.value)

    @staticmethod
    def from_string(s):
        for log_level in LogLevel:
            if log_level.value == s:
                return log_level
        raise ValueError(f"Unsupported log level {s}")


class UnattendedBootStatus(enum.Enum):
    ON = "on"
    OFF = "off"


class KeyType(enum.Enum):
    RSA = "RSA"
    CURVE25519 = "Curve25519"
    EC_P224 = "EC_P224"
    EC_P256 = "EC_P256"
    EC_P384 = "EC_P384"
    EC_P521 = "EC_P521"
    GENERIC = "Generic"


class KeyMechanism(enum.Enum):
    RSA_DECRYPTION_RAW = "RSA_Decryption_RAW"
    RSA_DECRYPTION_PKCS1 = "RSA_Decryption_PKCS1"
    RSA_DECRYPTION_OAEP_MD5 = "RSA_Decryption_OAEP_MD5"
    RSA_DECRYPTION_OAEP_SHA1 = "RSA_Decryption_OAEP_SHA1"
    RSA_DECRYPTION_OAEP_SHA224 = "RSA_Decryption_OAEP_SHA224"
    RSA_DECRYPTION_OAEP_SHA256 = "RSA_Decryption_OAEP_SHA256"
    RSA_DECRYPTION_OAEP_SHA384 = "RSA_Decryption_OAEP_SHA384"
    RSA_DECRYPTION_OAEP_SHA512 = "RSA_Decryption_OAEP_SHA512"
    RSA_SIGNATURE_PKCS1 = "RSA_Signature_PKCS1"
    RSA_SIGNATURE_PSS_MD5 = "RSA_Signature_PSS_MD5"
    RSA_SIGNATURE_PSS_SHA1 = "RSA_Signature_PSS_SHA1"
    RSA_SIGNATURE_PSS_SHA224 = "RSA_Signature_PSS_SHA224"
    RSA_SIGNATURE_PSS_SHA256 = "RSA_Signature_PSS_SHA256"
    RSA_SIGNATURE_PSS_SHA384 = "RSA_Signature_PSS_SHA384"
    RSA_SIGNATURE_PSS_SHA512 = "RSA_Signature_PSS_SHA512"
    EDDSA_SIGNATURE = "EdDSA_Signature"
    ECDSA_SIGNATURE = "ECDSA_Signature"
    AES_ENCRYPTION_CBC = "AES_Encryption_CBC"
    AES_DECRYPTION_CBC = "AES_Decryption_CBC"


class EncryptMode(enum.Enum):
    AES_CBC = "AES_CBC"


class DecryptMode(enum.Enum):
    RAW = "RAW"
    PKCS1 = "PKCS1"
    OAEP_MD5 = "OAEP_MD5"
    OAEP_SHA1 = "OAEP_SHA1"
    OAEP_SHA224 = "OAEP_SHA224"
    OAEP_SHA256 = "OAEP_SHA256"
    OAEP_SHA384 = "OAEP_SHA384"
    OAEP_SHA512 = "OAEP_SHA512"
    AES_CBC = "AES_CBC"


class SignMode(enum.Enum):
    PKCS1 = "PKCS1"
    PSS_MD5 = "PSS_MD5"
    PSS_SHA1 = "PSS_SHA1"
    PSS_SHA224 = "PSS_SHA224"
    PSS_SHA256 = "PSS_SHA256"
    PSS_SHA384 = "PSS_SHA384"
    PSS_SHA512 = "PSS_SHA512"
    EDDSA = "EdDSA"
    ECDSA = "ECDSA"


class TlsKeyType(enum.Enum):
    RSA = "RSA"
    CURVE25519 = "Curve25519"
    EC_P224 = "EC_P224"
    EC_P256 = "EC_P256"
    EC_P384 = "EC_P384"
    EC_P521 = "EC_P521"


class SystemInfo:
    def __init__(self, firmware_version, software_version, hardware_version, build_tag):
        self.firmware_version = firmware_version
        self.software_version = software_version
        self.hardware_version = hardware_version
        self.build_tag = build_tag


class User:
    def __init__(self, user_id, real_name, role):
        self.user_id = user_id
        self.real_name = real_name
        self.role = role


class Key:
    def __init__(
        self, key_id, mechanisms, type, operations, tags, modulus, public_exponent, data
    ):
        self.key_id = key_id
        self.mechanisms = mechanisms
        self.type = type
        self.operations = operations
        self.tags = tags
        self.modulus = modulus
        self.public_exponent = public_exponent
        self.data = data


def _handle_api_exception(e, messages={}, roles=[], state=None):
    # give priority to custom messages
    if e.status in messages:
        message = messages[e.status]
        raise NetHSMError(message)

    if e.status == 401 and roles:
        message = "Unauthorized -- invalid username or password"
    elif e.status == 403 and roles:
        roles = [role.value for role in roles]
        message = "Access denied -- this operation requires the role " + " or ".join(
            roles
        )
    elif e.status == 405:
        # 405 "Method Not Allowed" mostly happens when the UserID or KeyID contains a character
        # - that ends the path of the URL like a question mark '?' :
        #   /api/v1/keys/?/cert will hit the keys listing endpoint instead of the key/{KeyID}/cert endpoint
        # - that doesn't count as a path parameter like a slash '/' :
        #   /api/v1/keys///cert will be interpreted as /api/v1/keys/cert with cert as the KeyID
        message = "The ID you provided contains invalid characters"
    elif e.status == 406:
        message = "Invalid content type requested"
    elif e.status == 412 and state:
        message = f"Precondition failed -- this operation can only be used on a NetHSM in the state {state.value}"
    elif e.status == 429:
        message = (
            "Too many requests -- you may have tried the wrong credentials too often"
        )
    else:
        message = f"Unexpected API error {e.status}: {e.reason}"

    if e.api_response:
        try:
            body = None
            # "custom" requests
            if hasattr(e.api_response, "text") and e.api_response.text != "":
                body = json.loads(e.api_response.text)
            # generated code
            elif (
                hasattr(e.api_response, "response")
                and e.api_response.response.data != ""
            ):
                body = json.loads(e.api_response.response.data)
            if body is not None and "message" in body:
                message += "\n" + body["message"]
        except json.JSONDecodeError:
            pass

    raise NetHSMError(message)


class NetHSMError(Exception):
    def __init__(self, message):
        super().__init__(message)


class NetHSM:
    def __init__(self, host, version, username, password, verify_tls=True):
        from .client.components.security_schemes import security_scheme_basic
        from .client.configurations.api_configuration import SecuritySchemeInfo
        from .client.servers.server_0 import Server0, VariablesDict

        self.host = host
        self.version = version
        self.username = username
        self.password = password

        security_info = SecuritySchemeInfo(
            {
                "basic": security_scheme_basic.Basic(
                    user_id=username,
                    password=password,
                )
            }
        )

        server_config = {
            "servers/0": Server0(variables=VariablesDict(host=host, version=version))
        }
        config = client.ApiConfiguration(
            server_info=server_config, security_scheme_info=security_info
        )
        config.verify_ssl = verify_tls
        self.client = client.ApiClient(configuration=config)

        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = verify_tls

    def close(self):
        self.client.close()
        self.session.close()

    def request(
        self, method, endpoint, params=None, data=None, mime_type=None, json=None
    ):
        url = f"https://{self.host}/api/{self.version}/{endpoint}"
        headers = {}
        if mime_type:
            headers["Content-Type"] = mime_type
        response = self.session.request(
            method, url, params=params, data=data, headers=headers, json=json
        )
        if not response.ok:
            raise ApiException(
                status=response.status_code,
                reason=response.reason,
                api_response=response,
            )
        return response

    def get_api(self):
        from .client.apis.tags.default_api import DefaultApi

        return DefaultApi(self.client)

    def get_location(self, headers):
        return headers.get("location")

    def get_key_id_from_location(self, headers):
        location = self.get_location(headers)
        key_id_match = re.fullmatch(f"/api/{self.version}/keys/(.*)", location)
        if not key_id_match:
            raise click.ClickException("Could not determine the ID of the new key")
        return key_id_match[1]

    def get_user_id_from_location(self, headers):
        location = self.get_location(headers)
        user_id_match = re.fullmatch(f"/api/{self.version}/users/(.*)", location)
        if not user_id_match:
            raise click.ClickException("Could not determine the ID of the new user")
        return user_id_match[1]

    def unlock(self, passphrase):
        from .client.components.schema.unlock_request_data import UnlockRequestDataDict

        request_body = UnlockRequestDataDict(
            passphrase=passphrase,
        )
        try:
            self.get_api().unlock_post(request_body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.LOCKED,
                messages={
                    # Doc says 400 could happen when the passphrase is invalid?
                    400: "Access denied -- wrong unlock passphrase",
                    403: "Access denied -- wrong unlock passphrase",
                },
            )

    def lock(self):
        try:
            self.get_api().lock_post()
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def provision(self, unlock_passphrase, admin_passphrase, system_time):
        from .client.components.schema.provision_request_data import (
            ProvisionRequestDataDict,
        )

        request_body = ProvisionRequestDataDict(
            unlockPassphrase=unlock_passphrase,
            adminPassphrase=admin_passphrase,
            systemTime=system_time,
        )
        try:
            self.get_api().provision_post(request_body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.UNPROVISIONED,
                messages={
                    400: "Malformed request data -- e. g. weak passphrase or invalid time",
                },
            )

    def list_users(self):
        try:
            response = self.get_api().users_get()
            return [item["user"] for item in response.body]
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def get_user(self, user_id):
        from .client.paths.users_user_id.get.path_parameters import PathParametersDict

        path_params = PathParametersDict(UserID=user_id)
        try:
            response = self.get_api().users_user_id_get(path_params=path_params)
            return User(
                user_id=user_id,
                real_name=response.body.realName,
                role=Role.from_string(response.body.role),
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"User {user_id} not found",
                },
            )

    def add_user(self, real_name, role, passphrase, user_id=None):
        from .client.components.schema.user_post_data import UserPostDataDict
        from .client.paths.users_user_id.put.path_parameters import PathParametersDict

        body = UserPostDataDict(
            realName=real_name,
            role=role,
            passphrase=passphrase,
        )
        try:
            if user_id:
                path_params = PathParametersDict(UserID=user_id)
                self.get_api().users_user_id_put(path_params=path_params, body=body)
                return user_id
            else:
                response = self.get_api().users_post(body=body)
                return self.get_user_id_from_location(response.response.getheaders())
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

    def delete_user(self, user_id):
        from .client.paths.users_user_id.delete.path_parameters import (
            PathParametersDict,
        )

        try:
            path_params = PathParametersDict(UserID=user_id)
            self.get_api().users_user_id_delete(path_params=path_params)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"User {user_id} not found",
                },
            )

    def set_passphrase(self, user_id, passphrase):
        from .client.components.schema.user_passphrase_post_data import (
            UserPassphrasePostDataDict,
        )
        from .client.paths.users_user_id_passphrase.post.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id)
        body = UserPassphrasePostDataDict(passphrase=passphrase)
        try:
            self.get_api().users_user_id_passphrase_post(
                path_params=path_params, body=body
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    400: "Bad request -- e. g. weak passphrase",
                    404: f"User {user_id} not found",
                },
            )

    def list_operator_tags(self, user_id):
        from .client.paths.users_user_id_tags.get.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id)
        try:
            response = self.get_api().users_user_id_tags_get(path_params=path_params)
            return response.body
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"User {user_id} not found",
                },
            )

    def add_operator_tag(self, user_id, tag):
        from .client.paths.users_user_id_tags_tag.put.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id, Tag=tag)
        try:
            return self.get_api().users_user_id_tags_tag_put(path_params=path_params)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    304: f"Tag is already present for {user_id}",
                    400: "Invalid tag format or user is not an operator",
                    404: f"User {user_id} not found",
                },
            )

    def delete_operator_tag(self, user_id, tag):
        from .client.paths.users_user_id_tags_tag.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(UserID=user_id, Tag=tag)
        try:
            return self.get_api().users_user_id_tags_tag_delete(path_params=path_params)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"User {user_id} or tag {tag} not found",
                },
            )

    def add_key_tag(self, key_id, tag):
        from .client.paths.keys_key_id_restrictions_tags_tag.put.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id, Tag=tag)
        try:
            return self.get_api().keys_key_id_restrictions_tags_tag_put(
                path_params=path_params
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    304: f"Tag is already present for {key_id}",
                    400: f"Tag {tag} has invalid format",
                    404: f"Key {key_id} not found",
                },
            )

    def delete_key_tag(self, key_id, tag):
        from .client.paths.keys_key_id_restrictions_tags_tag.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id, Tag=tag)
        try:
            return self.get_api().keys_key_id_restrictions_tags_tag_delete(
                path_params=path_params
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"Key {key_id} or tag {tag} not found",
                },
            )

    def get_info(self):
        try:
            response = self.get_api().info_get()
            return (response.body["vendor"], response.body["product"])
        except ApiException as e:
            _handle_api_exception(e)

    def get_state(self):
        try:
            response = self.get_api().health_state_get()
            return State.from_string(response.body["state"])
        except ApiException as e:
            _handle_api_exception(e)

    def get_random_data(self, n):
        from .client.components.schema.random_request_data import RandomRequestDataDict

        body = RandomRequestDataDict(length=n)
        try:
            response = self.get_api().random_post(body=body)
            return response.body["random"]
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.OPERATOR],
                messages={
                    400: "Invalid length. Must be between 1 and 1024",
                },
            )

    def get_metrics(self):
        try:
            response = self.get_api().metrics_get()
            return response.body
        except ApiException as e:
            _handle_api_exception(e, state=State.OPERATIONAL, roles=[Role.METRICS])

    def list_keys(self, filter):
        from .client.paths.keys.get.query_parameters import QueryParametersDict

        try:
            if filter:
                query_params = QueryParametersDict(filter=filter)
                response = self.get_api().keys_get(query_params=query_params)
            else:
                response = self.get_api().keys_get()
            return [item["key"] for item in response.body]
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
            )

    def get_key(self, key_id):
        from .client.paths.keys_key_id.get.path_parameters import PathParametersDict

        path_params = PathParametersDict(KeyID=key_id)
        try:
            response = self.get_api().keys_key_id_get(path_params=path_params)
            key = response.body
            return Key(
                key_id=key_id,
                mechanisms=[mechanism for mechanism in key.mechanisms],
                type=key.type,
                operations=key.operations,
                tags=[tag for tag in key.restrictions["tags"]]
                if "tags" in key.restrictions.keys()
                else None,
                modulus=getattr(key.key, "modulus", None),
                public_exponent=getattr(key.key, "public_exponent", None),
                data=getattr(key.key, "data", None),
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Key {key_id} not found",
                },
            )

    def get_key_public_key(self, key_id):
        from .client.paths.keys_key_id_public_pem.get.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        try:
            response = self.get_api().keys_key_id_public_pem_get(
                path_params=path_params, skip_deserialization=True
            )
            return response.response.data.decode("utf-8")
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Key {key_id} not found",
                },
            )

    def add_key(
        self, key_id, type, mechanisms, tags, prime_p, prime_q, public_exponent, data
    ):
        from .client.components.schema.key_private_data import KeyPrivateDataDict
        from .client.components.schema.key_restrictions import KeyRestrictionsDict
        from .client.components.schema.private_key import PrivateKeyDict
        from .client.components.schema.tag_list import TagListTuple

        if type == "RSA":
            key_data = KeyPrivateDataDict(
                primeP=prime_p,
                primeQ=prime_q,
                publicExponent=public_exponent,
            )
        else:
            key_data = KeyPrivateDataDict(data=data)

        if tags:
            body = PrivateKeyDict(
                type=type,
                mechanisms=mechanisms,
                key=key_data,
                restrictions=KeyRestrictionsDict(
                    tags=TagListTuple([tag for tag in tags])
                ),
            )
        else:
            body = PrivateKeyDict(
                type=type,
                mechanisms=mechanisms,
                key=key_data,
            )

        try:
            if key_id:
                from .client.paths.keys_key_id.put.path_parameters import (
                    PathParametersDict,
                )

                path_params = PathParametersDict(KeyID=key_id)
                self.get_api().keys_key_id_put(
                    path_params=path_params,
                    body=body,
                    content_type="application/json",
                )
                return key_id
            else:
                response = self.get_api().keys_post(
                    body=body,
                    content_type="application/json",
                    skip_deserialization=True,
                )
                return self.get_key_id_from_location(response.response.getheaders())
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- specified properties are invalid",
                    409: f"Conflict -- a key with the ID {key_id} already exists",
                },
            )

    def delete_key(self, key_id):
        from .client.paths.keys_key_id.delete.path_parameters import PathParametersDict

        path_params = PathParametersDict(KeyID=key_id)
        try:
            self.get_api().keys_key_id_delete(path_params=path_params)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"Key {key_id} not found",
                },
            )

    def generate_key(self, type, mechanisms, length, key_id):
        from .client.components.schema.key_generate_request_data import (
            KeyGenerateRequestDataDict,
        )
        from .client.components.schema.key_mechanisms import KeyMechanismsTuple

        if key_id:
            body = KeyGenerateRequestDataDict(
                type=type,
                mechanisms=KeyMechanismsTuple(mechanisms),
                length=length,
                id=key_id,
            )
        else:
            body = KeyGenerateRequestDataDict(
                type=type,
                mechanisms=KeyMechanismsTuple(mechanisms),
                length=length,
            )
        try:
            response = self.get_api().keys_generate_post(
                body=body, skip_deserialization=True
            )
            return key_id or self.get_key_id_from_location(
                response.response.getheaders()
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid input data",
                    409: f"Conflict -- a key with the ID {key_id} already exists",
                },
            )

    def get_config_logging(self):
        try:
            response = self.get_api().config_logging_get()
            return response.body
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_config_network(self):
        try:
            response = self.get_api().config_network_get()
            return response.body
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_config_time(self):
        try:
            response = self.get_api().config_time_get()
            return response.body.time
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_config_unattended_boot(self):
        try:
            return self.get_api().config_unattended_boot_get().body.status
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_public_key(self):
        try:
            response = self.get_api().config_tls_public_pem_get(
                skip_deserialization=True
            )
            return response.response.data.decode("utf-8")
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_certificate(self):
        try:
            response = self.get_api().config_tls_cert_pem_get(skip_deserialization=True)
            return response.response.data.decode("utf-8")
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_key_certificate(self, key_id):
        try:
            from .client.paths.keys_key_id_cert.get.path_parameters import (
                PathParametersDict,
            )

            path_params = PathParametersDict(KeyID=key_id)

            response = self.get_api().keys_key_id_cert_get(
                path_params=path_params, skip_deserialization=True
            )
            return response.response.data.decode("utf-8")
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Certificate for key {key_id} not found",
                    # The API returns a 406 if there is no certificate or if the key does not exist
                    406: f"Certificate for key {key_id} not found",
                },
            )

    def set_certificate(self, cert):
        try:
            self.request(
                "PUT",
                "config/tls/cert.pem",
                data=cert,
                mime_type="application/x-pem-file",
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad Request -- invalid certificate",
                },
            )

    def set_key_certificate(self, key_id, cert, mime_type):
        try:
            self.request("PUT", f"keys/{key_id}/cert", data=cert, mime_type=mime_type)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad Request -- invalid certificate",
                    404: f"Key {key_id} not found",
                    409: f"Conflict -- key {key_id} already has a certificate",
                    415: "Invalid mime type",
                },
            )

    def delete_key_certificate(self, key_id):
        from .client.paths.keys_key_id_cert.delete.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        try:
            return self.get_api().keys_key_id_cert_delete(path_params=path_params)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"Key {key_id} not found",
                    409: f"Certificate for key {key_id} not found",
                },
            )

    def csr(
        self,
        country,
        state_or_province,
        locality,
        organization,
        organizational_unit,
        common_name,
        email_address,
    ):
        body = {
            "countryName": country,
            "stateOrProvinceName": state_or_province,
            "localityName": locality,
            "organizationName": organization,
            "organizationalUnitName": organizational_unit,
            "commonName": common_name,
            "emailAddress": email_address,
        }
        try:
            response = self.get_api().config_tls_csr_pem_post(
                body=body, skip_deserialization=True
            )
            return response.response.data.decode("utf-8")
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def generate_tls_key(
        self,
        type,
        length,
    ):
        from .client.components.schema.tls_key_generate_request_data import (
            TlsKeyGenerateRequestDataDict,
        )

        if type == "RSA":
            body = TlsKeyGenerateRequestDataDict(
                type=type,
                length=length,
            )
        else:
            body = TlsKeyGenerateRequestDataDict(
                type=type,
            )

        try:
            return self.get_api().config_tls_generate_post(body=body)
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def key_csr(
        self,
        key_id,
        country,
        state_or_province,
        locality,
        organization,
        organizational_unit,
        common_name,
        email_address,
    ):
        from .client.paths.keys_key_id_csr_pem.post.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        body = {
            "countryName": country,
            "stateOrProvinceName": state_or_province,
            "localityName": locality,
            "organizationName": organization,
            "organizationalUnitName": organizational_unit,
            "commonName": common_name,
            "emailAddress": email_address,
        }
        try:
            response = self.get_api().keys_key_id_csr_pem_post(
                path_params=path_params, body=body, skip_deserialization=True
            )
            return response.response.data.decode("utf-8")
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Key {key_id} not found",
                },
            )

    def set_backup_passphrase(self, passphrase):
        from .client.components.schema.backup_passphrase_config import (
            BackupPassphraseConfigDict,
        )

        body = BackupPassphraseConfigDict(passphrase=passphrase)
        try:
            self.get_api().config_backup_passphrase_put(body=body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- e. g. weak passphrase",
                },
            )

    def set_unlock_passphrase(self, passphrase):
        from .client.components.schema.unlock_passphrase_config import (
            UnlockPassphraseConfigDict,
        )

        body = UnlockPassphraseConfigDict(passphrase=passphrase)
        try:
            self.get_api().config_unlock_passphrase_put(body=body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- e. g. weak passphrase",
                },
            )

    def set_logging_config(self, ip_address, port, log_level):
        from .client.components.schema.logging_config import LoggingConfigDict

        body = LoggingConfigDict(ipAddress=ip_address, port=port, logLevel=log_level)
        try:
            self.get_api().config_logging_put(body=body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid input data",
                },
            )

    def set_network_config(self, ip_address, netmask, gateway):
        from .client.components.schema.network_config import NetworkConfigDict

        body = NetworkConfigDict(ipAddress=ip_address, netmask=netmask, gateway=gateway)
        try:
            self.get_api().config_network_put(body=body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid input data",
                },
            )

    def set_time(self, time):
        from .client.components.schema.time_config import TimeConfigDict

        body = TimeConfigDict(time=time)
        try:
            self.get_api().config_time_put(body=body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid time format",
                },
            )

    def set_unattended_boot(self, status):
        from .client.components.schema.unattended_boot_config import (
            UnattendedBootConfigDict,
        )

        body = UnattendedBootConfigDict(status=status)
        try:
            self.get_api().config_unattended_boot_put(body=body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid status setting",
                },
            )

    def get_system_info(self):
        try:
            response = self.get_api().system_info_get()
            return SystemInfo(
                firmware_version=response.body["firmwareVersion"],
                software_version=response.body["softwareVersion"],
                hardware_version=response.body["hardwareVersion"],
                build_tag=response.body["softwareBuild"],
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def backup(self):
        try:
            response = self.get_api().system_backup_post()
            return response.response.data
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.BACKUP],
                messages={
                    412: "NetHSM is not Operational or the backup passphrase is not set",
                },
            )

    def restore(self, backup, passphrase, time):
        try:
            params = {
                "backupPassphrase": passphrase,
                "systemTime": time.isoformat(),
            }
            self.request("POST", "system/restore", params=params, data=backup)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.UNPROVISIONED,
                messages={
                    400: "Bad request -- backup did not apply",
                },
            )

    def update(self, image):
        try:
            response = self.request("POST", "system/update", data=image)
            return response.json().get("releaseNotes")
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- malformed image",
                    409: "Conflict -- major version downgrade is not allowed",
                },
            )

    def cancel_update(self):
        try:
            self.get_api().system_cancel_update_post()
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def commit_update(self):
        try:
            self.get_api().system_commit_update_post()
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def reboot(self):
        try:
            self.get_api().system_reboot_post()
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def shutdown(self):
        try:
            self.get_api().system_shutdown_post()
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def factory_reset(self):
        try:
            self.get_api().system_factory_reset_post()
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def encrypt(self, key_id, data, mode, iv):
        from .client.components.schema.encrypt_request_data import (
            EncryptRequestDataDict,
        )
        from .client.paths.keys_key_id_encrypt.post.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        body = EncryptRequestDataDict(message=data, mode=mode, iv=iv)
        try:
            response = self.get_api().keys_key_id_encrypt_post(
                path_params=path_params, body=body
            )
            return (response.body.encrypted, response.body.iv)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.OPERATOR],
                messages={
                    400: "Bad request -- e. g. invalid encryption mode, or wrong padding",
                    404: f"Key {key_id} not found",
                },
            )

    def decrypt(self, key_id, data, mode, iv):
        from .client.components.schema.decrypt_request_data import (
            DecryptRequestDataDict,
        )
        from .client.paths.keys_key_id_decrypt.post.path_parameters import (
            PathParametersDict,
        )

        body = DecryptRequestDataDict(encrypted=data, mode=mode, iv=iv)

        if len(iv) == 0:
            body = DecryptRequestDataDict(encrypted=data, mode=mode)

        path_params = PathParametersDict(KeyID=key_id)
        try:
            response = self.get_api().keys_key_id_decrypt_post(
                path_params=path_params, body=body
            )
            return response.body.decrypted
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.OPERATOR],
                messages={
                    400: "Bad request -- e. g. invalid encryption mode",
                    404: f"Key {key_id} not found",
                },
            )

    def sign(self, key_id, data, mode):
        from .client.components.schema.sign_request_data import SignRequestDataDict
        from .client.paths.keys_key_id_sign.post.path_parameters import (
            PathParametersDict,
        )

        path_params = PathParametersDict(KeyID=key_id)
        body = SignRequestDataDict(message=data, mode=mode)
        try:
            response = self.get_api().keys_key_id_sign_post(
                path_params=path_params, body=body
            )
            return response.body.signature
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.OPERATOR],
                messages={
                    400: "Bad request -- e. g. invalid sign mode",
                    404: f"Key {key_id} not found",
                },
            )


@contextlib.contextmanager
def connect(host, version, username, password, verify_tls=True):
    nethsm = NetHSM(host, version, username, password, verify_tls)
    try:
        yield nethsm
    finally:
        nethsm.close()
