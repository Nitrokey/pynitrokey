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
    if e.status in messages:
        message = messages[e.status]
    elif e.status == 403 and roles:
        roles = [role.value for role in roles]
        message = "Access denied -- this operation requires the role " + " or ".join(
            roles
        )
    elif e.status == 401 and roles:
        message = "Unauthorized -- invalid username or password"
    elif e.status == 412 and state:
        message = f"Precondition failed -- this operation can only be used on a NetHSM in the state {state.value}"
    else:
        message = f"Unexpected API error {e.status}: {e.reason}"

    if e.body:
        try:
            body = json.loads(e.body)
            if "message" in body:
                message += "\n" + body["message"]
        except json.JSONDecodeError:
            pass

    raise NetHSMError(message)


class NetHSMError(Exception):
    def __init__(self, message):
        super().__init__(message)


class NetHSM:
    def __init__(self, host, version, username, password, verify_tls=True):
        self.host = host
        self.version = version
        self.username = username
        self.password = password

        base_url = f"https://{host}/api/{version}"
        config = client.Configuration(
            host=base_url, username=username, password=password
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
            e = ApiException(status=response.status_code, reason=response.reason)
            e.body = response.text
            e.headers = response.headers
            raise e
        return response

    def get_api(self):
        from .client.api.default_api import DefaultApi

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
        from .client.models.unlock_request_data import UnlockRequestData

        request_body = UnlockRequestData(
            passphrase=passphrase,
        )
        try:
            self.get_api().unlock_post(request_body)
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
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def provision(self, unlock_passphrase, admin_passphrase, system_time):
        from .client.models.provision_request_data import ProvisionRequestData

        request_body = ProvisionRequestData(
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
                    400: "Malformed request data -- e. g. weak passphrase",
                },
            )

    def list_users(self):
        try:
            response = self.get_api().users_get()
            return [item.user for item in response]
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def get_user(self, user_id):
        try:
            # Validation is broken for this endpoint, we parse the response manually
            response = self.get_api().users_user_id_get_with_http_info(user_id,_preload_content=False)
            user = json.loads(response.raw_data)
            return User(
                user_id=user_id,
                real_name=user["realName"],
                role=Role.from_string(user["role"]),
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
        from .client.models.user_post_data import UserPostData
        from .client.models.user_role import UserRole

        body = UserPostData(
            realName=real_name,
            role=UserRole(role),
            passphrase=passphrase,
        )
        try:
            if user_id:
                self.get_api().users_user_id_put(user_id, body)
                return user_id
            else:
                response = self.get_api().users_post_with_http_info(body)
                return self.get_user_id_from_location(response.headers)
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

        try:
            self.get_api().users_user_id_delete(user_id=user_id)
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
        from .client.models.user_passphrase_post_data import UserPassphrasePostData

        body = UserPassphrasePostData(passphrase=passphrase)
        try:
            self.get_api().users_user_id_passphrase_post(user_id, body)
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

        try:
            response = self.get_api().users_user_id_tags_get(user_id)
            return response
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
        try:
            return self.get_api().users_user_id_tags_tag_put(user_id, tag)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    404: f"User {user_id} not found",
                    304: f"Tag is already present for {user_id}",
                },
            )

    def delete_operator_tag(self, user_id, tag):
        try:
            return self.get_api().users_user_id_tags_tag_delete(
                user_id=user_id, tag=tag
            )
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
        try:
            return self.get_api().keys_key_id_restrictions_tags_tag_put(
                key_id=key_id, tag=tag
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
        try:
            return self.get_api().keys_key_id_restrictions_tags_tag_delete(
                key_id=key_id, tag=tag
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
            return (response.vendor,response.product)
        except ApiException as e:
            _handle_api_exception(e)

    def get_state(self):
        try:
            response = self.get_api().health_state_get()
            return State.from_string(response.state)
        except ApiException as e:
            _handle_api_exception(e)

    def get_random_data(self, n):
        from .client.models.random_request_data import RandomRequestData

        body = RandomRequestData(length=n)
        try:
            response = self.get_api().random_post(body)
            return response.body["random"]
        except ApiException as e:
            _handle_api_exception(e, state=State.OPERATIONAL, roles=[Role.OPERATOR])

    def get_metrics(self):
        try:
            response = self.get_api().metrics_get()
            return response
        except ApiException as e:
            _handle_api_exception(e, state=State.OPERATIONAL, roles=[Role.METRICS])

    def list_keys(self, filter):
        try:
            if filter:
                response = self.get_api().keys_get(filter=filter)
            else:
                response = self.get_api().keys_get()
            return [item.key for item in response]
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
            )

    def get_key(self, key_id):
        try:
            key = self.get_api().keys_key_id_get(key_id)
            return Key(
                key_id=key_id,
                mechanisms=[mechanism for mechanism in key.mechanisms],
                type=key.type,
                operations=key.operations,
                tags=[tag for tag in key.restrictions.tags]
                if key.restrictions.tags is not None
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
        try:
            response = self.get_api().keys_key_id_public_pem_get(
                key_id=key_id, skip_deserialization=True
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
        from .client.models.key_mechanism import KeyMechanism
        from .client.models.key_private_data import KeyPrivateData
        from .client.models.key_restrictions import KeyRestrictions
        from .client.models.key_type import KeyType
        from .client.models.private_key import PrivateKey

        if type == "RSA":
            key_data = KeyPrivateData(
                prime_p=prime_p,
                prime_q=prime_q,
                public_exponent=public_exponent,
            )
        else:
            key_data = KeyPrivateData(data=data)

        if tags:
            body = PrivateKey(
                type=KeyType(type),
                mechanisms=[KeyMechanism(mechanism) for mechanism in mechanisms],
                key=key_data,
                restrictions=KeyRestrictions(tags=[tag for tag in tags]),
            )
        else:
            body = PrivateKey(
                type=KeyType(type),
                mechanisms=[KeyMechanism(mechanism) for mechanism in mechanisms],
                key=key_data,
            )

        try:
            if key_id:
                self.get_api().keys_key_id_put(
                    key_id=key_id, private_key=body, _content_type="application/json"
                )
                return key_id
            else:
                response = self.get_api().keys_post_with_http_info(
                    body, _content_type="application/json"
                )
                return self.get_key_id_from_location(response.headers)
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
        try:
            self.get_api().keys_key_id_delete(key_id=key_id)
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
        from .client.models.key_generate_request_data import KeyGenerateRequestData
        from .client.models.key_mechanism import KeyMechanism
        from .client.models.key_type import KeyType

        if key_id:
            body = KeyGenerateRequestData(
                type=KeyType(type),
                mechanisms=[KeyMechanism(mechanism) for mechanism in mechanisms],
                length=length,
                id=key_id,
            )
        else:
            body = KeyGenerateRequestData(
                type=KeyType(type),
                mechanisms=[KeyMechanism(mechanism) for mechanism in mechanisms],
                length=length,
            )
        try:
            response = self.get_api().keys_generate_post_with_http_info(body)
            return key_id or self.get_key_id_from_location(response.headers)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid input data",
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
            response = self.request("GET", f"keys/{key_id}/cert")
            return response.content.decode("utf-8")
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
                messages={
                    404: f"Certificate for key {key_id} not found",
                },
            )

    def set_certificate(self, cert):
        try:
            self.get_api().config_tls_cert_pem_put(
                cert, _content_type="application/x-pem-file"
            )
            # self.request(
            #     "PUT",
            #     "config/tls/cert.pem",
            #     data=cert,
            #     mime_type="application/x-pem-file",
            # )
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
            self.get_api().keys_key_id_cert_put(
                key_id=key_id, cert=cert, _content_type=mime_type
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad Request -- invalid certificate",
                    404: f"Key {key_id} not found",
                    409: f"Conflict -- key {key_id} already has a certificate",
                },
            )

    def delete_key_certificate(self, key_id):
        try:
            return self.get_api().keys_key_id_cert_delete(key_id=key_id)
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
        from .client.models.distinguished_name import DistinguishedName

        body = DistinguishedName(
            countryName=country,
            stateOrProvinceName=state_or_province,
            localityName=locality,
            organizationName=organization,
            organizationalUnitName=organizational_unit,
            commonName=common_name,
            emailAddress=email_address,
        )
        try:
            response = self.get_api().config_tls_csr_pem_post(
                body, skip_deserialization=True
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
        from .client.models.tls_key_generate_request_data import (
            TlsKeyGenerateRequestData,
        )
        from .client.models.tls_key_type import TlsKeyType

        if type == "RSA":
            body = TlsKeyGenerateRequestData(
                type=TlsKeyType(type),
                length=length,
            )
        else:
            body = TlsKeyGenerateRequestData(
                type=TlsKeyType(type),
            )

        try:
            return self.get_api().config_tls_generate_post(body)
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
        from .client.models.distinguished_name import DistinguishedName

        body = DistinguishedName(
            countryName=country,
            stateOrProvinceName=state_or_province,
            localityName=locality,
            organizationName=organization,
            organizationalUnitName=organizational_unit,
            commonName=common_name,
            emailAddress=email_address,
        )

        try:
            response = self.get_api().keys_key_id_csr_pem_post(
                key_id=key_id, distinguished_name=body, skip_deserialization=True
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
        from .client.models.backup_passphrase_config import BackupPassphraseConfig

        body = BackupPassphraseConfig(passphrase=passphrase)
        try:
            self.get_api().config_backup_passphrase_put(body)
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
        from .client.models.unlock_passphrase_config import UnlockPassphraseConfig

        body = UnlockPassphraseConfig(passphrase=passphrase)
        try:
            self.get_api().config_unlock_passphrase_put(body)
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
        from .client.models.log_level import LogLevel
        from .client.models.logging_config import LoggingConfig

        body = LoggingConfig(
            ipAddress=ip_address, port=port, logLevel=LogLevel(log_level)
        )
        try:
            self.get_api().config_logging_put(body)
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
        from .client.models.network_config import NetworkConfig

        body = NetworkConfig(ipAddress=ip_address, netmask=netmask, gateway=gateway)
        try:
            self.get_api().config_network_put(body)
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
        from .client.models.time_config import TimeConfig

        body = TimeConfig(time=time)
        try:
            self.get_api().config_time_put(body)
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
                messages={
                    400: "Bad request -- invalid input data",
                },
            )

    def set_unattended_boot(self, status):
        from .client.models.switch import Switch
        from .client.models.unattended_boot_config import UnattendedBootConfig

        body = UnattendedBootConfig(status=Switch(status))
        try:
            self.get_api().config_unattended_boot_put(body)
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
            # validation is broken for this endpoint, we parse the response manually
            response = self.get_api().system_info_get_with_http_info(_preload_content=False)
            body = json.loads(response.raw_data)
            print(body)
            return SystemInfo(
                firmware_version=body["firmwareVersion"],
                software_version=body["softwareVersion"],
                hardware_version=body["hardwareVersion"],
                build_tag=body["softwareBuild"],
            )
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def backup(self):
        try:
            response = self.request("POST", "system/backup")
            return response.content
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.BACKUP],
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
        from .client.models.encrypt_mode import EncryptMode
        from .client.models.encrypt_request_data import EncryptRequestData

        body = EncryptRequestData(message=data, mode=EncryptMode(mode), iv=iv)
        try:
            response = self.get_api().keys_key_id_encrypt_post(key_id, body)
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
        from .client.models.decrypt_mode import DecryptMode
        from .client.models.decrypt_request_data import DecryptRequestData

        body = DecryptRequestData(encrypted=data, mode=DecryptMode(mode), iv=iv)
        try:
            response = self.get_api().keys_key_id_decrypt_post(key_id, body)
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
        from .client.models.sign_mode import SignMode
        from .client.models.sign_request_data import SignRequestData

        body = SignRequestData(message=data, mode=SignMode(mode))
        try:
            response = self.get_api().keys_key_id_sign_post(key_id, body)
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
