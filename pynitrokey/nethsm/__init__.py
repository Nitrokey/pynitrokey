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


class KeyAlgorithm(enum.Enum):
    RSA = "RSA"
    ED25519 = "ED25519"
    ECDSA_P224 = "ECDSA_P224"
    ECDSA_P256 = "ECDSA_P256"
    ECDSA_P384 = "ECDSA_P384"
    ECDSA_P521 = "ECDSA_P521"


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
    ED25519_SIGNATURE = "ED25519_Signature"
    ECDSA_P224_SIGNATURE = "ECDSA_P224_Signature"
    ECDSA_P256_SIGNATURE = "ECDSA_P256_Signature"
    ECDSA_P384_SIGNATURE = "ECDSA_P384_Signature"
    ECDSA_P521_SIGNATURE = "ECDSA_P521_Signature"


class DecryptMode(enum.Enum):
    RAW = "RAW"
    PKCS1 = "PKCS1"
    OAEP_MD5 = "OAEP_MD5"
    OAEP_SHA1 = "OAEP_SHA1"
    OAEP_SHA224 = "OAEP_SHA224"
    OAEP_SHA256 = "OAEP_SHA256"
    OAEP_SHA384 = "OAEP_SHA384"
    OAEP_SHA512 = "OAEP_SHA512"


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
    def __init__(self, key_id, mechanisms, algorithm, operations, modulus, public_exponent):
        self.key_id = key_id
        self.mechanisms = mechanisms
        self.algorithm = algorithm
        self.operations = operations
        self.modulus = modulus
        self.public_exponent = public_exponent


def _handle_api_exception(e, messages={}, roles=[], state=None):
    if e.status == 403 and roles:
        roles = [role.value for role in roles]
        message = "Access denied -- this operation requires the role " + " or ".join(
            roles
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
                messages={
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
        from .client.model.user_passphrase_post_data import UserPassphrasePostData

        body = UserPassphrasePostData(passphrase=Passphrase(passphrase))
        try:
            self.get_api().users_user_id_passphrase_post(user_id=user_id, body=body)
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

    def get_info(self):
        try:
            data = self.get_api().info_get()
            return (data.vendor, data.product)
        except ApiException as e:
            _handle_api_exception(e)

    def get_state(self):
        try:
            data = self.get_api().health_state_get()
            return State.from_model(data.state)
        except ApiException as e:
            _handle_api_exception(e)

    def get_random_data(self, n):
        from .client.model.random_request_data import RandomRequestData

        body = RandomRequestData(length=n)
        try:
            data = self.get_api().random_post(body=body)
            return data.random
        except ApiException as e:
            _handle_api_exception(e, state=State.OPERATIONAL, roles=[Role.OPERATOR])

    def get_metrics(self):
        try:
            return self.get_api().metrics_get()
        except ApiException as e:
            _handle_api_exception(e, state=State.OPERATIONAL, roles=[Role.METRICS])

    def list_keys(self):
        try:
            data = self.get_api().keys_get()
            return [item["key"] for item in data.value]
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR, Role.OPERATOR],
            )

    def get_key(self, key_id):
        try:
            key = self.get_api().keys_key_id_get(key_id=key_id)
            return Key(
                key_id=key_id,
                mechanisms=[mechanism.value for mechanism in key.mechanisms.value],
                algorithm=key.algorithm.value,
                operations=key.operations,
                modulus=key.key.modulus,
                public_exponent=key.key.public_exponent,
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

    def add_key(self, key_id, algorithm, mechanisms, prime_p, prime_q, public_exponent, data):
        from .client.model.key_algorithm import KeyAlgorithm
        from .client.model.key_mechanism import KeyMechanism
        from .client.model.key_mechanisms import KeyMechanisms
        from .client.model.key_private_data import KeyPrivateData
        from .client.model.private_key import PrivateKey

        if algorithm == "RSA":
            key_data = KeyPrivateData(
                prime_p=prime_p,
                prime_q=prime_q,
                public_exponent=public_exponent,
            )
        else:
            key_data = KeyPrivateData(data=data)

        body = PrivateKey(
            algorithm=KeyAlgorithm(algorithm),
            mechanisms=KeyMechanisms([KeyMechanism(mechanism) for mechanism in mechanisms]),
            key=key_data,
        )
        try:
            if key_id:
                self.get_api().keys_key_id_put(key_id=key_id, body=body)
                return key_id
            else:
                self.get_api().keys_post(body=body)
                # TODO: determine the key ID generated by the NetHSM
                return "[randomly generated key ID]"
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

    def generate_key(self, algorithm, mechanisms, length, key_id):
        from .client.model.key_algorithm import KeyAlgorithm
        from .client.model.key_mechanism import KeyMechanism
        from .client.model.key_mechanisms import KeyMechanisms
        from .client.model.key_generate_request_data import KeyGenerateRequestData

        body = KeyGenerateRequestData(
            algorithm=KeyAlgorithm(algorithm),
            mechanisms=KeyMechanisms([KeyMechanism(mechanism) for mechanism in mechanisms]),
            length=length,
            id=key_id or "",
        )
        try:
            self.get_api().keys_generate_post(body=body)
            if not key_id:
                # TODO: determine the key ID generated by the NetHSM
                key_id = "[randomly generated key ID]"
            return key_id
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
            return self.get_api().config_logging_get()
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_config_network(self):
        try:
            return self.get_api().config_network_get()
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_config_time(self):
        try:
            return self.get_api().config_time_get().time
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_config_unattended_boot(self):
        try:
            return self.get_api().config_unattended_boot_get().status
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_public_key(self):
        try:
            return self.get_api().config_tls_public_pem_get()
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def get_certificate(self):
        try:
            return self.get_api().config_tls_cert_pem_get()
        except ApiException as e:
            _handle_api_exception(
                e, state=State.OPERATIONAL, roles=[Role.ADMINISTRATOR]
            )

    def set_backup_passphrase(self, passphrase):
        from .client.model.backup_passphrase_config import BackupPassphraseConfig

        body = BackupPassphraseConfig(passphrase=Passphrase(passphrase))
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
        from .client.model.unlock_passphrase_config import UnlockPassphraseConfig

        body = UnlockPassphraseConfig(passphrase=Passphrase(passphrase))
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
        from .client.model.log_level import LogLevel
        from .client.model.logging_config import LoggingConfig

        body = LoggingConfig(ip_address=ip_address, port=port, log_level=LogLevel(log_level))
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
        from .client.model.network_config import NetworkConfig

        body = NetworkConfig(ip_address=ip_address, netmask=netmask, gateway=gateway)
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
        from .client.model.time_config import TimeConfig

        body = TimeConfig(time=time)
        try:
            self.get_api().config_time_put(body=body)
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
        from .client.model.switch import Switch
        from .client.model.unattended_boot_config import UnattendedBootConfig

        body = UnattendedBootConfig(status=Switch(status))
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
            data = self.get_api().system_info_get()
            return SystemInfo(
                firmware_version=data.firmware_version,
                software_version=data.software_version,
                hardware_version=data.hardware_version,
                build_tag=data.build_tag,
            )
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

    def reset(self):
        try:
            self.get_api().system_reset_post()
        except ApiException as e:
            _handle_api_exception(
                e,
                state=State.OPERATIONAL,
                roles=[Role.ADMINISTRATOR],
            )

    def decrypt(self, key_id, data, mode):
        from .client.model.base64 import Base64
        from .client.model.decrypt_mode import DecryptMode
        from .client.model.decrypt_request_data import DecryptRequestData

        body = DecryptRequestData(encrypted=Base64(data), mode=DecryptMode(mode))
        try:
            data = self.get_api().keys_key_id_decrypt_post(key_id=key_id, body=body)
            return data.decrypted.value
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


@contextlib.contextmanager
def connect(host, version, username, password, verify_tls=True):
    nethsm = NetHSM(host, version, username, password, verify_tls)
    try:
        yield nethsm
    finally:
        nethsm.close()
