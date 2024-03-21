#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SignatureProvider is an Interface for all potential signature providers.

Each concrete signature provider needs to implement:
- sign(data: bytes) -> bytes
- signature_length -> int
- into() -> str
"""

import abc
import json
import logging
from types import ModuleType
from typing import Any, Dict, List, Optional, Tuple, Type, Union

import requests
from cryptography.hazmat.primitives.hashes import HashAlgorithm

from ..crypto.exceptions import SPSDKKeysNotMatchingError
from ..crypto.hash import EnumHashAlgorithm, get_hash_algorithm
from ..crypto.keys import (
    ECDSASignature,
    PrivateKey,
    PrivateKeyEcc,
    PrivateKeyRsa,
    PrivateKeySM2,
    PublicKeyEcc,
    PublicKeyRsa,
    PublicKeySM2,
    SPSDKKeyPassphraseMissing,
    prompt_for_passphrase,
)
from ..crypto.types import SPSDKEncoding
from ..exceptions import (
    SPSDKError,
    SPSDKKeyError,
    SPSDKUnsupportedOperation,
    SPSDKValueError,
)
from ..utils.misc import find_file
from ..utils.plugins import PluginsManager, PluginType

logger = logging.getLogger(__name__)


class SignatureProvider(abc.ABC):
    """Abstract class (Interface) for all signature providers."""

    # Subclasses override the following signature provider type
    sp_type = "INVALID"
    reserved_keys = ["type", "search_paths"]

    @abc.abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Return signature for data."""

    @property
    @abc.abstractmethod
    def signature_length(self) -> int:
        """Return length of the signature."""

    def verify_public_key(self, public_key: bytes) -> bool:
        """Verify if given public key matches private key."""
        raise SPSDKUnsupportedOperation("Verify method is not supported.")

    def get_signature(self, data: bytes) -> bytes:
        """Get signature. In case of ECC signature, the NXP format(r+s) is used.

        :param data: Data to be signed.
        :return: Signature of the data

        """
        signature = self.sign(data)
        try:
            ecdsa_sig = ECDSASignature.parse(signature)
            signature = ecdsa_sig.export(SPSDKEncoding.NXP)
        except SPSDKValueError:
            pass  # Not an ECC signature
        if len(signature) != self.signature_length:
            logger.warning(
                f"Signature has unexpected length: {len(signature)}. Expected length: {self.signature_length}"
            )
        return signature

    def info(self) -> str:
        """Provide information about the Signature provider."""
        return self.__class__.__name__

    @staticmethod
    def convert_params(params: str) -> Dict[str, str]:
        """Coverts creation params from string into dictionary.

        e.g.: "type=file;file_path=some_path" -> {'type': 'file', 'file_path': 'some_path'}
        :param params: Params in the mentioned format.
        :raises: SPSDKKeyError: Duplicate key found.
        :raises: SPSDKValueError: Parameter must meet the following pattern: type=file;file_path=some_path.
        :return: Converted dictionary of parameters.
        """
        result: Dict[str, str] = {}
        try:
            for p in params.split(";"):
                key, value = p.split("=")

                # Check for duplicate keys
                if key in result:
                    raise SPSDKKeyError(f"Duplicate key found: {key}")

                result[key] = value

        except ValueError as e:
            raise SPSDKValueError(
                "Parameter must meet the following pattern: type=file;file_path=some_path"
            ) from e

        return result

    @classmethod
    def get_types(cls) -> List[str]:
        """Returns a list of all available signature provider types."""
        return [sub_class.sp_type for sub_class in cls.__subclasses__()]

    @classmethod
    def filter_params(cls, klass: Any, params: Dict[str, str]) -> Dict[str, str]:
        """Remove unused parameters from the given dictionary based on the class constructor.

        :param klass: Signature provider class.
        :param params: Dictionary of parameters.
        :return: Filtered dictionary of parameters.
        """
        unused_params = set(params) - set(klass.__init__.__code__.co_varnames)
        for key in cls.reserved_keys:
            if key in unused_params:
                del params[key]
        return params

    @classmethod
    def create(cls, params: Union[str, dict]) -> Optional["SignatureProvider"]:
        """Creates an concrete instance of signature provider."""
        load_plugins()
        if isinstance(params, str):
            params = cls.convert_params(params)
        sp_classes = cls.get_all_signature_providers()
        for (
            klass
        ) in sp_classes:  # pragma: no branch  # there always be at least one subclass
            if klass.sp_type == params["type"]:
                klass.filter_params(klass, params)
                return klass(**params)

        logger.info(f"Signature provider of type {params['type']} was not found.")
        return None

    @staticmethod
    def get_all_signature_providers() -> List[Type["SignatureProvider"]]:
        """Get list of all available signature providers."""

        def get_subclasses(
            base_class: Type,
        ) -> List[Type["SignatureProvider"]]:
            """Recursively find all subclasses."""
            subclasses = []
            for subclass in base_class.__subclasses__():
                subclasses.append(subclass)
                subclasses.extend(get_subclasses(subclass))
            return subclasses

        return get_subclasses(SignatureProvider)


class PlainFileSP(SignatureProvider):
    """PlainFileSP is a SignatureProvider implementation that uses plain local files."""

    sp_type = "file"

    def __init__(
        self,
        file_path: str,
        password: Optional[str] = None,
        hash_alg: Optional[EnumHashAlgorithm] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """Initialize the plain file signature provider.

        :param file_path: Path to private file
        :param password: Password in case of encrypted private file, defaults to None
        :param hash_alg: Hash for the signature, defaults to None
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid Private Key
        """
        self.file_path = find_file(file_path=file_path, search_paths=search_paths)
        self.private_key = PrivateKey.load(self.file_path, password=password)
        self.hash_alg = self._get_hash_algorithm(hash_alg)

    def _get_hash_algorithm(
        self, hash_alg: Optional[EnumHashAlgorithm] = None
    ) -> HashAlgorithm:
        if hash_alg:
            hash_alg_name = hash_alg
        else:
            if isinstance(self.private_key, PrivateKeyRsa):
                hash_alg_name = EnumHashAlgorithm.SHA256

            elif isinstance(self.private_key, PrivateKeyEcc):
                # key_size <= 256       =>  SHA256
                # 256 < key_size <= 384 =>  SHA384
                # 384 < key_size        =>  SHA512
                if self.private_key.key_size <= 256:
                    hash_size = 256
                elif 256 < self.private_key.key_size <= 384:
                    hash_size = 384
                else:
                    hash_size = 512
                hash_alg_name = EnumHashAlgorithm.from_label(f"sha{hash_size}")

            elif isinstance(self.private_key, PrivateKeySM2):
                hash_alg_name = EnumHashAlgorithm.SM3
            else:
                raise SPSDKError(
                    f"Unsupported private key by signature provider: {str(self.private_key)}"
                )
        return get_hash_algorithm(hash_alg_name)

    @property
    def signature_length(self) -> int:
        """Return length of the signature."""
        return self.private_key.signature_size

    def verify_public_key(self, public_key: bytes) -> bool:
        """Verify if given public key matches private key."""
        try:
            return self.private_key.verify_public_key(PublicKeyEcc.parse(public_key))
        except SPSDKError:
            pass
        try:
            return self.private_key.verify_public_key(PublicKeyRsa.parse(public_key))
        except SPSDKError:
            pass
        try:
            return self.private_key.verify_public_key(PublicKeySM2.parse(public_key))
        except SPSDKError:
            pass
        raise SPSDKError("Unsupported public key")

    def info(self) -> str:
        """Return basic into about the signature provider."""
        msg = super().info()
        msg += f"\nKey path: {self.file_path}\n"
        return msg

    def sign(self, data: bytes) -> bytes:
        """Return the signature for data."""
        return self.private_key.sign(data)


class InteractivePlainFileSP(PlainFileSP):
    """SignatureProvider implementation that uses plain local file in an "interactive" mode.

    If the private key is encrypted, the user will be prompted for password
    """

    sp_type = "interactive_file"

    def __init__(  # pylint: disable=super-init-not-called
        self,
        file_path: str,
        hash_alg: Optional[EnumHashAlgorithm] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """Initialize the interactive plain file signature provider.

        :param file_path: Path to private file
        :param hash_alg: Hash for the signature, defaults to sha256
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid Private Key
        """
        self.file_path = find_file(file_path=file_path, search_paths=search_paths)
        try:
            self.private_key = PrivateKey.load(self.file_path)
        except SPSDKKeyPassphraseMissing:
            password = prompt_for_passphrase()
            self.private_key = PrivateKey.load(self.file_path, password=password)
        self.hash_alg = self._get_hash_algorithm(hash_alg)


class HttpProxySP(SignatureProvider):
    """Signature Provider implementation that delegates all operations to a proxy server."""

    sp_type = "proxy"
    reserved_keys = ["type", "search_paths", "data"]

    def __init__(
        self,
        host: str = "localhost",
        port: str = "8000",
        url_prefix: str = "api",
        **kwargs: Dict[str, str],
    ) -> None:
        """Initialize Http Proxy Signature Provider.

        :param host: Hostname (IP address) of the proxy server, defaults to "localhost"
        :param port: Port of the proxy server, defaults to "8000"
        :param url_prefix: REST API prefix, defaults to "api"
        """
        self.base_url = f"http://{host}:{port}/"
        self.base_url += f"{url_prefix}/" if url_prefix else ""
        self.kwargs = kwargs

    def _handle_request(self, url: str, data: Optional[Dict] = None) -> Dict:
        """Handle REST API request.

        :param url: REST API endpoint URL
        :param data: JSON payload data, defaults to None
        :raises SPSDKError: HTTP Error during API request
        :raises SPSDKError: Invalid response data (not a valid dictionary)
        :return: REST API data response as dictionary
        """
        json_payload = data or {}
        json_payload.update(self.kwargs)
        full_url = self.base_url + url
        logger.info(f"Requesting: {full_url}")
        response = requests.get(url=full_url, json=json_payload, timeout=60)
        logger.info(f"Response: {response}")
        if not response.ok:
            try:
                extra_message = response.json()
            except json.JSONDecodeError:
                extra_message = "N/A"
            raise SPSDKError(
                f"Error {response.status_code} ({response.reason}) occurred when calling {full_url}\n"
                f"Extra response data: {extra_message}"
            )
        try:
            return response.json()
        except json.JSONDecodeError as e:
            raise SPSDKError("Response is not a valid JSON object") from e

    def _check_response(
        self, response: Dict, names_types: List[Tuple[str, Type]]
    ) -> None:
        """Check if the response contains required data.

        :param response: Response to check
        :param names_types: Name and type of required response members
        :raises SPSDKError: Response doesn't contain required member
        :raises SPSDKError: Responses' member has incorrect type
        """
        for name, typ in names_types:
            if name not in response:
                raise SPSDKError(f"Response object doesn't contain member '{name}'")
            if not isinstance(response[name], typ):
                raise SPSDKError(
                    f"Response member '{name}' is not a instance of '{typ}' but '{type(response[name])}'"
                )

    def sign(self, data: bytes) -> bytes:
        """Return signature for data."""
        response = self._handle_request("sign", {"data": data.hex()})
        self._check_response(response=response, names_types=[("data", str)])
        return bytes.fromhex(response["data"])

    @property
    def signature_length(self) -> int:
        """Return length of the signature."""
        response = self._handle_request("signature_length")
        self._check_response(response=response, names_types=[("data", int)])
        return int(response["data"])

    def verify_public_key(self, public_key: bytes) -> bool:
        """Verify if given public key matches private key."""
        response = self._handle_request("verify_public_key", {"data": public_key.hex()})
        self._check_response(response=response, names_types=[("data", bool)])
        return response["data"]


def get_signature_provider(
    sp_cfg: Optional[str] = None, local_file_key: Optional[str] = None, **kwargs: Any
) -> SignatureProvider:
    """Get the signature provider from configuration.

    :param sp_cfg: Configuration of signature provider.
    :param local_file_key: Optional backward compatibility
        option to specify just path to local private key.
    :param kwargs: Additional parameters, that could be accepted by Signature providers.
    :return: Signature Provider instance.
    :raises SPSDKError: Invalid input configuration.
    """
    if sp_cfg:
        params: Dict[str, Union[str, List[str]]] = {}
        params.update(SignatureProvider.convert_params(sp_cfg))
        for k, v in kwargs.items():
            if not k in params:
                params[k] = v
        signature_provider = SignatureProvider.create(params=params)
    elif local_file_key:
        signature_provider = InteractivePlainFileSP(
            file_path=local_file_key,
            search_paths=kwargs.get("search_paths"),
        )
    else:
        raise SPSDKValueError("No signature provider configuration is provided")

    if not signature_provider:
        raise SPSDKError(
            f"Cannot create signature provider from: {sp_cfg or local_file_key}"
        )

    return signature_provider


def load_plugins() -> Dict[str, ModuleType]:
    """Load all installed signature provider plugins."""
    plugins_manager = PluginsManager()
    plugins_manager.load_from_entrypoints(PluginType.SIGNATURE_PROVIDER.label)
    return plugins_manager.plugins


def try_to_verify_public_key(
    signature_provider: SignatureProvider, public_key_data: bytes
) -> None:
    """Verify public key by signature provider if verify method is implemented.

    :param signature_provider: Signature provider used for verification.
    :param public_key_data: Public key data to be verified.
    :raises SPSDKUnsupportedOperation: The verify_public_key method si nto implemented
    :raises SPSDKError: The verification of key-pair integrity failed
    """
    try:
        result = signature_provider.verify_public_key(public_key_data)
        if not result:
            raise SPSDKKeysNotMatchingError(
                "Signature verification failed, public key does not match to private key"
            )
        logger.debug(
            "The verification of private key pair integrity has been successful."
        )
    except SPSDKUnsupportedOperation:
        logger.warning(
            "Signature provider could not verify the integrity of private key pair."
        )
