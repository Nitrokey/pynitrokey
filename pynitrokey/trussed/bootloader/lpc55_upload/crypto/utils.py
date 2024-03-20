#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation for security backend."""

from typing import Iterable, List, Optional

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.keys import PrivateKey, PublicKey
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.misc import load_binary


def get_matching_key_id(public_keys: List[PublicKey], signature_provider: SignatureProvider) -> int:
    """Get index of public key that match to given private key.

    :param public_keys: List of public key used to find the match for the private key.
    :param signature_provider: Signature provider used to try to match public key index.
    :raises SPSDKValueError: No match found.
    :return: Index of public key.
    """
    for i, public_key in enumerate(public_keys):
        if signature_provider.verify_public_key(public_key.export()):
            return i

    raise SPSDKValueError("There is no match of private key in given list.")


def extract_public_key_from_data(object_data: bytes, password: Optional[str] = None) -> PublicKey:
    """Extract any kind of public key from a data that contains Certificate, Private Key or Public Key.

    :raises SPSDKError: Raised when file can not be loaded
    :return: private key of any type
    """
    try:
        return Certificate.parse(object_data).get_public_key()
    except SPSDKError:
        pass

    try:
        return PrivateKey.parse(
            object_data, password=password if password else None
        ).get_public_key()
    except SPSDKError:
        pass

    try:
        return PublicKey.parse(object_data)
    except SPSDKError as exc:
        raise SPSDKError("Unable to load secret data.") from exc


def extract_public_key(
    file_path: str, password: Optional[str] = None, search_paths: Optional[List[str]] = None
) -> PublicKey:
    """Extract any kind of public key from a file that contains Certificate, Private Key or Public Key.

    :param file_path: File path to public key file.
    :param password: Optional password for encrypted Private file source.
    :param search_paths: List of paths where to search for the file, defaults to None
    :raises SPSDKError: Raised when file can not be loaded
    :return: Public key of any type
    """
    try:
        object_data = load_binary(file_path, search_paths=search_paths)
        return extract_public_key_from_data(object_data, password)
    except SPSDKError as exc:
        raise SPSDKError(f"Unable to load secret file '{file_path}'.") from exc


def extract_public_keys(
    secret_files: Iterable[str],
    password: Optional[str] = None,
    search_paths: Optional[List[str]] = None,
) -> List[PublicKey]:
    """Extract any kind of public key from files that contain Certificate, Private Key or Public Key.

    :param secret_files: List of file paths to public key files.
    :param password: Optional password for encrypted Private file source.
    :param search_paths: List of paths where to search for the file, defaults to None
    :return: List of public keys of any type
    """
    return [
        extract_public_key(file_path=source, password=password, search_paths=search_paths)
        for source in secret_files
    ]
