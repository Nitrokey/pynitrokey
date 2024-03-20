#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""The module provides support for Root Key Hash table."""

import logging
import math
from abc import abstractmethod
from typing import List, Optional, Sequence, Union

from typing_extensions import Self

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.hash import EnumHashAlgorithm, get_hash, get_hash_length
from spsdk.crypto.keys import PrivateKey, PublicKey, PublicKeyEcc, PublicKeyRsa
from spsdk.crypto.utils import extract_public_key, extract_public_key_from_data
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness

logger = logging.getLogger(__name__)


class RKHT:
    """Root Key Hash Table class."""

    def __init__(self, rkh_list: List[bytes]) -> None:
        """Initialization of Root Key Hash Table class.

        :param rkh_list: List of Root Key Hashes
        """
        if len(rkh_list) > 4:
            raise SPSDKError("Number of Root Key Hashes can not be larger than 4.")
        self.rkh_list = rkh_list

    @classmethod
    def from_keys(
        cls,
        keys: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> Self:
        """Create RKHT from list of keys.

        :param keys: List of public keys/certificates/private keys/bytes
        :param password: Optional password to open secured private keys, defaults to None
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        public_keys = (
            [cls.convert_key(x, password, search_paths=search_paths) for x in keys] if keys else []
        )
        if not all(isinstance(x, type(public_keys[0])) for x in public_keys):
            raise SPSDKError("RKHT must contains all keys of a same instances.")
        if not all(
            cls._get_hash_algorithm(x) == cls._get_hash_algorithm(public_keys[0])
            for x in public_keys
        ):
            raise SPSDKError("RKHT must have same hash algorithm for all keys.")

        rotk_hashes = [cls._calc_key_hash(key) for key in public_keys]
        return cls(rotk_hashes)

    @abstractmethod
    def rkth(self) -> bytes:
        """Root Key Table Hash.

        :return: Hash of hashes of public keys.
        """

    @staticmethod
    def _get_hash_algorithm(key: PublicKey) -> EnumHashAlgorithm:
        """Get hash algorithm output size for the key.

        :param key: Key to get hash.
        :raises SPSDKError: Invalid kye type.
        :return: Size in bits of hash.
        """
        if isinstance(key, PublicKeyEcc):
            return EnumHashAlgorithm.from_label(f"sha{key.key_size}")

        if isinstance(key, PublicKeyRsa):
            # In case of RSA keys, hash is always SHA-256, regardless of the key length
            return EnumHashAlgorithm.SHA256

        raise SPSDKError("Unsupported key type to load.")

    @property
    def hash_algorithm(self) -> EnumHashAlgorithm:
        """Used hash algorithm name."""
        if not len(self.rkh_list) > 0:
            raise SPSDKError("Unknown hash algorighm name. No root key hashes.")
        return EnumHashAlgorithm.from_label(f"sha{self.hash_algorithm_size}")

    @property
    def hash_algorithm_size(self) -> int:
        """Used hash algorithm size in bites."""
        if not len(self.rkh_list) > 0:
            raise SPSDKError("Unknown hash algorithm size. No public keys provided.")
        return len(self.rkh_list[0]) * 8

    @staticmethod
    def _calc_key_hash(
        public_key: PublicKey,
        algorithm: Optional[EnumHashAlgorithm] = None,
    ) -> bytes:
        """Calculate a hash out of public key's exponent and modulus in RSA case, X/Y in EC.

        :param public_key: List of public keys to compute hash from.
        :param sha_width: Used hash algorithm.
        :raises SPSDKError: Unsupported public key type
        :return: Computed hash.
        """
        n_1 = 0
        n_2 = 0
        if isinstance(public_key, PublicKeyRsa):
            n_1 = public_key.e
            n1_len = math.ceil(n_1.bit_length() / 8)
            n_2 = public_key.n
            n2_len = math.ceil(n_2.bit_length() / 8)
        elif isinstance(public_key, PublicKeyEcc):
            n_1 = public_key.y
            n_2 = public_key.x
            n1_len = n2_len = public_key.coordinate_size
        else:
            raise SPSDKError(f"Unsupported key type: {type(public_key)}")

        n1_bytes = n_1.to_bytes(n1_len, Endianness.BIG.value)
        n2_bytes = n_2.to_bytes(n2_len, Endianness.BIG.value)

        algorithm = algorithm or RKHT._get_hash_algorithm(public_key)
        return get_hash(n2_bytes + n1_bytes, algorithm=algorithm)

    @staticmethod
    def convert_key(
        key: Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate],
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> PublicKey:
        """Convert practically whole input that could hold Public key into public key.

        :param key: Public key in Certificate/Private key, Public key as a path to file,
            loaded bytes or supported class.
        :param password: Optional password to open secured private keys, defaults to None.
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid kye type.
        :return: Public Key object.
        """
        if isinstance(key, PublicKey):
            return key

        if isinstance(key, PrivateKey):
            return key.get_public_key()

        if isinstance(key, Certificate):
            return key.get_public_key()

        if isinstance(key, str):
            return extract_public_key(key, password, search_paths=search_paths)

        if isinstance(key, (bytes, bytearray)):
            return extract_public_key_from_data(key, password)

        raise SPSDKError("RKHT: Unsupported key to load.")


class RKHTv1(RKHT):
    """Root Key Hash Table class for cert block v1."""

    RKHT_SIZE = 4
    RKH_SIZE = 32

    def __init__(
        self,
        rkh_list: List[bytes],
    ) -> None:
        """Initialization of Root Key Hash Table class.

        :param rkh_list: List of Root Key Hashes
        """
        for key_hash in rkh_list:
            if len(key_hash) != self.RKH_SIZE:
                raise SPSDKError(f"Invalid key hash size: {len(key_hash)}")
        super().__init__(rkh_list)

    @property
    def hash_algorithm(self) -> EnumHashAlgorithm:
        """Used Hash algorithm name."""
        return EnumHashAlgorithm.SHA256

    def export(self) -> bytes:
        """Export RKHT as bytes."""
        rotk_table = b""
        for i in range(self.RKHT_SIZE):
            if i < len(self.rkh_list) and self.rkh_list[i]:
                rotk_table += self.rkh_list[i]
            else:
                rotk_table += bytes(self.RKH_SIZE)
        if len(rotk_table) != self.RKH_SIZE * self.RKHT_SIZE:
            raise SPSDKError("Invalid length of data.")
        return rotk_table

    @classmethod
    def parse(cls, rkht: bytes) -> Self:
        """Parse Root Key Hash Table into RKHTv1 object.

        :param rkht: Valid RKHT table
        """
        rotkh_len = len(rkht) // cls.RKHT_SIZE
        offset = 0
        key_hashes = []
        for _ in range(cls.RKHT_SIZE):
            key_hashes.append(rkht[offset : offset + rotkh_len])
            offset += rotkh_len
        return cls(key_hashes)

    def rkth(self) -> bytes:
        """Root Key Table Hash.

        :return: Hash of Hashes of public key.
        """
        rotkh = get_hash(self.export(), self.hash_algorithm)
        return rotkh

    def set_rkh(self, index: int, rkh: bytes) -> None:
        """Set Root Key Hash with index.

        :param index: Index in the hash table
        :param rkh: Root Key Hash to be set
        """
        if index > 3:
            raise SPSDKError("Key hash can not be larger than 3.")
        if self.rkh_list and len(rkh) != len(self.rkh_list[0]):
            raise SPSDKError("Root Key Hash must be the same size as other hashes.")
        # fill the gap with zeros if the keys are not consecutive
        for idx in range(index + 1):
            if len(self.rkh_list) < idx + 1:
                self.rkh_list.append(bytes(self.RKH_SIZE))
        assert len(self.rkh_list) <= 4
        self.rkh_list[index] = rkh


class RKHTv21(RKHT):
    """Root Key Hash Table class for cert block v2.1."""

    def export(self) -> bytes:
        """Export RKHT as bytes."""
        hash_table = bytes()
        if len(self.rkh_list) > 1:
            hash_table = bytearray().join(self.rkh_list)
        return hash_table

    @classmethod
    def parse(cls, rkht: bytes, hash_algorithm: EnumHashAlgorithm) -> Self:
        """Parse Root Key Hash Table into RKHTv21 object.

        :param rkht: Valid RKHT table
        :param hash_algorithm: Hash algorithm to be used
        """
        rkh_len = get_hash_length(hash_algorithm)
        if len(rkht) % rkh_len != 0:
            raise SPSDKError(
                f"The length of Root Key Hash Table does not match the hash algorithm {hash_algorithm}"
            )
        offset = 0
        rkh_list = []
        rkht_size = len(rkht) // rkh_len
        for _ in range(rkht_size):
            rkh_list.append(rkht[offset : offset + rkh_len])
            offset += rkh_len
        return cls(rkh_list)

    def rkth(self) -> bytes:
        """Root Key Table Hash.

        :return: Hash of Hashes of public key.
        """
        if not self.rkh_list:
            logger.debug("RKHT has no records.")
            return bytes()
        if len(self.rkh_list) == 1:
            rotkh = self.rkh_list[0]
        else:
            rotkh = get_hash(self.export(), self.hash_algorithm)
        return rotkh
