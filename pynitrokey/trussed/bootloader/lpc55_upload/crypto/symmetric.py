#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation for symmetric key encryption."""


# Used security modules
from typing import Optional

from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers import Cipher, aead, algorithms, modes

from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness, align_block


class Counter:
    """AES counter with specified counter byte ordering and customizable increment."""

    @property
    def value(self) -> bytes:
        """Initial vector for AES encryption."""
        return self._nonce + self._ctr.to_bytes(4, self._ctr_byteorder_encoding.value)

    def __init__(
        self,
        nonce: bytes,
        ctr_value: Optional[int] = None,
        ctr_byteorder_encoding: Endianness = Endianness.LITTLE,
    ):
        """Constructor.

        :param nonce: last four bytes are used as initial value for counter
        :param ctr_value: counter initial value; it is added to counter value retrieved from nonce
        :param ctr_byteorder_encoding: way how the counter is encoded into output value
        :raises SPSDKError: When invalid byteorder is provided
        """
        assert isinstance(nonce, bytes) and len(nonce) == 16
        self._nonce = nonce[:-4]
        self._ctr_byteorder_encoding = ctr_byteorder_encoding
        self._ctr = int.from_bytes(nonce[-4:], ctr_byteorder_encoding.value)
        if ctr_value is not None:
            self._ctr += ctr_value

    def increment(self, value: int = 1) -> None:
        """Increment counter by specified value.

        :param value: to add to counter
        """
        self._ctr += value


def aes_key_wrap(kek: bytes, key_to_wrap: bytes) -> bytes:
    """Wraps a key using a key-encrypting key (KEK).

    :param kek: The key-encrypting key
    :param key_to_wrap: Plain data
    :return: Wrapped key
    """
    return keywrap.aes_key_wrap(kek, key_to_wrap)


def aes_key_unwrap(kek: bytes, wrapped_key: bytes) -> bytes:
    """Unwraps a key using a key-encrypting key (KEK).

    :param kek: The key-encrypting key
    :param wrapped_key: Encrypted data
    :return: Un-wrapped key
    """
    return keywrap.aes_key_unwrap(kek, wrapped_key)


def aes_ecb_encrypt(key: bytes, plain_data: bytes) -> bytes:
    """Encrypt plain data with AES in ECB mode.

    :param key: The key for data encryption
    :param plain_data: Input data
    :return: Encrypted data
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(plain_data) + enc.finalize()


def aes_ecb_decrypt(key: bytes, encrypted_data: bytes) -> bytes:
    """Decrypt encrypted data with AES in ECB mode.

    :param key: The key for data decryption
    :param encrypted_data: Input data
    :return: Decrypted data
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.decryptor()
    return enc.update(encrypted_data) + enc.finalize()


def aes_cbc_encrypt(key: bytes, plain_data: bytes, iv_data: Optional[bytes] = None) -> bytes:
    """Encrypt plain data with AES in CBC mode.

    :param key: The key for data encryption
    :param plain_data: Input data
    :param iv_data: Initialization vector data
    :raises SPSDKError: Invalid Key or IV
    :return: Encrypted image
    """
    if len(key) * 8 not in algorithms.AES.key_sizes:
        raise SPSDKError(
            "The key must be a valid AES key length: "
            f"{', '.join([str(k) for k in algorithms.AES.key_sizes])}"
        )
    init_vector = iv_data or bytes(algorithms.AES.block_size // 8)
    if len(init_vector) * 8 != algorithms.AES.block_size:
        raise SPSDKError(f"The initial vector length must be {algorithms.AES.block_size // 8}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
    enc = cipher.encryptor()
    return (
        enc.update(align_block(plain_data, alignment=algorithms.AES.block_size // 8))
        + enc.finalize()
    )


def aes_cbc_decrypt(key: bytes, encrypted_data: bytes, iv_data: Optional[bytes] = None) -> bytes:
    """Decrypt encrypted data with AES in CBC mode.

    :param key: The key for data decryption
    :param encrypted_data: Input data
    :param iv_data: Initialization vector data
    :raises SPSDKError: Invalid Key or IV
    :return: Decrypted image
    """
    if len(key) * 8 not in algorithms.AES.key_sizes:
        raise SPSDKError(
            "The key must be a valid AES key length: "
            f"{', '.join([str(k) for k in algorithms.AES.key_sizes])}"
        )
    init_vector = iv_data or bytes(algorithms.AES.block_size)
    if len(init_vector) * 8 != algorithms.AES.block_size:
        raise SPSDKError(f"The initial vector length must be {algorithms.AES.block_size}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
    dec = cipher.decryptor()
    return dec.update(encrypted_data) + dec.finalize()


def aes_ctr_encrypt(key: bytes, plain_data: bytes, nonce: bytes) -> bytes:
    """Encrypt plain data with AES in CTR mode.

    :param key: The key for data encryption
    :param plain_data: Input data
    :param nonce: Nonce data with counter value
    :return: Encrypted data
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    return enc.update(plain_data) + enc.finalize()


def aes_ctr_decrypt(key: bytes, encrypted_data: bytes, nonce: bytes) -> bytes:
    """Decrypt encrypted data with AES in CTR mode.

    :param key: The key for data decryption
    :param encrypted_data: Input data
    :param nonce: Nonce data with counter value
    :return: Decrypted data
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.decryptor()
    return enc.update(encrypted_data) + enc.finalize()


def aes_xts_encrypt(key: bytes, plain_data: bytes, tweak: bytes) -> bytes:
    """Encrypt plain data with AES in XTS mode.

    :param key: The key for data encryption
    :param plain_data: Input data
    :param tweak: The tweak is a 16 byte value
    :return: Encrypted data
    """
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    enc = cipher.encryptor()
    return enc.update(plain_data) + enc.finalize()


def aes_xts_decrypt(key: bytes, encrypted_data: bytes, tweak: bytes) -> bytes:
    """Decrypt encrypted data with AES in XTS mode.

    :param key: The key for data decryption
    :param encrypted_data: Input data
    :param tweak: The tweak is a 16 byte value
    :return: Decrypted data
    """
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    enc = cipher.decryptor()
    return enc.update(encrypted_data) + enc.finalize()


def aes_ccm_encrypt(
    key: bytes, plain_data: bytes, nonce: bytes, associated_data: bytes = b"", tag_len: int = 16
) -> bytes:
    """Encrypt plain data with AES in CCM mode (Counter with CBC).

    :param key: The key for data encryption
    :param plain_data: Input data
    :param nonce: Nonce data with counter value
    :param associated_data: Associated data - Unencrypted but authenticated
    :param tag_len: Length of encryption tag
    :return: Encrypted data
    """
    aesccm = aead.AESCCM(key, tag_length=tag_len)
    return aesccm.encrypt(nonce, plain_data, associated_data)


def aes_ccm_decrypt(
    key: bytes, encrypted_data: bytes, nonce: bytes, associated_data: bytes, tag_len: int = 16
) -> bytes:
    """Decrypt encrypted data with AES in CCM mode (Counter with CBC).

    :param key: The key for data decryption
    :param encrypted_data: Input data
    :param nonce: Nonce data with counter value
    :param associated_data: Associated data - Unencrypted but authenticated
    :param tag_len: Length of encryption tag
    :return: Decrypted data
    """
    aesccm = aead.AESCCM(key, tag_length=tag_len)
    return aesccm.decrypt(nonce, encrypted_data, associated_data)


def sm4_cbc_encrypt(key: bytes, plain_data: bytes, iv_data: Optional[bytes] = None) -> bytes:
    """Encrypt plain data with SM4 in CBC mode.

    :param key: The key for data encryption
    :param plain_data: Input data
    :param iv_data: Initialization vector data
    :raises SPSDKError: Invalid Key or IV
    :return: Encrypted image
    """
    if len(key) * 8 not in algorithms.SM4.key_sizes:
        raise SPSDKError(
            "The key must be a valid SM4 key length: "
            f"{', '.join([str(k) for k in algorithms.SM4.key_sizes])}"
        )
    init_vector = iv_data or bytes(algorithms.SM4.block_size // 8)
    if len(init_vector) * 8 != algorithms.SM4.block_size:
        raise SPSDKError(f"The initial vector length must be {algorithms.SM4.block_size // 8}")
    cipher = Cipher(algorithms.SM4(key), modes.CBC(init_vector))
    enc = cipher.encryptor()
    return (
        enc.update(align_block(plain_data, alignment=algorithms.SM4.block_size // 8))
        + enc.finalize()
    )


def sm4_cbc_decrypt(key: bytes, encrypted_data: bytes, iv_data: Optional[bytes] = None) -> bytes:
    """Decrypt encrypted data with SM4 in CBC mode.

    :param key: The key for data decryption
    :param encrypted_data: Input data
    :param iv_data: Initialization vector data
    :raises SPSDKError: Invalid Key or IV
    :return: Decrypted image
    """
    if len(key) * 8 not in algorithms.SM4.key_sizes:
        raise SPSDKError(
            "The key must be a valid SM4 key length: "
            f"{', '.join([str(k) for k in algorithms.AES.key_sizes])}"
        )
    init_vector = iv_data or bytes(algorithms.SM4.block_size)
    if len(init_vector) * 8 != algorithms.SM4.block_size:
        raise SPSDKError(f"The initial vector length must be {algorithms.SM4.block_size}")
    cipher = Cipher(algorithms.SM4(key), modes.CBC(init_vector))
    dec = cipher.decryptor()
    return dec.update(encrypted_data) + dec.finalize()
