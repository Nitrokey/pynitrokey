#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""The module provides support for RoT hash calculation ."""


from abc import abstractmethod
from typing import List, Optional, Sequence, Type, Union

from ...crypto.certificate import Certificate
from ...crypto.keys import PrivateKey, PublicKey
from ...exceptions import SPSDKError
from ...image.ahab.ahab_container import SRKRecord
from ...image.ahab.ahab_container import SRKTable as AhabSrkTable
from ...image.secret import SrkItem
from ...image.secret import SrkTable as HabSrkTable
from ...utils.crypto.rkht import RKHT, RKHTv1, RKHTv21
from ...utils.database import DatabaseManager, get_db, get_families
from ...utils.misc import load_binary


class Rot:
    """Root of Trust object providing an abstraction over the RoT hash calculation for multiple device families."""

    def __init__(
        self,
        family: str,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """Root of Trust initialization."""
        self.rot_obj = self.get_rot_class(family)(
            keys_or_certs=keys_or_certs, password=password, search_paths=search_paths
        )

    def calculate_hash(self) -> bytes:
        """Calculate RoT hash."""
        return self.rot_obj.calculate_hash()

    def export(self) -> bytes:
        """Export RoT."""
        return self.rot_obj.export()

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Get all supported families."""
        return get_families(DatabaseManager.CERT_BLOCK)

    @classmethod
    def get_rot_class(cls, family: str) -> Type["RotBase"]:
        """Get RoT class."""
        db = get_db(family, "latest")
        rot_type = db.get_str(DatabaseManager.CERT_BLOCK, "rot_type")
        for subclass in RotBase.__subclasses__():
            if subclass.rot_type == rot_type:
                return subclass
        raise SPSDKError(f"A ROT type {rot_type} does not exist.")


class RotBase:
    """Root of Trust base class."""

    rot_type: Optional[str] = None

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """Rot initialization."""
        self.keys_or_certs = keys_or_certs
        self.password = password
        self.search_paths = search_paths

    @abstractmethod
    def calculate_hash(
        self,
    ) -> bytes:
        """Calculate ROT hash."""

    @abstractmethod
    def export(self) -> bytes:
        """Calculate ROT table."""


class RotCertBlockv1(RotBase):
    """Root of Trust for certificate block v1 class."""

    rot_type = "cert_block_1"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """Rot cert block v1 initialization."""
        super().__init__(keys_or_certs, password, search_paths)
        self.rkht = RKHTv1.from_keys(self.keys_or_certs, self.password, self.search_paths)

    def calculate_hash(
        self,
    ) -> bytes:
        """Calculate RoT hash."""
        return self.rkht.rkth()

    def export(self) -> bytes:
        """Export RoT."""
        return self.rkht.export()


class RotCertBlockv21(RotBase):
    """Root of Trust for certificate block v21 class."""

    rot_type = "cert_block_21"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """Rot cert block v21 initialization."""
        super().__init__(keys_or_certs, password, search_paths)
        self.rkht = RKHTv21.from_keys(self.keys_or_certs, self.password, self.search_paths)

    def calculate_hash(
        self,
    ) -> bytes:
        """Calculate ROT hash."""
        return self.rkht.rkth()

    def export(self) -> bytes:
        """Export RoT."""
        return self.rkht.export()


class RotSrkTableAhab(RotBase):
    """Root of Trust for AHAB SrkTable class."""

    rot_type = "srk_table_ahab"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """AHAB SRK table initialization."""
        super().__init__(keys_or_certs, password, search_paths)
        self.srk = AhabSrkTable(
            [SRKRecord(RKHT.convert_key(key, password, search_paths)) for key in keys_or_certs]
        )
        self.srk.update_fields()

    def calculate_hash(self) -> bytes:
        """Calculate ROT hash."""
        return self.srk.compute_srk_hash()

    def export(self) -> bytes:
        """Export RoT."""
        return self.srk.export()


class RotSrkTableHab(RotBase):
    """Root of Trust for HAB SrkTable class."""

    rot_type = "srk_table_hab"

    def __init__(
        self,
        keys_or_certs: Sequence[Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate]],
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """HAB SRK table initialization."""
        super().__init__(keys_or_certs, password, search_paths)
        self.srk = HabSrkTable()
        for certificate in keys_or_certs:
            if isinstance(certificate, (str, bytes, bytearray)):
                try:
                    certificate = self._load_certificate(certificate, search_paths)
                except SPSDKError as exc:
                    raise SPSDKError(
                        "Unable to load certificate. Certificate must be provided for HAB RoT calculation."
                    ) from exc
            if not isinstance(certificate, Certificate):
                raise SPSDKError("Certificate must be provided for HAB RoT calculation.")
            item = SrkItem.from_certificate(certificate)
            self.srk.append(item)

    def calculate_hash(self) -> bytes:
        """Calculate ROT hash."""
        return self.srk.export_fuses()

    def export(self) -> bytes:
        """Export RoT."""
        return self.srk.export()

    @classmethod
    def _load_certificate(
        cls,
        certificate: Union[str, bytes, bytearray],
        search_paths: Optional[List[str]] = None,
    ) -> Certificate:
        """Load certificate if certificate provided, or extract public key if private/public key is provided."""
        if isinstance(certificate, str):
            certificate = load_binary(certificate, search_paths)
        try:
            return Certificate.parse(certificate)
        except SPSDKError as exc:
            raise SPSDKError("Unable to load certificate.") from exc
