# -*- coding: utf-8 -*-
#
# Copyright 2022 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import hashlib
import logging
import re
import time
from abc import abstractmethod
from dataclasses import dataclass
from io import BytesIO
from typing import Optional, Sequence, TypeVar
from zipfile import ZipFile

import ecdsa
import ecdsa.curves
from ecdsa.keys import BadSignatureError

from pynitrokey.trussed.utils import Uuid, Version

from . import FirmwareMetadata, NitrokeyTrussedBootloader, ProgressCallback, Variant
from .nrf52_upload.dfu.dfu_transport import DfuEvent
from .nrf52_upload.dfu.dfu_transport_serial import DfuTransportSerial
from .nrf52_upload.dfu.init_packet_pb import InitPacketPB
from .nrf52_upload.dfu.manifest import Manifest
from .nrf52_upload.dfu.package import Package
from .nrf52_upload.lister.device_lister import DeviceLister

logger = logging.getLogger(__name__)

FILENAME_PATTERN = re.compile(
    "(firmware|alpha)-(nk3..|nkpk)-nrf52-(?P<version>.*)\\.zip$"
)

T = TypeVar("T", bound="NitrokeyTrussedBootloaderNrf52")


@dataclass
class SignatureKey:
    name: str
    is_official: bool
    # generate with:
    # $ openssl ec -in dfu_public.pem -inform pem -pubin -outform der | xxd -p
    der: str

    def vk(self) -> ecdsa.VerifyingKey:
        return ecdsa.VerifyingKey.from_der(bytes.fromhex(self.der))

    def verify(self, signature: str, message: str) -> bool:
        try:
            self.vk().verify(
                signature,
                message,
                hashfunc=hashlib.sha256,
            )
            return True
        except BadSignatureError:
            return False


@dataclass
class Image:
    init_packet: InitPacketPB
    firmware_dat: bytes
    firmware_bin: bytes
    is_signed: bool = False
    signature_key: Optional[SignatureKey] = None

    @classmethod
    def parse(cls, data: bytes, keys: Sequence[SignatureKey]) -> "Image":
        io = BytesIO(data)
        with ZipFile(io) as pkg:
            with pkg.open(Package.MANIFEST_FILENAME) as f:
                manifest = Manifest.from_json(f.read())
            if not manifest.application:
                raise Exception("Missing application in firmware package manifest")
            if not manifest.application.dat_file:
                raise Exception(
                    "Missing dat file for application in firmware package manifest"
                )
            if not manifest.application.bin_file:
                raise Exception(
                    "Missing bin file for application in firmware package manifest"
                )
            with pkg.open(manifest.application.dat_file, "r") as f:
                firmware_dat = f.read()
            with pkg.open(manifest.application.bin_file, "r") as f:
                firmware_bin = f.read()
            init_packet = InitPacketPB(from_bytes=firmware_dat)

        if init_packet.init_command.app_size != len(firmware_bin):
            raise Exception("Invalid app size")

        h = hashlib.sha256()
        h.update(firmware_bin)
        hash = bytes(reversed(h.digest()))
        if hash != init_packet.init_command.hash.hash:
            raise Exception("Invalid hash for firmware image")

        image = cls(
            init_packet=init_packet,
            firmware_dat=firmware_dat,
            firmware_bin=firmware_bin,
        )

        if init_packet.packet.signed_command:
            image.is_signed = True
            signature = init_packet.packet.signed_command.signature
            # see nordicsemi.dfu.signing.Signing.sign
            signature = signature[31::-1] + signature[63:31:-1]
            message = init_packet.get_init_command_bytes()
            for key in keys:
                if key.verify(signature, message):
                    image.signature_key = key

        return image


class NitrokeyTrussedBootloaderNrf52(NitrokeyTrussedBootloader):
    def __init__(self, path: str, uuid: int) -> None:
        self._path = path
        self._uuid = uuid

    @property
    def variant(self) -> Variant:
        return Variant.NRF52

    @property
    def path(self) -> str:
        return self._path

    @property
    @abstractmethod
    def signature_keys(self) -> Sequence[SignatureKey]:
        ...

    def close(self) -> None:
        pass

    def reboot(self) -> bool:
        return False

    def uuid(self) -> Optional[Uuid]:
        return Uuid(self._uuid)

    def update(self, data: bytes, callback: Optional[ProgressCallback] = None) -> None:
        # based on https://github.com/NordicSemiconductor/pc-nrfutil/blob/1caa347b1cca3896f4695823f48abba15fbef76b/nordicsemi/dfu/dfu.py
        # we have to implement this ourselves because we want to read the files
        # from memory, not from the filesystem

        image = Image.parse(data, self.signature_keys)

        time.sleep(3)

        dfu = DfuTransportSerial(self.path)

        if callback:
            total = len(image.firmware_bin)
            callback(0, total)
            dfu.register_events_callback(
                DfuEvent.PROGRESS_EVENT,
                CallbackWrapper(callback, total),
            )

        dfu.open()
        dfu.send_init_packet(image.firmware_dat)
        dfu.send_firmware(image.firmware_bin)
        dfu.close()

    @classmethod
    def list_vid_pid(cls: type[T], vid: int, pid: int) -> list[T]:
        return [cls(port, serial) for port, serial in _list_ports(vid, pid)]

    @classmethod
    def open_vid_pid(cls: type[T], vid: int, pid: int, path: str) -> Optional[T]:
        for port, serial in _list_ports(vid, pid):
            if path == port:
                return cls(path, serial)
        return None


@dataclass
class CallbackWrapper:
    callback: ProgressCallback
    total: int
    n: int = 0

    def __call__(self, progress: int) -> None:
        self.n += progress
        self.callback(self.n, self.total)


def _list_ports(vid: int, pid: int) -> list[tuple[str, int]]:
    ports = []
    for device in DeviceLister().enumerate():
        vendor_id = int(device.vendor_id, base=16)
        product_id = int(device.product_id, base=16)
        assert device.com_ports
        if len(device.com_ports) > 1:
            logger.warn(
                f"Nitrokey 3 NRF52 bootloader has multiple com ports: {device.com_ports}"
            )
        if vendor_id == vid and product_id == pid:
            port = device.com_ports[0]
            serial = int(device.serial_number, base=16)
            logger.debug(f"Found Nitrokey 3 NRF52 bootloader with port {port}")
            ports.append((port, serial))
        else:
            logger.debug(
                f"Skipping device {vendor_id:x}:{product_id:x} with ports {device.com_ports}"
            )
    return ports


def parse_firmware_image(data: bytes, keys: Sequence[SignatureKey]) -> FirmwareMetadata:
    image = Image.parse(data, keys)
    version = Version.from_int(image.init_packet.init_command.fw_version)
    metadata = FirmwareMetadata(version=version)

    if image.is_signed:
        metadata.signed_by = (
            image.signature_key.name if image.signature_key else "unknown"
        )
        if image.signature_key:
            metadata.signed_by_nitrokey = image.signature_key.is_official

    return metadata
