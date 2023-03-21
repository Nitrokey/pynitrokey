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
from dataclasses import dataclass
from io import BytesIO
from typing import Optional
from zipfile import ZipFile

import ecdsa
import ecdsa.curves
from ecdsa.keys import BadSignatureError

from ..utils import Uuid, Version
from . import FirmwareMetadata, Nitrokey3Bootloader, ProgressCallback, Variant
from .nrf52_upload.dfu.dfu_transport import DfuEvent
from .nrf52_upload.dfu.dfu_transport_serial import DfuTransportSerial
from .nrf52_upload.dfu.init_packet_pb import InitPacketPB
from .nrf52_upload.dfu.manifest import Manifest
from .nrf52_upload.dfu.package import Package
from .nrf52_upload.lister.device_lister import DeviceLister

logger = logging.getLogger(__name__)

FILENAME_PATTERN = re.compile("(firmware|alpha)-nk3..-nrf52-(?P<version>.*)\\.zip$")


@dataclass
class SignatureKey:
    name: str
    is_official: bool
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


# openssl ec -in dfu_public.pem -inform pem -pubin -outform der | xxd -p
SIGNATURE_KEYS = [
    # Nitrokey production key
    SignatureKey(
        name="Nitrokey",
        is_official=True,
        der="3059301306072a8648ce3d020106082a8648ce3d03010703420004a0849b19007ccd4661c01c533804b7fd0c4d8c0e7583653f1f36a8331afff298b542bd00a3dc47c16bf428ac4d2864137d63f702d89e5b42674e0549b4232618",
    ),
    # Nitrokey test key
    SignatureKey(
        name="Nitrokey Test",
        is_official=False,
        der="3059301306072a8648ce3d020106082a8648ce3d0301070342000493e461ab0582bda1f45b0ce47d66bc4e8623e289c31af2098cde6ebd8631da85acf17e412d406c1e38c2de654a8fd0196506a85b169a756aeac2505a541cdd5d",
    ),
]


@dataclass
class Image:
    init_packet: InitPacketPB
    firmware_dat: bytes
    firmware_bin: bytes
    is_signed: bool = False
    signature_key: Optional[SignatureKey] = None

    @classmethod
    def parse(cls, data: bytes) -> "Image":
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
            for key in SIGNATURE_KEYS:
                if key.verify(signature, message):
                    image.signature_key = key

        return image


class Nitrokey3BootloaderNrf52(Nitrokey3Bootloader):
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
    def name(self) -> str:
        return "Nitrokey 3 Bootloader (NRF52)"

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

        image = Image.parse(data)

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

    @staticmethod
    def list() -> list["Nitrokey3BootloaderNrf52"]:
        return [
            Nitrokey3BootloaderNrf52(port, serial) for port, serial in _list_ports()
        ]

    @staticmethod
    def open(path: str) -> Optional["Nitrokey3BootloaderNrf52"]:
        for port, serial in _list_ports():
            if path == port:
                return Nitrokey3BootloaderNrf52(path, serial)
        return None


@dataclass
class CallbackWrapper:
    callback: ProgressCallback
    total: int
    n: int = 0

    def __call__(self, progress: int) -> None:
        self.n += progress
        self.callback(self.n, self.total)


def _list_ports() -> list[tuple[str, int]]:
    from .. import PID_NITROKEY3_NRF52_BOOTLOADER, VID_NITROKEY

    ports = []
    for device in DeviceLister().enumerate():
        vendor_id = int(device.vendor_id, base=16)
        product_id = int(device.product_id, base=16)
        assert device.com_ports
        if len(device.com_ports) > 1:
            logger.warn(
                f"Nitrokey 3 NRF52 bootloader has multiple com ports: {device.com_ports}"
            )
        if vendor_id == VID_NITROKEY and product_id == PID_NITROKEY3_NRF52_BOOTLOADER:
            port = device.com_ports[0]
            serial = int(device.serial_number, base=16)
            logger.debug(f"Found Nitrokey 3 NRF52 bootloader with port {port}")
            ports.append((port, serial))
        else:
            logger.debug(
                f"Skipping device {vendor_id:x}:{product_id:x} with ports {device.com_ports}"
            )
    return ports


def parse_firmware_image(data: bytes) -> FirmwareMetadata:
    image = Image.parse(data)
    version = Version.from_int(image.init_packet.init_command.fw_version)
    metadata = FirmwareMetadata(version=version)

    if image.is_signed:
        metadata.signed_by = (
            image.signature_key.name if image.signature_key else "unknown"
        )
        if image.signature_key:
            metadata.signed_by_nitrokey = image.signature_key.is_official

    return metadata
