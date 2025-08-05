# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import logging
from hashlib import sha256
from struct import unpack
from threading import Thread
from typing import Any, Optional

from nitrokey.trussed import Fido2Certs, TrussedBase, TrussedDevice, Uuid, Version
from tqdm import tqdm

from pynitrokey.cli.trussed.test import TestContext, TestResult, TestStatus, test_case
from pynitrokey.helpers import local_print

logger = logging.getLogger(__name__)


AID_ADMIN = [0xA0, 0x00, 0x00, 0x08, 0x47, 0x00, 0x00, 0x00, 0x01]
AID_PROVISIONER = [0xA0, 0x00, 0x00, 0x08, 0x47, 0x01, 0x00, 0x00, 0x01]


@test_case("uuid", "UUID query")
def test_uuid_query(ctx: TestContext, device: TrussedBase) -> TestResult:
    uuid = device.uuid()
    uuid_str = str(uuid) if uuid else "[not supported]"
    return TestResult(TestStatus.SUCCESS, uuid_str)


@test_case("version", "Firmware version query")
def test_firmware_version_query(ctx: TestContext, device: TrussedBase) -> TestResult:
    if not isinstance(device, TrussedDevice):
        return TestResult(TestStatus.SKIPPED)
    version = device.admin.version()
    ctx.firmware_version = version
    return TestResult(TestStatus.SUCCESS, str(version))


def test_device_status_internal(
    ctx: TestContext, device: TrussedBase, skip_if_version: Optional[Version]
) -> TestResult:
    if not isinstance(device, TrussedDevice):
        return TestResult(TestStatus.SKIPPED)
    firmware_version = ctx.firmware_version or device.admin.version()

    if skip_if_version is not None and firmware_version.core() < skip_if_version:
        return TestResult(TestStatus.SKIPPED)

    errors = []

    status = device.admin.status()
    logger.info(f"Device status: {status}")

    if status.init_status is None:
        errors.append("missing init status")
    elif status.init_status.is_error():
        errors.append(f"init error: {status.init_status}")

    if status.efs_blocks is None or status.ifs_blocks is None:
        return TestResult(TestStatus.FAILURE, "missing filesystem status")
    else:
        if status.ifs_blocks < 5:
            errors.append(f"IFS block count critical ({status.ifs_blocks})")
        if status.efs_blocks < 10:
            errors.append(f"EFS block count critical ({status.ifs_blocks})")

    if errors:
        return TestResult(TestStatus.FAILURE, ", ".join(errors))
    else:
        return TestResult(TestStatus.SUCCESS, str(status))


@test_case("status", "Device status")
def test_nk3_device_status(ctx: TestContext, device: TrussedBase) -> TestResult:
    return test_device_status_internal(ctx, device, skip_if_version=Version(1, 3, 0))


@test_case("status", "Device status")
def test_nkpk_device_status(ctx: TestContext, device: TrussedBase) -> TestResult:
    return test_device_status_internal(ctx, device, skip_if_version=None)


@test_case("bootloader", "Bootloader configuration")
def test_bootloader_configuration(ctx: TestContext, device: TrussedBase) -> TestResult:
    if not isinstance(device, TrussedDevice):
        return TestResult(TestStatus.SKIPPED)
    if device.admin.is_locked():
        return TestResult(TestStatus.SUCCESS)
    else:
        return TestResult(TestStatus.FAILURE, "bootloader not locked")


@test_case("provisioner", "Firmware mode")
def test_firmware_mode(ctx: TestContext, device: TrussedBase) -> TestResult:
    try:
        from smartcard import System
        from smartcard.CardConnection import CardConnection
        from smartcard.Exceptions import NoCardException
    except ImportError:
        logger.debug("pcsc feature is deactivated, skipping firmware mode test")
        return TestResult(TestStatus.SKIPPED, "pcsc feature is deactivated")

    def find_smartcard(uuid: Uuid) -> CardConnection:
        for reader in System.readers():
            conn = reader.createConnection()
            try:
                conn.connect()
            except NoCardException:
                continue
            if not select(conn, AID_ADMIN):
                continue
            data, sw1, sw2 = conn.transmit([0x00, 0x62, 0x00, 0x00, 16])
            if (sw1, sw2) != (0x90, 0x00):
                continue
            if len(data) != 16:
                continue
            if uuid != Uuid(int.from_bytes(data, byteorder="big")):
                continue
            return conn
        raise Exception(f"No smartcard with UUID {uuid} found")

    def select(conn: CardConnection, aid: list[int]) -> bool:
        apdu = [0x00, 0xA4, 0x04, 0x00]
        apdu.append(len(aid))
        apdu.extend(aid)
        _, sw1, sw2 = conn.transmit(apdu)
        return (sw1, sw2) == (0x90, 0x00)

    uuid = device.uuid()
    if not uuid:
        return TestResult(TestStatus.SKIPPED, "no UUID")
    conn = find_smartcard(uuid)
    if select(conn, AID_PROVISIONER):
        return TestResult(TestStatus.FAILURE, "provisioner application active")
    else:
        return TestResult(TestStatus.SUCCESS)


SE050_STEPS = [
    "Enable",
    "Random1",
    "Random2",
    "Random3",
    "WriteUserId",
    "CreateSession",
    "VerifySessionUserId",
    "DeleteAll",
    "List",
    "WriteBinary1",
    "ReadBinary1",
    "DeleteBinary1",
    "WriteBinary2",
    "ReadBinary2",
    "DeleteBinary2",
    "WriteBinary3",
    "ReadBinary3",
    "DeleteBinary3",
    "CreateP256",
    "ListP256",
    "GenerateP256",
    "EcDsaP256",
    "VerifyP256",
    "DeleteP256",
    "CreateP521",
    "GenerateP521",
    "EcDsaP521",
    "VerifyP521",
    "DeleteP521",
    "RecreationWriteUserId",
    "RecreationWriteBinary",
    "RecreationDeleteAttempt",
    "RecreationDeleteUserId",
    "RecreationRecreateUserId",
    "RecreationCreateSession",
    "RecreationAuthSession",
    "RecreationDeleteAttack",
    "Rsa2048Gen",
    "Rsa2048Sign",
    "Rsa2048Verify",
    "Rsa2048Encrypt",
    "Rsa2048Decrypt",
    "Rsa2048Delete",
    "Rsa3072Gen",
    "Rsa3072Sign",
    "Rsa3072Verify",
    "Rsa3072Encrypt",
    "Rsa3072Decrypt",
    "Rsa3072Delete",
    "Rsa4096Gen",
    "Rsa4096Sign",
    "Rsa4096Verify",
    "Rsa4096Encrypt",
    "Rsa4096Decrypt",
    "Rsa4096Delete",
    "SymmWrite",
    "SymmEncryptOneShot",
    "SymmDecryptOneShot",
    "SymmEncryptCreate",
    "SymmEncryptInit",
    "SymmEncryptUpdate1",
    "SymmEncryptUpdate2",
    "SymmEncryptFinal",
    "SymmEncryptDelete",
    "SymmDecryptCreate",
    "SymmDecryptInit",
    "SymmDecryptUpdate1",
    "SymmDecryptUpdate2",
    "SymmDecryptFinal",
    "SymmDecryptDelete",
    "SymmDelete",
    "MacWrite",
    "MacSignOneShot",
    "MacVerifyOneShot",
    "MacSignCreate",
    "MacSignInit",
    "MacSignUpdate1",
    "MacSignUpdate2",
    "MacSignFinal",
    "MacSignDelete",
    "MacVerifyCreate",
    "MacVerifyInit",
    "MacVerifyUpdate1",
    "MacVerifyUpdate2",
    "MacVerifyFinal",
    "MacVerifyDelete",
    "MacDelete",
    "AesSessionCreateKey",
    "AesSessionCreateBinary",
    "AesSessionCreateSession",
    "AesSessionAuthenticate",
    "AesSessionReadBinary",
    "AesSessionUpdateKey",
    "AesSessionCloseSession",
    "AesSessionRecreateSession",
    "AesSessionReAuthenticate",
    "AesSessionReadBinary2",
    "AesSessionDeleteBinary",
    "AesSessionDeleteKey",
    "Pbkdf2WritePin",
    "Pbkdf2Calculate",
    "Pbkdf2Compare",
    "Pbkdf2DeletePin",
    "ImportWrite",
    "ImportCipher",
    "ImportExport",
    "ImportDelete",
    "ImportDeletionWorked",
    "ImportImport",
    "ImportCipher2",
    "ImportComp",
    "ImportDeleteFinal",
]


@test_case("se050", "SE050")
def test_se050(ctx: TestContext, device: TrussedBase) -> TestResult:
    from queue import Queue

    if not isinstance(device, TrussedDevice):
        return TestResult(TestStatus.SKIPPED)

    que: Queue[Optional[bytes]] = Queue()

    def internal_se050_run(
        q: Queue[Optional[bytes]],
    ) -> None:
        q.put(device.admin.se050_tests())

    t = Thread(target=internal_se050_run, args=[que])
    t.start()
    total = 1200
    bar = tqdm(
        desc="Running SE050 test", unit="%", bar_format="{l_bar}{bar}", total=total
    )
    # 2min in increments of 0.1 second
    for i in range(total):
        t.join(0.1)
        bar.update(1)
        if not t.is_alive():
            bar.update(total - i)
            break
    else:
        bar.close()
        return TestResult(
            TestStatus.FAILURE,
            "Test timed out after 2min",
        )

    bar.close()
    result = que.get()

    # This means  that the device responded with `CommandNotSupported`, so either it is a version that doesn't support this feature or it was disabled at compile time
    if result is None:
        return TestResult(
            TestStatus.SKIPPED,
            "Testing SE050 functionality is not supported by the device",
        )

    if len(result) < 11:
        return TestResult(TestStatus.FAILURE, "Did not get full test run data")
    major = result[0]
    minor = result[1]
    patch = result[2]
    sb_major = result[3]
    sb_minor = result[4]
    persistent = unpack(">H", result[5:7])
    transient_deselect = unpack(">H", result[7:9])
    transient_reset = unpack(">H", result[9:11])

    success_message = f"SE050 firmware version: {major}.{minor}.{patch} - {sb_major}.{sb_minor}, (persistent: {persistent}, transient_deselect: {transient_deselect}, transient_reset: {transient_reset})"

    i = 0
    max = len(SE050_STEPS)
    for b in result[11:]:
        i += 1
        if i != b:
            index = SE050_STEPS[i - 1] if i < max else hex(i)
            return TestResult(
                TestStatus.FAILURE,
                f"Failed at {index}, got {result[10+i:].hex()} of {result.hex()}",
            )
    if i != max:
        return TestResult(TestStatus.FAILURE, f"Got to {i}, expected {max}")

    return TestResult(TestStatus.SUCCESS, success_message)


@test_case("fido2", "FIDO2")
def test_fido2(ctx: TestContext, device: TrussedBase) -> TestResult:
    if not isinstance(device, TrussedDevice):
        return TestResult(TestStatus.SKIPPED)

    # drop out early, if pin is needed, but not provided
    from fido2.client import DefaultClientDataCollector, Fido2Client

    client_data_collector = DefaultClientDataCollector(origin="https://example.com")
    fido2_client = Fido2Client(
        device=device.device, client_data_collector=client_data_collector
    )
    options = fido2_client.info.options
    has_pin = options["clientPin"]
    uv_required = not options.get("makeCredUvNotRqd", False)

    if has_pin and uv_required and not ctx.pin:
        return TestResult(
            TestStatus.FAILURE,
            "FIDO2 pin is set, but not provided (use the --pin argument)",
        )

    # Based on https://github.com/Yubico/python-fido2/blob/142587b3e698ca0e253c78d75758fda635cac51a/examples/credential.py

    from fido2.attestation.base import InvalidSignature
    from fido2.attestation.packed import PackedAttestation
    from fido2.client import PinRequiredError, UserInteraction
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        AttestationConveyancePreference,
        AttestationObject,
        AuthenticatorAttachment,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
        UserVerificationRequirement,
    )

    def verify_attestation(
        attestation_object: AttestationObject, client_data_hash: bytes
    ) -> None:
        verifier = PackedAttestation()
        assert attestation_object.fmt == verifier.FORMAT
        verifier.verify(
            attestation_object.att_stmt, attestation_object.auth_data, client_data_hash
        )

    class NoInteraction(UserInteraction):
        def __init__(self, pin: Optional[str]) -> None:
            self.pin = pin

        def prompt_up(self) -> None:
            pass

        def request_pin(self, permissions: Any, rd_id: Any) -> str:
            if self.pin:
                return self.pin
            else:
                raise PinRequiredError()  # type: ignore[no-untyped-call]

        def request_uv(self, permissions: Any, rd_id: Any) -> bool:
            return True

    client = Fido2Client(
        device=device.device,
        client_data_collector=client_data_collector,
        user_interaction=NoInteraction(ctx.pin),
    )
    server = Fido2Server(
        PublicKeyCredentialRpEntity(id="example.com", name="Example RP"),
        attestation=AttestationConveyancePreference.DIRECT,
        verify_attestation=verify_attestation,
    )
    uv = UserVerificationRequirement.DISCOURAGED
    user = PublicKeyCredentialUserEntity(id=b"user_id", name="A. User")

    create_options, state = server.register_begin(
        user=user,
        user_verification=uv,
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
    )

    local_print("Please press the touch button on the device ...")
    try:
        make_credential_result = client.make_credential(create_options["publicKey"])
    except PinRequiredError:
        return TestResult(
            TestStatus.FAILURE,
            "PIN activated -- please set the --pin option",
        )
    cert = make_credential_result.response.attestation_object.att_stmt["x5c"]
    cert_hash = sha256(cert[0]).digest().hex()

    firmware_version = ctx.firmware_version or device.admin.version()
    if firmware_version:
        expected_certs = Fido2Certs.get(device.fido2_certs, firmware_version)
        if expected_certs and cert_hash not in expected_certs.hashes:
            return TestResult(
                TestStatus.FAILURE,
                f"Unexpected FIDO2 cert hash for version {firmware_version}: {cert_hash}",
            )

    try:
        auth_data = server.register_complete(
            state,
            response=make_credential_result,
        )
    except InvalidSignature:
        return TestResult(TestStatus.FAILURE, "Invalid attestation signature")
    if not auth_data.credential_data:
        return TestResult(TestStatus.FAILURE, "Missing credential data in auth data")
    credentials = [auth_data.credential_data]

    request_options, state = server.authenticate_begin(
        credentials, user_verification=uv
    )

    local_print("Please press the touch button on the device ...")
    get_assertion_result = client.get_assertion(request_options["publicKey"])
    get_assertion_response = get_assertion_result.get_response(0)

    server.authenticate_complete(
        state,
        credentials,
        response=get_assertion_response,
    )

    return TestResult(TestStatus.SUCCESS)
