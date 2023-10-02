# -*- coding: utf-8 -*-
#
# Copyright 2018 Yubico AB
# Copyright 2021 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import platform
import sys
from dataclasses import dataclass
from enum import Enum, auto, unique
from hashlib import sha256
from struct import unpack
from threading import Thread
from types import TracebackType
from typing import Any, Callable, Iterable, Optional, Tuple, Type, Union

from fido2.ctap import CtapError
from tqdm import tqdm

from pynitrokey.cli.exceptions import CliException
from pynitrokey.fido2 import device_path_to_str
from pynitrokey.fido2.client import NKFido2Client
from pynitrokey.helpers import local_print
from pynitrokey.nk3.admin_app import AdminApp
from pynitrokey.nk3.base import Nitrokey3Base
from pynitrokey.nk3.device import Nitrokey3Device
from pynitrokey.nk3.utils import Fido2Certs, Uuid, Version

logger = logging.getLogger(__name__)


TEST_CASES = []

AID_ADMIN = [0xA0, 0x00, 0x00, 0x08, 0x47, 0x00, 0x00, 0x00, 0x01]
AID_PROVISIONER = [0xA0, 0x00, 0x00, 0x08, 0x47, 0x01, 0x00, 0x00, 0x01]

DEFAULT_EXCLUDES = ["bootloader", "provisioner"]


ExcInfo = Tuple[Type[BaseException], BaseException, TracebackType]


class TestContext:
    def __init__(self, pin: Optional[str]) -> None:
        self.pin = pin
        self.firmware_version: Optional[Version] = None


@unique
class TestStatus(Enum):
    SKIPPED = auto()
    SUCCESS = auto()
    FAILURE = auto()


class TestResult:
    def __init__(
        self,
        status: TestStatus,
        data: Optional[str] = None,
        exc_info: Union[ExcInfo, Tuple[None, None, None]] = (None, None, None),
    ) -> None:
        self.status = status
        self.data = data
        self.exc_info = exc_info


TestCaseFn = Callable[[TestContext, Nitrokey3Base], TestResult]


class TestCase:
    def __init__(self, name: str, description: str, fn: TestCaseFn) -> None:
        self.name = name
        self.description = description
        self.fn = fn


def test_case(name: str, description: str) -> Callable[[TestCaseFn], TestCaseFn]:
    def decorator(func: TestCaseFn) -> TestCaseFn:
        TEST_CASES.append(TestCase(name, description, func))
        return func

    return decorator


def filter_test_cases(
    test_cases: list[TestCase], names: Iterable[str]
) -> Iterable[TestCase]:
    for test_case in test_cases:
        if test_case.name in names:
            yield test_case


@dataclass
class TestSelector:
    only: Iterable[str] = ()
    all: bool = False
    include: Iterable[str] = ()
    exclude: Iterable[str] = ()

    def select(self) -> list[TestCase]:
        if self.only:
            return list(filter_test_cases(TEST_CASES, self.only))

        selected = []
        for test_case in TEST_CASES:
            if test_case.name in self.include:
                selected.append(test_case)
            elif test_case.name not in self.exclude:
                if self.all or test_case.name not in DEFAULT_EXCLUDES:
                    selected.append(test_case)
        return selected


def log_devices() -> None:
    from fido2.hid import CtapHidDevice

    ctap_devices = [device for device in CtapHidDevice.list_devices()]
    logger.info(f"Found {len(ctap_devices)} CTAPHID devices:")
    for device in ctap_devices:
        descriptor = device.descriptor
        path = device_path_to_str(descriptor.path)
        logger.info(f"- {path} ({descriptor.vid:x}:{descriptor.pid:x})")


def log_system() -> None:
    logger.info(f"platform: {platform.platform()}")
    logger.info(f"uname: {platform.uname()}")


@test_case("uuid", "UUID query")
def test_uuid_query(ctx: TestContext, device: Nitrokey3Base) -> TestResult:
    uuid = device.uuid()
    uuid_str = str(uuid) if uuid else "[not supported]"
    return TestResult(TestStatus.SUCCESS, uuid_str)


@test_case("version", "Firmware version query")
def test_firmware_version_query(ctx: TestContext, device: Nitrokey3Base) -> TestResult:
    if not isinstance(device, Nitrokey3Device):
        return TestResult(TestStatus.SKIPPED)
    version = device.version()
    ctx.firmware_version = version
    return TestResult(TestStatus.SUCCESS, str(version))


@test_case("status", "Device status")
def test_device_status(ctx: TestContext, device: Nitrokey3Base) -> TestResult:
    if not isinstance(device, Nitrokey3Device):
        return TestResult(TestStatus.SKIPPED)
    firmware_version = ctx.firmware_version or device.version()
    if firmware_version.core() < Version(1, 3, 0):
        return TestResult(TestStatus.SKIPPED)

    errors = []

    status = AdminApp(device).status()
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


@test_case("bootloader", "Bootloader configuration")
def test_bootloader_configuration(
    ctx: TestContext, device: Nitrokey3Base
) -> TestResult:
    if not isinstance(device, Nitrokey3Device):
        return TestResult(TestStatus.SKIPPED)
    if device.is_locked():
        return TestResult(TestStatus.SUCCESS)
    else:
        return TestResult(TestStatus.FAILURE, "bootloader not locked")


@test_case("provisioner", "Firmware mode")
def test_firmware_mode(ctx: TestContext, device: Nitrokey3Base) -> TestResult:
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
def test_se050(ctx: TestContext, device: Nitrokey3Base) -> TestResult:
    from queue import Queue

    if not isinstance(device, Nitrokey3Device):
        return TestResult(TestStatus.SKIPPED)
    firmware_version = ctx.firmware_version or device.version()
    if (
        firmware_version.core() < Version(1, 5, 0)
        or firmware_version.core() >= Version(1, 6, 0)
        or firmware_version.pre is None
    ):
        return TestResult(TestStatus.SKIPPED)

    que: Queue[Optional[bytes]] = Queue()

    def internal_se050_run(
        q: Queue[Optional[bytes]],
    ) -> None:
        q.put(AdminApp(device).se050_tests())

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
            break
    else:
        bar.close()
        return TestResult(
            TestStatus.FAILURE,
            "Test timed out after 1m30",
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
def test_fido2(ctx: TestContext, device: Nitrokey3Base) -> TestResult:
    if not isinstance(device, Nitrokey3Device):
        return TestResult(TestStatus.SKIPPED)

    # drop out early, if pin is needed, but not provided
    nk_client = NKFido2Client()
    nk_client.find_device(device.device)

    if nk_client.has_pin() and not ctx.pin:
        return TestResult(
            TestStatus.FAILURE,
            "FIDO2 pin is set, but not provided (use the --pin argument)",
        )

    # Based on https://github.com/Yubico/python-fido2/blob/142587b3e698ca0e253c78d75758fda635cac51a/examples/credential.py

    from fido2.client import Fido2Client, PinRequiredError, UserInteraction
    from fido2.server import Fido2Server
    from fido2.webauthn import (
        AttestationConveyancePreference,
        AuthenticatorAttachment,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
        UserVerificationRequirement,
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
        device.device, "https://example.com", user_interaction=NoInteraction(ctx.pin)
    )
    server = Fido2Server(
        PublicKeyCredentialRpEntity(id="example.com", name="Example RP"),
        attestation=AttestationConveyancePreference.DIRECT,
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
    cert = make_credential_result.attestation_object.att_stmt["x5c"]
    cert_hash = sha256(cert[0]).digest().hex()

    firmware_version = ctx.firmware_version or device.version()
    if firmware_version:
        expected_certs = Fido2Certs.get(firmware_version)
        if expected_certs and cert_hash not in expected_certs.hashes:
            return TestResult(
                TestStatus.FAILURE,
                f"Unexpected FIDO2 cert hash for version {firmware_version}: {cert_hash}",
            )

    auth_data = server.register_complete(
        state,
        make_credential_result.client_data,
        make_credential_result.attestation_object,
    )
    if not auth_data.credential_data:
        return TestResult(TestStatus.FAILURE, "Missing credential data in auth data")
    credentials = [auth_data.credential_data]

    request_options, state = server.authenticate_begin(
        credentials, user_verification=uv
    )

    local_print("Please press the touch button on the device ...")
    get_assertion_result = client.get_assertion(request_options["publicKey"])
    get_assertion_response = get_assertion_result.get_response(0)
    if not get_assertion_response.credential_id:
        return TestResult(
            TestStatus.FAILURE, "Missing credential ID in GetAssertion response"
        )

    server.authenticate_complete(
        state,
        credentials,
        get_assertion_response.credential_id,
        get_assertion_response.client_data,
        get_assertion_response.authenticator_data,
        get_assertion_response.signature,
    )

    return TestResult(TestStatus.SUCCESS)


def list_tests(selector: TestSelector) -> None:
    test_cases = selector.select()
    print(f"{len(test_cases)} test case(s) selected")
    for test_case in test_cases:
        print(f"- {test_case.name}: {test_case.description}")


def run_tests(ctx: TestContext, device: Nitrokey3Base, selector: TestSelector) -> bool:
    test_cases = selector.select()
    if not test_cases:
        raise CliException("No test cases selected", support_hint=False)

    results = []

    local_print("")
    local_print(f"Running tests for {device.name} at {device.path}")
    local_print("")

    n = len(test_cases)
    idx_len = len(str(n))
    name_len = max([len(test_case.name) for test_case in test_cases]) + 2
    description_len = max([len(test_case.description) for test_case in test_cases]) + 2
    status_len = max([len(status.name) for status in TestStatus]) + 2

    for (i, test_case) in enumerate(test_cases):
        try:
            result = test_case.fn(ctx, device)
        except Exception:
            result = TestResult(TestStatus.FAILURE, exc_info=sys.exc_info())
        results.append(result)

        idx = str(i + 1).rjust(idx_len)
        name = test_case.name.ljust(name_len)
        description = test_case.description.ljust(description_len)
        status = result.status.name.ljust(status_len)
        msg = ""
        if result.data:
            msg = str(result.data)
        elif result.exc_info[1]:
            logger.error(
                f"An exception occured during the execution of the test {test_case.name}:",
                exc_info=result.exc_info,
            )
            msg = str(result.exc_info[1])

        local_print(f"[{idx}/{n}]\t{name}\t{description}\t{status}\t{msg}")

    success = len([result for result in results if result.status == TestStatus.SUCCESS])
    skipped = len([result for result in results if result.status == TestStatus.SKIPPED])
    failed = len([result for result in results if result.status == TestStatus.FAILURE])
    local_print("")
    local_print(f"{n} tests, {success} successful, {skipped} skipped, {failed} failed")

    return all([result.status != TestStatus.FAILURE for result in results])
