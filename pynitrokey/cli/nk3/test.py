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
from enum import Enum, auto, unique
from hashlib import sha256
from types import TracebackType
from typing import Callable, List, Optional, Tuple, Type, Union

from pynitrokey.fido2 import device_path_to_str
from pynitrokey.helpers import local_print
from pynitrokey.nk3.base import Nitrokey3Base
from pynitrokey.nk3.device import Nitrokey3Device
from pynitrokey.nk3.utils import Version

logger = logging.getLogger(__name__)


TEST_CASES = []

FIDO2_CERT_HASHES = {
    Version(0, 1, 0): [
        "ad8fd1d16f59104b9e06ef323cc03f777ed5303cd421a101c9cb00bb3fdf722d"
    ],
    Version(1, 0, 3): [
        "aa1cb760c2879530e7d7fed3da75345d25774be9cfdbbcbd36fdee767025f34b"
    ],
}


ExcInfo = Tuple[Type[BaseException], BaseException, TracebackType]


def get_fido2_cert_hashes(version: Version) -> Optional[List[str]]:
    versions = [v for v in FIDO2_CERT_HASHES if version >= v]
    if versions:
        return FIDO2_CERT_HASHES[max(versions)]
    else:
        return None


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
    def __init__(self, name: str, fn: TestCaseFn) -> None:
        self.name = name
        self.fn = fn


def test_case(name: str) -> Callable[[TestCaseFn], TestCaseFn]:
    def decorator(func: TestCaseFn) -> TestCaseFn:
        TEST_CASES.append(TestCase(name, func))
        return func

    return decorator


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


@test_case("UUID query")
def test_uuid_query(ctx: TestContext, device: Nitrokey3Base) -> TestResult:
    uuid = device.uuid()
    uuid_str = f"{uuid:X}" if uuid else "[not supported]"
    return TestResult(TestStatus.SUCCESS, uuid_str)


@test_case("Firmware version query")
def test_firmware_version_query(ctx: TestContext, device: Nitrokey3Base) -> TestResult:
    if not isinstance(device, Nitrokey3Device):
        return TestResult(TestStatus.SKIPPED)
    version = device.version()
    ctx.firmware_version = version
    return TestResult(TestStatus.SUCCESS, str(version))


@test_case("FIDO2")
def test_fido2(ctx: TestContext, device: Nitrokey3Base) -> TestResult:
    if not isinstance(device, Nitrokey3Device):
        return TestResult(TestStatus.SKIPPED)

    # Based on https://github.com/Yubico/python-fido2/blob/142587b3e698ca0e253c78d75758fda635cac51a/examples/credential.py

    from fido2.client import Fido2Client, PinRequiredError
    from fido2.server import Fido2Server

    client = Fido2Client(device.device, "https://example.com")
    server = Fido2Server(
        {"id": "example.com", "name": "Example RP"}, attestation="direct"
    )
    uv = "discouraged"
    user = {"id": b"user_id", "name": "A. User"}

    create_options, state = server.register_begin(
        user, user_verification=uv, authenticator_attachment="cross-platform"
    )

    local_print("Please press the touch button on the device ...")
    try:
        make_credential_result = client.make_credential(
            create_options["publicKey"], pin=ctx.pin
        )
    except PinRequiredError:
        return TestResult(
            TestStatus.FAILURE,
            "PIN activated -- please set the --pin option",
        )
    cert = make_credential_result.attestation_object.att_statement["x5c"]
    cert_hash = sha256(cert[0]).digest().hex()

    if ctx.firmware_version:
        expected_cert_hashes = get_fido2_cert_hashes(ctx.firmware_version)
        if expected_cert_hashes and cert_hash not in expected_cert_hashes:
            return TestResult(
                TestStatus.FAILURE,
                f"Unexpected FIDO2 cert hash for version {ctx.firmware_version}: {cert_hash}",
            )

    auth_data = server.register_complete(
        state,
        make_credential_result.client_data,
        make_credential_result.attestation_object,
    )
    credentials = [auth_data.credential_data]

    request_options, state = server.authenticate_begin(
        credentials, user_verification=uv
    )

    local_print("Please press the touch button on the device ...")
    get_assertion_result = client.get_assertion(
        request_options["publicKey"], pin=ctx.pin
    )
    get_assertion_response = get_assertion_result.get_response(0)

    server.authenticate_complete(
        state,
        credentials,
        get_assertion_response.credential_id,
        get_assertion_response.client_data,
        get_assertion_response.authenticator_data,
        get_assertion_response.signature,
    )

    return TestResult(TestStatus.SUCCESS)


def run_tests(ctx: TestContext, device: Nitrokey3Base) -> bool:
    results = []

    local_print("")
    local_print(f"Running tests for {device.name} at {device.path}")
    local_print("")

    n = len(TEST_CASES)
    idx_len = len(str(n))
    name_len = max([len(test_case.name) for test_case in TEST_CASES]) + 2
    status_len = max([len(status.name) for status in TestStatus]) + 2

    for (i, test_case) in enumerate(TEST_CASES):
        try:
            result = test_case.fn(ctx, device)
        except Exception:
            result = TestResult(TestStatus.FAILURE, exc_info=sys.exc_info())
        results.append(result)

        idx = str(i + 1).rjust(idx_len)
        name = test_case.name.ljust(name_len)
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

        local_print(f"[{idx}/{n}]\t{name}\t{status}\t{msg}")

    success = len([result for result in results if result.status == TestStatus.SUCCESS])
    skipped = len([result for result in results if result.status == TestStatus.SKIPPED])
    failed = len([result for result in results if result.status == TestStatus.FAILURE])
    local_print("")
    local_print(f"{n} tests, {success} successful, {skipped} skipped, {failed} failed")

    return all([result.status != TestStatus.FAILURE for result in results])
