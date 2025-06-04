# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import logging
import platform
import sys
from dataclasses import dataclass
from enum import Enum, auto, unique
from types import TracebackType
from typing import Callable, Iterable, Optional, Sequence, Tuple, Type, Union

from nitrokey.trussed import TrussedBase, Version

from pynitrokey.cli.exceptions import CliException
from pynitrokey.fido2 import device_path_to_str
from pynitrokey.helpers import local_print

logger = logging.getLogger(__name__)

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


TestCaseFn = Callable[[TestContext, TrussedBase], TestResult]


class TestCase:
    def __init__(self, name: str, description: str, fn: TestCaseFn) -> None:
        self.name = name
        self.description = description
        self.fn = fn


def test_case(name: str, description: str) -> Callable[[TestCaseFn], TestCase]:
    def decorator(func: TestCaseFn) -> TestCase:
        return TestCase(name, description, func)

    return decorator


def filter_test_cases(
    test_cases: Sequence[TestCase], names: Iterable[str]
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

    def select(self, test_cases: Sequence[TestCase]) -> list[TestCase]:
        if self.only:
            return list(filter_test_cases(test_cases, self.only))

        selected = []
        for test_case in test_cases:
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


def list_tests(
    selector: TestSelector,
    test_cases: Sequence[TestCase],
) -> None:
    test_cases = selector.select(test_cases)
    print(f"{len(test_cases)} test case(s) selected")
    for test_case in test_cases:
        print(f"- {test_case.name}: {test_case.description}")


def run_tests(
    ctx: TestContext,
    device: TrussedBase,
    selector: TestSelector,
    test_cases: Sequence[TestCase],
) -> bool:
    test_cases = selector.select(test_cases)
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

    for i, test_case in enumerate(test_cases):
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
