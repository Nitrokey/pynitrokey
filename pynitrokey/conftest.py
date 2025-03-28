# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import copy
import logging
import pathlib
import secrets
from enum import Enum, IntEnum, auto
from functools import partial

import pytest
from _pytest.fixtures import FixtureRequest
from nitrokey.nk3.secrets_app import Instruction, SecretsApp

from pynitrokey.cli.exceptions import CliException
from pynitrokey.cli.nk3 import Context

CORPUS_PATH = "/tmp/corpus"


logger = logging.getLogger("main")
log = logger.debug


def _write_corpus(
    ins: Instruction, data: bytes, prefix: str = "", path: str = CORPUS_PATH
):
    corpus_name = f"{prefix}"
    corpus_path = f"{path}/{corpus_name}"
    if len(data) > 255:
        # Do not write records longer than 255 bytes
        return
    data = bytes([len(data)]) + data
    with open(corpus_path, "ba") as f:
        print(f"Writing corpus data to the path {corpus_path}")
        f.write(data)


def pytest_addoption(parser):
    parser.addoption(
        "--generate-fuzzing-corpus",
        action="store_true",
        default=False,
        help="Enable generation of fuzzing corpus for the oath-authenticator.",
    )
    parser.addoption(
        "--fuzzing-corpus-path",
        type=pathlib.Path,
        default=CORPUS_PATH,
        help=f"Path to store the generated fuzzing corpus. Default: {CORPUS_PATH}.",
    )


@pytest.fixture(scope="session")
def generate_corpus_args(request: FixtureRequest):
    return request.config.getoption(
        "--generate-fuzzing-corpus"
    ), request.config.getoption("--fuzzing-corpus-path")


@pytest.fixture(scope="function")
def corpus_func(request: FixtureRequest, generate_corpus_args):
    """
    This fixture has to be function-scoped, to get different prefix "pre" for the per-test output
    """
    generate_corpus, corpus_path = generate_corpus_args
    if generate_corpus:
        print(f"\n*** Generating corpus for Secrets App fuzzing at {corpus_path}")
        pathlib.Path(corpus_path).mkdir(exist_ok=True)
        # Add some random suffix to have separate outputs for parametrized test cases
        pre = secrets.token_bytes(4).hex()
        pre = f"{request.function.__name__}-{pre}"
        return partial(_write_corpus, prefix=pre, path=corpus_path)
    return None


@pytest.fixture(scope="session")
def dev():
    ctx = Context(None)
    try:
        return ctx.connect_device()
    except CliException as e:
        if "No Nitrokey 3 device found" in str(e):
            pytest.skip(f"Cannot connect to the Nitrokey 3 device. Error: {e}")


class CredEncryptionType(Enum):
    # This requires providing PIN for encryption to work
    PinBased = auto()
    # Standard encryption
    HardwareBased = auto()


@pytest.fixture(scope="function")
def secretsAppRaw(corpus_func, dev) -> SecretsApp:
    """
    Create Secrets App client with or without corpus files generations.
    No other functional alterations.
    """
    app = SecretsApp(dev, logfn=log)
    app.write_corpus_fn = corpus_func
    return app


@pytest.fixture(
    scope="function",
    params=[
        CredEncryptionType.HardwareBased,
        CredEncryptionType.PinBased,
    ],
    ids=lambda x: f"Key{str(x).split('.')[-1]}",
)
def secretsApp(request, secretsAppRaw: SecretsApp) -> SecretsApp:
    """
    Create Secrets App client in two forms, w/ or w/o PIN-based encryption
    """
    app = copy.deepcopy(secretsAppRaw)

    credentials_type: CredEncryptionType = request.param
    app.verify_pin_raw_always = app.verify_pin_raw  # type: ignore[attr-defined]
    if credentials_type == CredEncryptionType.PinBased:
        # Make all credentials registered with the PIN-based encryption
        # Leave verify_pin_raw() working
        app.register = partial(app.register, pin_based_encryption=True)  # type: ignore[method-assign]
    elif credentials_type == CredEncryptionType.HardwareBased:
        # Make all verify_pin_raw() calls dormant
        # All credentials should register themselves as not requiring PIN
        app.verify_pin_raw = lambda x: secretsAppRaw.logfn(  # type: ignore[method-assign]
            "Skipping verify_pin_raw() call due to fixture configuration"
        )
    else:
        raise RuntimeError("Wrong param value")

    app._metadata["fixture_type"] = credentials_type

    return app


@pytest.fixture(scope="function")
def secretsAppResetLogin(secretsApp: SecretsApp) -> SecretsApp:
    secretsApp.reset()
    secretsApp.set_pin_raw(PIN)
    secretsApp.verify_pin_raw(PIN)
    return secretsApp


@pytest.fixture(scope="function")
def secretsAppNoLog(secretsApp: SecretsApp) -> SecretsApp:
    return secretsApp


FEATURE_BRUTEFORCE_PROTECTION_ENABLED = False
DELAY_AFTER_FAILED_REQUEST_SECONDS = 2
CREDID = "CRED ID"
CREDID2 = "CRED ID2"
SECRET = b"00" * 20
DIGITS = 6
CHALLENGE = 1000
HOTP_WINDOW_SIZE = 9
PIN = "12345678"
PIN2 = "123123123"
PIN_ATTEMPT_COUNTER_DEFAULT = 8
FEATURE_CHALLENGE_RESPONSE_ENABLED = False
CHALLENGE_RESPONSE_COMMANDS = {Instruction.Validate, Instruction.SetCode}
CALCULATE_ALL_COMMANDS = {Instruction.CalculateAll}
