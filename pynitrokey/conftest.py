import copy
import logging
import pathlib
import secrets
from enum import Enum, IntEnum, auto
from functools import partial

import pytest
from _pytest.fixtures import FixtureRequest

from pynitrokey.cli import CliException
from pynitrokey.cli.nk3 import Context
from pynitrokey.nk3.secrets_app import Instruction, SecretsApp

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


# @pytest.fixture(scope="function")
@pytest.fixture(scope="function")
def corpus_func(request: FixtureRequest, generate_corpus_args):
    """
    This fixture has to be function-scoped, to get different prefix "pre" for the per-test output
    """
    generate_corpus, corpus_path = generate_corpus_args
    if generate_corpus:
        print(
            f"\n*** Generating corpus for oath-authenticator fuzzing at {corpus_path}"
        )
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


class CredentialsType(Enum):
    pin_based_encryption = auto()
    no_pin_based_encryption = auto()


@pytest.fixture(scope="function")
def secretsAppRaw(corpus_func, dev):
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
        CredentialsType.no_pin_based_encryption,
        CredentialsType.pin_based_encryption,
    ],
)
def secretsApp(request, secretsAppRaw):
    """
    Create Secrets App client in two forms, w/ or w/o PIN-based encryption
    """
    app = copy.deepcopy(secretsAppRaw)

    credentials_type: CredentialsType = request.param
    if credentials_type == CredentialsType.pin_based_encryption:
        # Make all credentials registered with the PIN-based encryption
        # Leave verify_pin_raw() working
        app.register = partial(app.register, pin_based_encryption=True)
    elif credentials_type == CredentialsType.no_pin_based_encryption:
        # Make all verify_pin_raw() calls dormant
        # All credentials should register themselves as not requiring PIN
        app.verify_pin_raw = lambda x: secretsAppRaw.logfn(
            "Skipping verify_pin_raw() call"
        )
    else:
        raise RuntimeError("Wrong param value")

    app.fixture_type = credentials_type

    return app


@pytest.fixture(scope="function")
def secretsAppResetLogin(secretsApp):
    secretsApp.reset()
    secretsApp.set_pin_raw(PIN)
    secretsApp.verify_pin_raw(PIN)
    return secretsApp


@pytest.fixture(scope="function")
def secretsAppNoLog(secretsApp):
    return secretsApp


DELAY_AFTER_FAILED_REQUEST_SECONDS = 5
CREDID = "CRED ID"
SECRET = b"00" * 20
DIGITS = 6
CHALLENGE = 1000
HOTP_WINDOW_SIZE = 9
PIN = "12345678"
PIN2 = "123123123"
PIN_ATTEMPT_COUNTER_DEFAULT = 8
FEATURE_CHALLENGE_RESPONSE_ENABLED = False
