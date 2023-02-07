import logging
import pathlib
import secrets
from functools import partial

import pytest
from _pytest.fixtures import FixtureRequest

from pynitrokey.cli import CliException
from pynitrokey.cli.nk3 import Context
from pynitrokey.nk3.otp_app import Instruction, OTPApp

CORPUS_PATH = "/tmp/corpus"

logging.basicConfig(
    encoding="utf-8", level=logging.DEBUG, handlers=[logging.StreamHandler()]
)


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


@pytest.fixture(scope="function")
def otpApp(corpus_func, dev):
    app = OTPApp(dev, logfn=print)
    app.write_corpus_fn = corpus_func
    return app


@pytest.fixture(scope="function")
def otpAppNoLog(corpus_func, dev):
    app = OTPApp(dev)
    app.write_corpus_fn = corpus_func
    return app


CREDID = "CRED ID"
SECRET = b"00" * 20
DIGITS = 6
CHALLENGE = 1000
HOTP_WINDOW_SIZE = 9
