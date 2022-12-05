import hashlib
import logging
import os
import pathlib
import uuid
from functools import partial

import pytest
import secrets
from _pytest.fixtures import FixtureRequest

from pynitrokey.cli.nk3 import Context
from pynitrokey.nk3.otp_app import Instruction, OTPApp

logging.basicConfig(
    encoding="utf-8", level=logging.DEBUG, handlers=[logging.StreamHandler()]
)


def _write_corpus(ins: Instruction, data: bytes, prefix: str = ""):
    # corpus_name = f"{prefix}{ins}-{hashlib.sha1(data).digest().hex()}"
    corpus_name = f"{prefix}"
    corpus_path = f"/tmp/corpus/{corpus_name}"
    if len(data) > 255:
        return
    data = bytes([len(data)]) + data
    with open(corpus_path, "ba") as f:
        f.write(data)


@pytest.fixture(scope="function")
def corpus_func(request: FixtureRequest):
    pathlib.Path("/tmp/corpus").mkdir(exist_ok=True)
    if os.environ.get("NK_FUZZ") is not None:
        pre = secrets.token_bytes(4).hex()
        pre = f"{request.function.__name__}-{pre}"
        return partial(_write_corpus, prefix=pre)
    return None


@pytest.fixture(scope="session")
def dev():
    ctx = Context(None)
    return ctx.connect_device()


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
