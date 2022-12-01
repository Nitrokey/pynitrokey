import hashlib
import logging
import os
import pathlib

import pytest

from pynitrokey.cli.nk3 import Context
from pynitrokey.nk3.otp_app import Instruction, OTPApp

logging.basicConfig(
    encoding="utf-8", level=logging.DEBUG, handlers=[logging.StreamHandler()]
)


def _write_corpus(ins: Instruction, data: bytes):
    corpus_name = f"{ins}-{hashlib.sha1(data).digest().hex()}"
    corpus_path = f"/tmp/corpus/{corpus_name}"
    with open(corpus_path, "bw") as f:
        f.write(data)


def setup_for_making_corpus(app):
    pathlib.Path("/tmp/corpus").mkdir(exist_ok=True)
    if os.environ.get("NK_FUZZ") is not None:
        app.write_corpus_fn = _write_corpus


@pytest.fixture(scope="session")
def otpApp():
    ctx = Context(None)
    app = OTPApp(ctx.connect_device(), logfn=print)
    setup_for_making_corpus(app)
    return app


@pytest.fixture(scope="session")
def otpAppNoLog():
    ctx = Context(None)
    app = OTPApp(ctx.connect_device())
    setup_for_making_corpus(app)
    return app


CREDID = "CRED ID"
SECRET = b"00" * 20
DIGITS = 6
CHALLENGE = 1000
HOTP_WINDOW_SIZE = 9
