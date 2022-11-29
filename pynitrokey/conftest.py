import logging
import os

import pytest

from pynitrokey.cli.nk3 import Context
from pynitrokey.nk3.otp_app import OTPApp

logging.basicConfig(
    encoding="utf-8", level=logging.DEBUG, handlers=[logging.StreamHandler()]
)


@pytest.fixture(scope="session")
def otpApp():
    ctx = Context(None)
    app = OTPApp(ctx.connect_device(), logfn=print)
    # app.write_corpus = os.environ.get("NK_FUZZ") is not None
    # TODO inject functor to run on the data send
    app.write_corpus = False
    return app


@pytest.fixture(scope="session")
def otpAppNoLog():
    ctx = Context(None)
    app = OTPApp(ctx.connect_device())
    return app


CREDID = "CRED ID"
SECRET = b"00" * 20
DIGITS = 6
CHALLENGE = 1000
HOTP_WINDOW_SIZE = 9
