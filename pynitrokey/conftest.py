import logging

import pytest

from pynitrokey.cli.nk3 import Context
from pynitrokey.nk3.otp_app import OTPApp

logging.basicConfig(
    encoding="utf-8", level=logging.DEBUG, handlers=[logging.StreamHandler()]
)


@pytest.fixture(scope="session")
def otpApp():
    ctx = Context(None)
    return OTPApp(ctx.connect_device(), logfn=print)


CREDID = "CRED ID"
SECRET = b"00" * 20
DIGITS = 6
CHALLENGE = 1000
