"""
Tests for the OTP application interface placed in otp_app.py.
Requires a live device, or a USB-IP simulation.
"""

import binascii
import hashlib

import fido2
import pytest

from pynitrokey.conftest import CHALLENGE, CREDID, DIGITS, SECRET
from pynitrokey.nk3.otp_app import Algorithm, Kind


def test_list(otpApp):
    """
    List saved credentials. Simple test.
    """
    otpApp.list()


def test_register(otpApp):
    """
    Register credential with the given id and properties. Simple test.
    """
    otpApp.register(CREDID, SECRET, DIGITS)


def test_calculate(otpApp):
    """
    Run calculation on the default credential id. Simple test.
    """
    code = otpApp.calculate(CREDID, CHALLENGE)
    print(code)


def test_delete(otpApp):
    """
    Remove credential with the given id. Simple test.
    """
    otpApp.delete(CREDID)


def test_delete_nonexisting(otpApp):
    """
    Should not fail when trying to remove non-existing credential id.
    """
    otpApp.delete(CREDID)


def test_reset(otpApp):
    """
    Clear credentials storage. Simple test.
    """
    otpApp.reset()


def test_list_changes(otpApp):
    """
    Test how the list of credential changes, when one is added or removed, and after a reset.
    """
    cred1 = b"TESTCRED"
    cred2 = b"ANOTHERCRED"

    otpApp.reset()
    assert not otpApp.list()
    otpApp.register(cred1, SECRET, DIGITS)
    assert cred1 in otpApp.list()
    otpApp.register(cred2, SECRET, DIGITS)
    assert cred2 in otpApp.list()

    otpApp.delete(cred2)
    assert cred2 not in otpApp.list()
    assert cred1 in otpApp.list()

    otpApp.reset()
    assert not otpApp.list()


@pytest.mark.parametrize(
    "secret",
    [
        "3132333435363738393031323334353637383930",
        "00" * 19 + "ff",
        "002EF43F51AFA97BA2B46418768123C9E1809A5B",
        "002EF43F51AFA97BA2B46418768123C9E1809A5B" * 2,
    ],
)
@pytest.mark.parametrize(
    "start_counter",
    [
        0,
        0xFF + 1,
        0xFFFF + 1,
        0xFFFFFF + 1,
        0xFFFFFFFF - 10,
    ],
)
def test_calculated_codes_hotp(otpApp, secret, start_counter):
    """
    Test HOTP codes against another OTP library.
    Use different secret and start counter values.
    """
    oath = pytest.importorskip("oath")
    secretb = binascii.a2b_hex(secret)
    otpApp.reset()
    otpApp.register(
        CREDID,
        secretb,
        digits=6,
        kind=Kind.Hotp,
        algo=Algorithm.Sha1,
        initial_counter_value=start_counter,
    )
    lib_at = lambda t: oath.hotp(secret, counter=t, format="dec6").encode()
    for i in range(10):
        i = i + start_counter
        assert otpApp.calculate(CREDID, i) == lib_at(i)


@pytest.mark.parametrize(
    "secret",
    [
        "3132333435363738393031323334353637383930",
        "00" * 19 + "ff",
        "002EF43F51AFA97BA2B46418768123C9E1809A5B",
        "002EF43F51AFA97BA2B46418768123C9E1809A5B" * 2,
    ],
)
def test_calculated_codes_totp(otpApp, secret):
    """
    Test TOTP codes against another OTP library.
    """
    oath = pytest.importorskip("oath")
    secretb = binascii.a2b_hex(secret)
    otpApp.reset()
    otpApp.register(CREDID, secretb, digits=6, kind=Kind.Totp, algo=Algorithm.Sha1)
    lib_at = lambda t: oath.totp(secret, format="dec6", period=30, t=t * 30).encode()
    for i in range(10):
        assert otpApp.calculate(CREDID, i) == lib_at(i)


def test_calculated_codes_test_vector(otpApp):
    """
    Check output against RFC4226 test vectors, as provided in
    https://www.rfc-editor.org/rfc/rfc4226#page-32
    """
    secret = "3132333435363738393031323334353637383930"
    secretb = binascii.a2b_hex(secret)

    test_vectors = """
       Count    Hexadecimal    Decimal        HOTP
       0        4c93cf18       1284755224     755224
       1        41397eea       1094287082     287082
       2         82fef30        137359152     359152
       3        66ef7655       1726969429     969429
       4        61c5938a       1640338314     338314
       5        33c083d4        868254676     254676
       6        7256c032       1918287922     287922
       7         4e5b397         82162583     162583
       8        2823443f        673399871     399871
       9        2679dc69        645520489     520489"""
    # select last column only, starting after the header line
    codes = [x.split()[-1].encode() for x in test_vectors.splitlines()[2:]]

    otpApp.reset()
    otpApp.register(CREDID, secretb, digits=6, kind=Kind.Hotp, algo=Algorithm.Sha1)
    for i in range(10):
        assert otpApp.calculate(CREDID, i) == codes[i]


def test_reverse_hotp(otpApp):
    """
    Test passing conditions for the HOTP reverse check
    Check against RFC4226 test vectors, as provided in
    https://www.rfc-editor.org/rfc/rfc4226#page-32
    """
    secret = "3132333435363738393031323334353637383930"
    secretb = binascii.a2b_hex(secret)

    test_vectors = """
       Count    Hexadecimal    Decimal        HOTP
       0        4c93cf18       1284755224     755224
       1        41397eea       1094287082     287082
       2         82fef30        137359152     359152
       3        66ef7655       1726969429     969429
       4        61c5938a       1640338314     338314
       5        33c083d4        868254676     254676
       6        7256c032       1918287922     287922
       7         4e5b397         82162583     162583
       8        2823443f        673399871     399871
       9        2679dc69        645520489     520489"""
    # select last column only, starting after the header line
    codes = [x.split()[-1].encode() for x in test_vectors.splitlines()[2:]]

    otpApp.reset()
    otpApp.register(CREDID, secretb, digits=6, kind=Kind.Hotp, algo=Algorithm.Sha1)
    for i in range(10):
        c = bytes(codes[i])
        assert otpApp.verify_code(CREDID, c)


def test_reverse_hotp_failure(otpApp):
    """
    Test failing conditions for the HOTP reverse check
    """
    secret = "3132333435363738393031323334353637383930"
    secretb = binascii.a2b_hex(secret)

    codes = [str(x) for x in range(10)]

    otpApp.reset()
    otpApp.register(CREDID, secretb, digits=6, kind=Kind.Hotp, algo=Algorithm.Sha1)
    for i in range(3):
        c = codes[i].encode()
        with pytest.raises(fido2.ctap.CtapError):
            assert not otpApp.verify_code(CREDID, c)

    # Test parsing too long code
    with pytest.raises(fido2.ctap.CtapError):
        assert not otpApp.verify_code(CREDID, "1" * 7)

    otpApp.register(CREDID, secretb, digits=7, kind=Kind.Hotp, algo=Algorithm.Sha1)
    with pytest.raises(fido2.ctap.CtapError):
        assert not otpApp.verify_code(CREDID, "1" * 8)

    otpApp.register(CREDID, secretb, digits=8, kind=Kind.Hotp, algo=Algorithm.Sha1)
    with pytest.raises(fido2.ctap.CtapError):
        assert not otpApp.verify_code(CREDID, "1" * 9)

    # TODO test that counter has moved, and it accepts the 3+1+1+1 = 6th code


@pytest.mark.skip(reason="not implemented")
def test_reverse_hotp_window(otpApp):
    pass


@pytest.mark.parametrize(
    "digits",
    [6, 8],
)
@pytest.mark.parametrize(
    "algorithm",
    [
        (Algorithm.Sha1, hashlib.sha1),
        (Algorithm.Sha256, hashlib.sha256),
        # (Algorithm.Sha512, hashlib.sha512),  # unsupported by the OTP App in the firmware
    ],
)
@pytest.mark.parametrize(
    "secret",
    [
        "3132333435363738393031323334353637383930",
        "002EF43F51AFA97BA2B46418768123C9E1809A5B" * 2,
    ],
)
def test_calculated_codes_totp_hash_digits(otpApp, secret, algorithm, digits):
    """
    Test TOTP codes against another OTP library, with different hash algorithms and digits count.
    Test vector secret, and a random 40 bytes value.
    """
    algo_app, algo_oath = algorithm
    oath = pytest.importorskip("oath")
    secretb = binascii.a2b_hex(secret)
    otpApp.reset()
    otpApp.register(CREDID, secretb, digits=digits, kind=Kind.Totp, algo=algo_app)
    lib_at = lambda t: oath.totp(
        secret, format="dec" + str(digits), period=30, t=t * 30, hash=algo_oath
    ).encode()
    for i in range(10):
        assert otpApp.calculate(CREDID, i) == lib_at(i)
