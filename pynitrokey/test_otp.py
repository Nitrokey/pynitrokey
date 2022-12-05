"""
Tests for the OTP application interface placed in otp_app.py.
Requires a live device, or a USB-IP simulation.
"""

import binascii
import datetime
import hashlib
import hmac
import time
from datetime import timedelta
from sys import stderr

import fido2
import pytest
import tlv8

from pynitrokey.conftest import CHALLENGE, CREDID, DIGITS, HOTP_WINDOW_SIZE, SECRET
from pynitrokey.nk3.otp_app import (
    Algorithm,
    Instruction,
    Kind,
    OTPAppException,
    RawBytes,
    Tag,
)


def test_reset(otpApp):
    """
    Clear credentials' storage. Simple test.
    """
    otpApp.reset()


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
    otpApp.register(
        CREDID, secretb, digits=6, kind=Kind.HotpReverse, algo=Algorithm.Sha1
    )
    for i in range(10):
        c = int(codes[i])
        assert otpApp.verify_code(CREDID, c)


def test_reverse_hotp_failure(otpApp):
    """
    Test failing conditions for the HOTP reverse check
    """
    secret = "3132333435363738393031323334353637383930"
    secretb = binascii.a2b_hex(secret)

    codes = [x for x in range(10)]

    otpApp.reset()
    otpApp.register(
        CREDID, secretb, digits=6, kind=Kind.HotpReverse, algo=Algorithm.Sha1
    )
    for i in range(3):
        c = codes[i]
        with pytest.raises(OTPAppException, match="VerificationFailed"):
            assert not otpApp.verify_code(CREDID, c)

    # Test parsing too long code
    with pytest.raises(OTPAppException, match="VerificationFailed"):
        assert not otpApp.verify_code(CREDID, 10**5)

    otpApp.register(CREDID, secretb, digits=7, kind=Kind.Hotp, algo=Algorithm.Sha1)
    with pytest.raises(OTPAppException, match="ConditionsOfUseNotSatisfied"):
        assert not otpApp.verify_code(CREDID, 10**6)

    otpApp.register(CREDID, secretb, digits=8, kind=Kind.Hotp, algo=Algorithm.Sha1)
    with pytest.raises(OTPAppException, match="ConditionsOfUseNotSatisfied"):
        assert not otpApp.verify_code(CREDID, 10**7)


@pytest.mark.parametrize(
    "start_value",
    [0, 0xFFFF, 0xFFFFFFFF - HOTP_WINDOW_SIZE - 2],
)
@pytest.mark.parametrize(
    "offset",
    [0, 1, HOTP_WINDOW_SIZE - 1, HOTP_WINDOW_SIZE, HOTP_WINDOW_SIZE + 1],
)
def test_reverse_hotp_window(otpApp, offset, start_value):
    """
    https://github.com/Nitrokey/nitrokey-hotp-verification#verifying-hotp-code
    Solution contains a mean to avoid desynchronization between the host's and device's counters. Device calculates
    up to 9 values ahead of its current counter to find the matching code (in total it calculates HOTP code for 10
    subsequent counter positions). In case:

     - no code would match - the on-device counter will not be changed;
     - code would match, but with some counter's offset (up to 9) - the on-device counter will be set to matched code-generated HOTP counter and incremented by 1;
     - code would match, and the code matches counter without offset - the counter will be incremented by 1;
     - counter overflows while calculating the code within the specified window - error is returned, and in that case a new credential with reset counter should be registered

    Device will stop verifying the HOTP codes in case, when the difference between the host and on-device counters
    will be greater or equal to 10.
    """
    oath = pytest.importorskip("oath")
    secret = "3132333435363738393031323334353637383930"
    secretb = binascii.a2b_hex(secret)
    otpApp.reset()
    otpApp.register(
        CREDID,
        secretb,
        digits=6,
        kind=Kind.HotpReverse,
        algo=Algorithm.Sha1,
        initial_counter_value=start_value,
    )
    lib_at = lambda t: oath.hotp(secret, counter=t, format="dec6").encode()
    code_to_send = lib_at(start_value + offset)
    code_to_send = int(code_to_send)
    if offset > HOTP_WINDOW_SIZE:
        # calls with offset bigger than HOTP_WINDOW_SIZE should fail
        with pytest.raises(OTPAppException, match="VerificationFailed"):
            otpApp.verify_code(CREDID, code_to_send)
    else:
        # check if this code will be accepted on the given offset
        assert otpApp.verify_code(CREDID, code_to_send)
        # the same code should not be accepted again, unless counted got saturated
        is_counter_saturated = (
            start_value == (0xFFFFFFFF - HOTP_WINDOW_SIZE)
            and offset == HOTP_WINDOW_SIZE
        )
        if not is_counter_saturated:
            with pytest.raises(
                OTPAppException,
                match="UnspecifiedPersistentExecutionError|VerificationFailed",
            ):
                # send the same code once again
                otpApp.verify_code(CREDID, code_to_send)
            # test the very next value - should be accepted
            code_to_send = lib_at(start_value + offset + 1)
            code_to_send = int(code_to_send)
            assert otpApp.verify_code(CREDID, code_to_send)
        else:
            # counter got saturated, error code will be returned
            assert otpApp.verify_code(CREDID, code_to_send)
            assert otpApp.verify_code(CREDID, code_to_send)
            assert otpApp.verify_code(CREDID, code_to_send)


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


@pytest.mark.parametrize(
    "kind",
    [Kind.Totp, Kind.Hotp],
)
def test_load(otpApp, kind: Kind):
    """
    Load tests to see how much OTP credentials we can store,
    and if using of them is not broken with the full FS.
    """
    secret = "3132333435363738393031323334353637383930"
    oath = pytest.importorskip("oath")
    secretb = binascii.a2b_hex(secret)
    otpApp.reset()

    credentials_registered = 0

    for i in range(100000):
        name = f"LOAD{i}"
        try:
            otpApp.register(name, secretb, digits=6, kind=kind, initial_counter_value=i)
        except Exception as e:
            print(f"{e}")
            print(f"Registered {i} credentials")
            size = len(secret) + len(name)
            print(f"Single Credential size: {size} B")
            print(f"Total size: {size*i} B")
            credentials_registered = i
            break

    assert (
        credentials_registered > 100
    ), "Expecting being able to register at least 100 OTP credentials"

    lib_at = lambda t: oath.totp(secret, format="dec6", period=30, t=t * 30).encode()
    if kind == Kind.Hotp:
        lib_at = lambda t: oath.hotp(secret, format="dec6", counter=t).encode()

    for i in range(credentials_registered):
        # At this point device should respond to our calls, despite being full, fail otherwise
        # Iterate over credentials and check code at given challenge
        name = f"LOAD{i}"
        assert otpApp.calculate(name, i) == lib_at(i)

    l = otpApp.list()
    assert len(l) == credentials_registered


@pytest.mark.xfail
def test_send_rubbish(otpApp):
    """Check if the application crashes, when sending unexpected data for the given command"""
    otpApp.reset()
    otpApp.register(CREDID, SECRET, DIGITS)

    # Just randomly selected 20 bytes of non-TLV data
    invalid_data = bytes([0x11] * 20)
    for _ in range(3):
        with pytest.raises(fido2.ctap.CtapError):
            otpApp._send_receive_inner(invalid_data)
    otpApp.list()

    # Reset and List commands do not parse
    for ins in set(Instruction).difference({Instruction.Reset, Instruction.List}):
        with pytest.raises(fido2.ctap.CtapError):
            structure = [
                RawBytes([0x02, 0x02]),
            ]
            otpApp._send_receive(ins, structure)
    otpApp.list()


def test_too_long_message(otpApp):
    """
    Check device's response for the too long message
    """
    otpApp.reset()
    otpApp.register(CREDID, SECRET, DIGITS)
    otpApp.list()

    too_long_name = b"a" * 253
    with pytest.raises(OTPAppException, match="IncorrectDataParameter"):
        structure = [
            tlv8.Entry(Tag.CredentialId.value, too_long_name),
        ]
        otpApp._send_receive(Instruction.Put, structure)
    otpApp.list()


@pytest.mark.xfail
def test_too_long_message2(otpApp):
    """
    Test how long the secret could be (WIP)
    """
    otpApp.reset()
    otpApp.register(CREDID, SECRET, DIGITS)
    otpApp.list()

    too_long_name = b"a" * 256
    additional_space = 100
    otpApp.register(too_long_name[: -len(SECRET) - additional_space], SECRET, DIGITS)
    # find out the maximum secret length - 126 bytes?
    for i in range(255):
        print(i)
        otpApp.reset()
        otpApp.register(CREDID, too_long_name[:i], DIGITS)


def test_status(otpApp):
    """
    Simple test for getting device's status
    """
    print(otpApp.select())


def test_set_code(otpApp):
    """
    Simple test for setting the proper code on the device.
    """
    SECRET = b"1" * 20
    CHALLENGE = b"1234"

    otpApp.reset()
    state = otpApp.select()
    print(state)
    assert state.algorithm is None
    assert state.challenge is None

    response = hmac.HMAC(key=SECRET, msg=CHALLENGE, digestmod="sha1").digest()
    otpApp.set_code_raw(SECRET, CHALLENGE, response)

    state = otpApp.select()
    print(state)
    assert state.challenge is not None
    assert state.algorithm is not None


def test_set_code_and_validate(otpApp):
    """
    Test device's behavior when the validation code is set.
    Non-authorized calls should be rejected, except for the selected.
    Authorization should be valid only until the next call.

    Authorization is needed for all the listed commands except for RESET and VALIDATE:
         Required               Not required
         PUT 0x01               RESET 0x04 N
         DELETE 0x02            VALIDATE 0xa3 N
         SET CODE 0x03
         LIST 0xa1
         CALCULATE 0xa2
         CALCULATE ALL 0xa4
         SEND REMAINING 0xa5
    Details:
    - https://developers.yubico.com/OATH/YKOATH_Protocol.html
    """

    # The secret in production should be:
    #   SECRET = PBKDF2(USER_PASSPHRASE || DEVICEID, 1000)[:16]
    SECRET = b"1" * 20
    CHALLENGE = b"12345678"  # in production should be random 8 bytes

    # Device should be in the non-protected mode, and list command is allowed
    otpApp.reset()
    otpApp.list()

    # Set the code, and require validation before regular calls from now on
    response = hmac.HMAC(key=SECRET, msg=CHALLENGE, digestmod="sha1").digest()
    otpApp.set_code_raw(SECRET, CHALLENGE, response)

    # Make sure all the expected commands are failing, as in specification
    with pytest.raises(OTPAppException, match="ConditionsOfUseNotSatisfied"):
        otpApp.list()

    for ins in set(Instruction) - {Instruction.Reset, Instruction.Validate}:
        # TODO check for the exact error code
        with pytest.raises(
            OTPAppException,
            match="IncorrectDataParameter|InstructionNotSupportedOrInvalid|NotFound|ConditionsOfUseNotSatisfied",
        ):
            structure = [RawBytes([0x02] * 10)]
            otpApp._send_receive(ins, structure)

    # Each guarded command has to prepended by the validation call
    # Run "list" command, with validation first
    state = otpApp.select()
    response_validate = hmac.HMAC(
        key=SECRET, msg=state.challenge, digestmod="sha1"
    ).digest()
    otpApp.validate_raw(challenge=state.challenge, response=response_validate)
    otpApp.list()

    # Make sure another command call is not allowed
    with pytest.raises(OTPAppException, match="ConditionsOfUseNotSatisfied"):
        otpApp.list()

    # Test running "list" command again
    state = otpApp.select()
    response_validate = hmac.HMAC(
        key=SECRET, msg=state.challenge, digestmod="sha1"
    ).digest()
    otpApp.validate_raw(challenge=state.challenge, response=response_validate)
    otpApp.list()

    # Reset should be allowed
    otpApp.reset()
    state = otpApp.select()
    assert state.challenge is None


@pytest.mark.skip(reason="This test takes long time")
def test_revhotp_bruteforce(otpAppNoLog):
    """
    This test implements practical brute-forcing of the codes values.
    In case multiple devices use the same secret, stealing and brute-forcing answers on one
    could help with the other.
    """
    otpApp = otpAppNoLog
    otpApp.reset()
    otpApp.register(
        CREDID, SECRET, digits=6, kind=Kind.HotpReverse, algo=Algorithm.Sha1
    )
    start_time = time.time()
    code_start = 1_000_000

    from tqdm import tqdm, trange

    for current_code in trange(code_start, 0, -1):
        tqdm.write(f"Trying code {current_code}")
        try:
            otpApp.verify_code(CREDID, current_code)
            stop_time = time.time()
            tqdm.write(
                f"Found code {current_code} after {stop_time-start_time} seconds"
            )
            break
        except KeyboardInterrupt:
            break
        except fido2.ctap.CtapError:
            pass
        except Exception:
            break


@pytest.mark.xfail(reason="Not implemented in the firmware. Expected to fail.")
def test_revhotp_delay_on_failure(otpApp):
    """
    Check if the right delay is set, when the invalid code is given for the reverse HOTP operation.
    On failure the response time should take at least 1 second to prevent easy brute force.
    """
    start_time = time.time()
    otpApp.reset()
    otpApp.register(
        CREDID, SECRET, digits=6, kind=Kind.HotpReverse, algo=Algorithm.Sha1
    )
    current_code = 123123
    otpApp.verify_code(CREDID, current_code)
    stop_time = time.time()

    assert (
        stop_time - start_time
    ) > 1, "Replies' delay after the failed execution takes less than 1 second"
