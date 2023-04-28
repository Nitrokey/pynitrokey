"""
Tests for the Secrets application interface placed in secrets_app.py.
Requires a live device, or an USB-IP simulation.
"""

import binascii
import datetime
import hashlib
import hmac
import logging
import time
from datetime import timedelta
from os import wait
from sys import stderr
from typing import Any, Callable, List

import fido2
import pytest
import tlv8

from pynitrokey.conftest import (
    CALCULATE_ALL_COMMANDS,
    CHALLENGE,
    CHALLENGE_RESPONSE_COMMANDS,
    CREDID,
    DELAY_AFTER_FAILED_REQUEST_SECONDS,
    DIGITS,
    FEATURE_BRUTEFORCE_PROTECTION_ENABLED,
    FEATURE_CHALLENGE_RESPONSE_ENABLED,
    HOTP_WINDOW_SIZE,
    PIN,
    PIN2,
    PIN_ATTEMPT_COUNTER_DEFAULT,
    SECRET,
    CredEncryptionType,
)
from pynitrokey.nk3.secrets_app import (
    Algorithm,
    CCIDInstruction,
    Instruction,
    Kind,
    PasswordSafeEntry,
    RawBytes,
    SecretsApp,
    SecretsAppException,
    Tag,
)

CREDENTIAL_LABEL_MAX_SIZE = 127


def test_reset(secretsAppResetLogin):
    """
    Clear credentials' storage. Simple test.
    """
    secretsAppResetLogin.reset()


def test_list(secretsAppResetLogin):
    """
    List saved credentials. Simple test.
    """
    secretsAppResetLogin.list()


def test_register(secretsAppResetLogin):
    """
    Register credential with the given id and properties. Simple test.
    """
    secretsAppResetLogin.register(CREDID, SECRET, DIGITS)


def test_calculate(secretsAppResetLogin):
    """
    Run calculation on the default credential id. Simple test.
    """
    secretsAppResetLogin.register(CREDID, SECRET, DIGITS, kind=Kind.Hotp)
    secretsAppResetLogin.verify_pin_raw(PIN)
    code = secretsAppResetLogin.calculate(CREDID, CHALLENGE)
    print(code)


def test_delete(secretsAppResetLogin):
    """
    Remove credential with the given id. Simple test.
    """
    secretsAppResetLogin.register(CREDID, SECRET, DIGITS)
    secretsAppResetLogin.verify_pin_raw(PIN)
    secretsAppResetLogin.delete(CREDID)


def test_delete_nonexisting(secretsAppResetLogin):
    """
    Should fail when trying to remove non-existing credential id.
    """
    with pytest.raises(SecretsAppException, match="NotFound"):
        secretsAppResetLogin.delete(CREDID)


def test_list_changes(secretsAppResetLogin):
    """
    Test how the list of credential changes, when one is added or removed, and after a reset.
    """
    cred1 = b"TESTCRED"
    cred2 = b"ANOTHERCRED"

    secretsApp = secretsAppResetLogin

    assert not secretsApp.list()

    secretsApp.verify_pin_raw(PIN)
    secretsApp.register(cred1, SECRET, DIGITS)
    secretsApp.verify_pin_raw(PIN)
    assert cred1 in secretsApp.list()
    secretsApp.verify_pin_raw(PIN)
    secretsApp.register(cred2, SECRET, DIGITS)
    secretsApp.verify_pin_raw(PIN)
    assert cred2 in secretsApp.list()

    secretsApp.verify_pin_raw(PIN)
    secretsApp.delete(cred2)
    secretsApp.verify_pin_raw(PIN)
    assert cred2 not in secretsApp.list()
    secretsApp.verify_pin_raw(PIN)
    assert cred1 in secretsApp.list()

    secretsApp.reset()
    secretsApp.set_pin_raw(PIN)
    secretsApp.verify_pin_raw(PIN)
    assert not secretsApp.list()


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
def test_calculated_codes_hotp(secretsAppResetLogin, secret, start_counter):
    """
    Test HOTP codes against another OTP library.
    Use different secret and start counter values.
    """
    oath = pytest.importorskip("oath")
    secretb = binascii.a2b_hex(secret)
    secretsApp = secretsAppResetLogin
    secretsApp.register(
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
        secretsApp.verify_pin_raw(PIN)
        assert secretsApp.calculate(CREDID, i) == lib_at(i)


@pytest.mark.parametrize(
    "secret",
    [
        "3132333435363738393031323334353637383930",
        "00" * 19 + "ff",
        "002EF43F51AFA97BA2B46418768123C9E1809A5B",
        "002EF43F51AFA97BA2B46418768123C9E1809A5B" * 2,
    ],
)
def test_calculated_codes_totp(secretsAppResetLogin, secret):
    """
    Test TOTP codes against another OTP library.
    """
    oath = pytest.importorskip("oath")
    secretb = binascii.a2b_hex(secret)
    secretsApp = secretsAppResetLogin
    secretsApp.register(CREDID, secretb, digits=6, kind=Kind.Totp, algo=Algorithm.Sha1)
    lib_at = lambda t: oath.totp(secret, format="dec6", period=30, t=t * 30).encode()
    for i in range(10):
        secretsApp.verify_pin_raw(PIN)
        assert secretsApp.calculate(CREDID, i) == lib_at(i)


def test_calculated_codes_test_vector(secretsAppResetLogin):
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
    secretsApp = secretsAppResetLogin

    secretsApp.register(CREDID, secretb, digits=6, kind=Kind.Hotp, algo=Algorithm.Sha1)
    for i in range(10):
        secretsApp.verify_pin_raw(PIN)
        assert secretsApp.calculate(CREDID, i) == codes[i]


def test_reverse_hotp_vectors(secretsAppResetLogin):
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

    secretsApp = secretsAppResetLogin
    secretsApp.register(
        CREDID, secretb, digits=6, kind=Kind.HotpReverse, algo=Algorithm.Sha1
    )
    for i in range(10):
        c = int(codes[i])
        secretsApp.verify_pin_raw(PIN)
        assert secretsApp.verify_code(CREDID, c)


def test_reverse_hotp_failure(secretsAppRaw):
    """
    Test failing conditions for the HOTP reverse check
    """
    secret = "3132333435363738393031323334353637383930"
    secretb = binascii.a2b_hex(secret)

    codes = [x for x in range(10)]

    secretsApp = secretsAppRaw
    secretsApp.reset()
    secretsApp.register(
        CREDID, secretb, digits=6, kind=Kind.HotpReverse, algo=Algorithm.Sha1
    )
    # Make sure the obligatory delay has passed in case the previous test has triggered it
    helper_wait_after_failed_hotp_verification_request()
    for i in range(3):
        c = codes[i]
        with pytest.raises(SecretsAppException, match="VerificationFailed"):
            assert not secretsApp.verify_code(CREDID, c)
        helper_wait_after_failed_hotp_verification_request()

    # Test parsing too long code
    with pytest.raises(SecretsAppException, match="VerificationFailed"):
        assert not secretsApp.verify_code(CREDID, 10**5)
    helper_wait_after_failed_hotp_verification_request()

    secretsApp.register(CREDID, secretb, digits=7, kind=Kind.Hotp, algo=Algorithm.Sha1)
    with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
        assert not secretsApp.verify_code(CREDID, 10**6)
    helper_wait_after_failed_hotp_verification_request()

    secretsApp.register(CREDID, secretb, digits=8, kind=Kind.Hotp, algo=Algorithm.Sha1)
    with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
        assert not secretsApp.verify_code(CREDID, 10**7)
    helper_wait_after_failed_hotp_verification_request()


def helper_wait(seconds: int) -> None:
    l = logging.getLogger()
    l.debug(f"Waiting {seconds} seconds before continuing")
    time.sleep(seconds)


def helper_wait_after_failed_hotp_verification_request():
    if FEATURE_BRUTEFORCE_PROTECTION_ENABLED:
        helper_wait(DELAY_AFTER_FAILED_REQUEST_SECONDS)


@pytest.mark.parametrize(
    "start_value",
    [0, 0xFFFF, 0xFFFFFFFF - HOTP_WINDOW_SIZE - 2],
)
@pytest.mark.parametrize(
    "offset",
    [0, 1, HOTP_WINDOW_SIZE - 1, HOTP_WINDOW_SIZE, HOTP_WINDOW_SIZE + 1],
)
def test_reverse_hotp_window(secretsAppResetLogin, offset, start_value):
    """
    Test reverse HOTP code calculation synchronization.
    Solution contains a means to avoid desynchronization between the host's and device's counters. Device calculates
    up to 9 values ahead of its current counter to find the matching code (in total it calculates HOTP code for 10
    subsequent counter positions). In case:

     - no code would match - the on-device counter will not be changed;
     - code would match, but with some counter's offset (up to 9) - the on-device counter will be set to matched code-generated HOTP counter and incremented by 1;
     - code would match, and the code matches counter without offset - the counter will be incremented by 1;
     - counter overflows while calculating the code within the specified window - error is returned, and in that case a new credential with reset counter should be registered

    Device will stop verifying the HOTP codes in case, when the difference between the host and on-device counters
    will be greater or equal to 10.
    See https://github.com/Nitrokey/nitrokey-hotp-verification#verifying-hotp-code for more information.
    """
    oath = pytest.importorskip("oath")
    secret = "3132333435363738393031323334353637383930"
    secretb = binascii.a2b_hex(secret)
    secretsApp = secretsAppResetLogin
    secretsApp.register(
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
        secretsApp.verify_pin_raw(PIN)
        with pytest.raises(SecretsAppException, match="VerificationFailed"):
            secretsApp.verify_code(CREDID, code_to_send)
        helper_wait_after_failed_hotp_verification_request()
    else:
        # check if this code will be accepted on the given offset
        secretsApp.verify_pin_raw(PIN)
        assert secretsApp.verify_code(CREDID, code_to_send)
        # the same code should not be accepted again, unless counted got saturated
        is_counter_saturated = (
            start_value == (0xFFFFFFFF - HOTP_WINDOW_SIZE)
            and offset == HOTP_WINDOW_SIZE
        )
        if not is_counter_saturated:
            with pytest.raises(
                SecretsAppException,
                match="UnspecifiedPersistentExecutionError|VerificationFailed",
            ):
                secretsAppResetLogin.verify_pin_raw(PIN)
                # send the same code once again - should be rejected
                secretsApp.verify_code(CREDID, code_to_send)
            helper_wait_after_failed_hotp_verification_request()
            # test the very next value - should be accepted
            code_to_send = lib_at(start_value + offset + 1)
            code_to_send = int(code_to_send)
            secretsAppResetLogin.verify_pin_raw(PIN)
            assert secretsApp.verify_code(CREDID, code_to_send)
        else:
            # counter got saturated, error code will be returned
            for _ in range(3):
                with pytest.raises(
                    SecretsAppException, match="UnspecifiedPersistentExecutionError"
                ):
                    secretsAppResetLogin.verify_pin_raw(PIN)
                    secretsApp.verify_code(CREDID, code_to_send)
                helper_wait_after_failed_hotp_verification_request()


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
def test_calculated_codes_totp_hash_digits(
    secretsAppResetLogin, secret, algorithm, digits
):
    """
    Test TOTP codes against another OTP library, with different hash algorithms and digits count.
    Test vector secret, and a random 40 bytes value.
    """
    algo_app, algo_oath = algorithm
    oath = pytest.importorskip("oath")
    secretb = binascii.a2b_hex(secret)
    secretsApp = secretsAppResetLogin
    secretsApp.register(CREDID, secretb, digits=digits, kind=Kind.Totp, algo=algo_app)
    lib_at = lambda t: oath.totp(
        secret, format="dec" + str(digits), period=30, t=t * 30, hash=algo_oath
    ).encode()
    for i in range(10):
        secretsApp.verify_pin_raw(PIN)
        assert secretsApp.calculate(CREDID, i) == lib_at(i)


@pytest.mark.slow
@pytest.mark.parametrize(
    "long_labels",
    ["short_labels", "long_labels"],
)
@pytest.mark.parametrize(
    "kind",
    [Kind.Totp, Kind.Hotp],
)
@pytest.mark.parametrize(
    "count",
    [
        30,
        pytest.param(1000, marks=pytest.mark.slow),
    ],
)
def test_load(secretsAppResetLogin, kind: Kind, long_labels: str, count):
    """
    Load tests to see how much OTP credentials we can store,
    and if using of them is not broken with the full FS.
    """
    secret = "3132333435363738393031323334353637383930"
    oath = pytest.importorskip("oath")
    secretb = binascii.a2b_hex(secret)

    secretsApp = secretsAppResetLogin
    credentials_registered: int = 0
    names_registered: List[bytes] = []

    name_gen: Callable[[int], str] = lambda x: f"LOAD{x:02}"
    if long_labels == "long_labels":
        name_gen = lambda x: (f"LOAD{x:02}" * 100)[:CREDENTIAL_LABEL_MAX_SIZE]

    i = 0
    while True:
        name = name_gen(i)
        try:
            secretsApp.verify_pin_raw(PIN)
            secretsApp.register(
                name.encode(), secretb, digits=6, kind=kind, initial_counter_value=i
            )
            names_registered.append(name.encode())
            if i > count:
                i = i + 1
                raise Exception("Reached expected credentials count, finishing early")
        except Exception as e:
            print(f"{e}")
            print(f"Registered {i} credentials")
            size = len(secret) + len(name)
            print(f"Single Credential size: {size} B")
            print(f"Total size: {size*i} B")
            credentials_registered = i
            break
        i += 1

    assert (
        credentials_registered > 30
    ), "Expecting being able to register at least 30 OTP credentials"

    secretsApp.verify_pin_raw(PIN)
    l = secretsApp.list()
    assert sorted(l) == sorted(names_registered)
    assert len(l) == credentials_registered

    # Make some space for the counter updates - delete the last 3 credentials
    CRED_TO_REMOVE = 3
    for name_c in names_registered[-CRED_TO_REMOVE:]:
        secretsApp.verify_pin_raw(PIN)
        secretsApp.delete(name_c)
    credentials_registered -= CRED_TO_REMOVE

    secretsApp.verify_pin_raw(PIN)
    l = secretsApp.list()
    assert len(l) == credentials_registered

    lib_at = lambda t: oath.totp(secret, format="dec6", period=30, t=t * 30).encode()
    if kind == Kind.Hotp:
        lib_at = lambda t: oath.hotp(secret, format="dec6", counter=t).encode()

    for i in range(credentials_registered):
        # At this point device should respond to our calls, despite being full, fail otherwise
        # Iterate over credentials and check code at given challenge
        nameb = name_gen(i).encode()
        secretsApp.verify_pin_raw(PIN)
        assert secretsApp.calculate(nameb, i) == lib_at(i)

    secretsApp.verify_pin_raw(PIN)
    l = secretsApp.list()
    assert len(l) == credentials_registered


def test_remove_all_credentials_by_hand(secretsAppRaw):
    """
    Remove all hold credentials by hand and test for being empty.
    """
    secretsApp = secretsAppRaw
    secretsApp.reset()
    secretsApp.set_pin_raw(PIN)
    cred_no_pbek = [f"CredNoPBEK{i}".encode() for i in range(1, 5)]
    cred_pbek = [f"CredPBEK{i}".encode() for i in range(1, 5)]
    all_registered = sorted([*cred_no_pbek, *cred_pbek])

    for c in cred_no_pbek:
        secretsApp.register(
            c, SECRET, DIGITS, pin_based_encryption=False, kind=Kind.Hotp
        )

    for c in cred_pbek:
        secretsApp.verify_pin_raw(PIN)
        secretsApp.register(c, SECRET, DIGITS, pin_based_encryption=True)

    secretsApp.verify_pin_raw(PIN)
    credential_list = secretsApp.list()
    assert len(credential_list) > 0, "Empty credentials list"
    assert sorted(secretsApp.list()) == cred_no_pbek
    secretsApp.verify_pin_raw(PIN)
    assert sorted(secretsApp.list()) == all_registered

    # Delete all listed credentials by hand
    for credential_name in credential_list:
        try:
            secretsApp.delete(credential_name)
        except SecretsAppException as e:
            if "NotFound" in str(e):
                # Try again with provided PIN
                secretsApp.verify_pin_raw(PIN)
                secretsApp.delete(credential_name)

    secretsApp.verify_pin_raw(PIN)
    credential_list = secretsApp.list()
    assert len(credential_list) == 0


def test_send_rubbish(secretsAppRaw):
    """Check if the application crashes, when sending unexpected data for the given command"""
    secretsApp = secretsAppRaw
    secretsApp.reset()
    secretsApp.register(CREDID, SECRET, DIGITS)

    # Just randomly selected 20 bytes of non-TLV data
    invalid_data = bytes([0x11] * 20)
    for _ in range(3):
        with pytest.raises(fido2.ctap.CtapError):
            secretsApp._send_receive_inner(invalid_data)
    secretsApp.list()

    # Skip some commands from test
    for ins in set(Instruction).difference(
        {
            # These commands do not parse
            Instruction.Reset,
            Instruction.List,
            Instruction.SendRemaining,
            # Following are deactivated
            *CHALLENGE_RESPONSE_COMMANDS,
            *CALCULATE_ALL_COMMANDS,
        }
    ):
        with pytest.raises(Exception, match="CTAP error|IncorrectDataParameter"):
            structure = [
                RawBytes([0x02, 0x02]),
            ]
            secretsApp._send_receive(ins, structure)
    secretsApp.list()


def test_too_long_message(secretsAppResetLogin):
    """
    Check device's response for the too long message
    """
    secretsApp = secretsAppResetLogin
    secretsApp.register(CREDID, SECRET, DIGITS)
    secretsApp.verify_pin_raw(PIN)
    secretsApp.list()

    too_long_name = b"a" * 253
    with pytest.raises(SecretsAppException, match="IncorrectDataParameter"):
        structure = [
            tlv8.Entry(Tag.CredentialId.value, too_long_name),
        ]
        secretsApp._send_receive(Instruction.Put, structure)
    secretsApp.verify_pin_raw(PIN)
    secretsApp.list()


def test_too_long_message2(secretsAppRaw):
    """
    Test how long the secret could be
    """
    secretsApp = secretsAppRaw
    secretsApp.reset()
    secretsApp.register(CREDID, SECRET, DIGITS)
    secretsApp.list()

    # Check maximum label length
    too_long_name = b"a" * 256
    additional_space = 100
    max_label_length = len(SECRET) + additional_space
    secretsApp.register(too_long_name[:-max_label_length], SECRET, DIGITS)

    # Find out experimentally the maximum accepted secret length - 126 bytes
    # Use minimal label length
    codes = []
    i = 0
    for i in range(1, 255, 5):
        secretsApp.logfn(f"Testing secret length {i} bytes")
        try:
            secretsApp.register("C", too_long_name[:i], DIGITS, kind=Kind.Hotp)
            codes.append(secretsApp.calculate("C"))
        except Exception:
            break
    assert i >= 40, "Maximum secret length should be at least 320 bits"
    assert len(list(set(codes))) == len(
        codes
    ), "All returned OTP codes should be unique"


def test_status(secretsApp):
    """
    Simple test for getting device's status
    """
    print(secretsApp.select())


@pytest.mark.skipif(
    not FEATURE_CHALLENGE_RESPONSE_ENABLED,
    reason="Challenge-Response feature should be activated",
)
def test_set_code(secretsApp):
    """
    Simple test for setting the proper code on the device.
    """
    SECRET = b"1" * 20
    CHALLENGE = b"1234"

    secretsApp.reset()
    state = secretsApp.select()
    print(state)
    assert state.algorithm is None
    assert state.challenge is None

    response = hmac.HMAC(key=SECRET, msg=CHALLENGE, digestmod="sha1").digest()
    secretsApp.set_code_raw(SECRET, CHALLENGE, response)

    state = secretsApp.select()
    print(state)
    assert state.challenge is not None
    assert state.algorithm is not None


@pytest.mark.parametrize(
    "remove_password_with",
    [
        Instruction.Reset,
        Instruction.SetCode,
    ],
)
@pytest.mark.skipif(
    not FEATURE_CHALLENGE_RESPONSE_ENABLED,
    reason="Challenge-Response feature should be activated",
)
def test_set_code_and_validate(secretsAppRaw, remove_password_with: Instruction):
    """
    Test device's behavior when the validation code is set.
    Non-authorized calls should be rejected, except for the selected.
    Authorization should be valid only until the next call.

    Authorization is needed for all the listed commands, except for RESET and VALIDATE:
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
    secretsApp = secretsAppRaw
    secretsApp.reset()
    secretsApp.list()

    # Set the code, and require validation before regular calls from now on
    response = hmac.HMAC(key=SECRET, msg=CHALLENGE, digestmod="sha1").digest()
    secretsApp.set_code_raw(SECRET, CHALLENGE, response)

    # Make sure all the expected commands are failing, as in specification
    with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
        secretsApp.list()

    for ins in set(Instruction) - {Instruction.Reset, Instruction.Validate}:
        with pytest.raises(
            SecretsAppException,
            match="IncorrectDataParameter|InstructionNotSupportedOrInvalid|NotFound|ConditionsOfUseNotSatisfied",
        ):
            structure = [RawBytes([0x02] * 10)]
            secretsApp._send_receive(ins, structure)

    # Each guarded command has to prepended by the validation call
    # Run "list" command, with validation first
    state = secretsApp.select()
    response_validate = hmac.HMAC(
        key=SECRET, msg=state.challenge, digestmod="sha1"
    ).digest()
    secretsApp.validate_raw(challenge=state.challenge, response=response_validate)
    secretsApp.list()

    # Make sure another command call is not allowed
    with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
        secretsApp.list()

    # Test running "list" command again
    state = secretsApp.select()
    response_validate = hmac.HMAC(
        key=SECRET, msg=state.challenge, digestmod="sha1"
    ).digest()
    secretsApp.validate_raw(challenge=state.challenge, response=response_validate)
    secretsApp.list()

    if remove_password_with == Instruction.Reset:
        # Reset should be allowed
        secretsApp.reset()
    elif remove_password_with == Instruction.SetCode:
        # Clearing passphrase should be allowed after authentication
        with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
            secretsApp.clear_code()

        state = secretsApp.select()
        response_validate = hmac.HMAC(
            key=SECRET, msg=state.challenge, digestmod="sha1"
        ).digest()
        secretsApp.validate_raw(challenge=state.challenge, response=response_validate)
        secretsApp.clear_code()
    else:
        raise ValueError()

    state = secretsApp.select()
    assert state.challenge is None


@pytest.mark.skip(reason="This test takes long time")
def test_revhotp_bruteforce(secretsAppNoLog):
    """
    This test implements practical brute-forcing of the codes values.
    In case multiple devices use the same secret, stealing and brute-forcing answers on one
    could help with the other.
    """
    secretsApp = secretsAppNoLog
    secretsApp.reset()
    secretsApp.register(
        CREDID, SECRET, digits=6, kind=Kind.HotpReverse, algo=Algorithm.Sha1
    )
    start_time = time.time()
    code_start = 1_000_000

    from tqdm import tqdm, trange

    for current_code in trange(code_start, 0, -1):
        tqdm.write(f"Trying code {current_code}")
        try:
            secretsApp.verify_code(CREDID, current_code)
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


@pytest.mark.skipif(
    FEATURE_BRUTEFORCE_PROTECTION_ENABLED == False,
    reason="Brute-force protection feature should be activated",
)
def test_revhotp_delay_on_failure(secretsAppRaw):
    """
    Check if the right delay is set, when the invalid code is given for the reverse HOTP operation.
    On failure the response time should take at least 1 second to prevent easy brute force.
    """

    secretsApp = secretsAppRaw
    intentionally_wrong_code = 123123

    secretsApp.reset()
    secretsApp.register(
        CREDID, SECRET, digits=6, kind=Kind.HotpReverse, algo=Algorithm.Sha1
    )
    start_time = time.time()
    stop_time = start_time + DELAY_AFTER_FAILED_REQUEST_SECONDS
    with pytest.raises(SecretsAppException, match="VerificationFailed"):
        secretsApp.verify_code(CREDID, intentionally_wrong_code)
    while time.time() < stop_time:
        with pytest.raises(SecretsAppException, match="SecurityStatusNotSatisfied"):
            secretsApp.verify_code(CREDID, intentionally_wrong_code)
        helper_wait(DELAY_AFTER_FAILED_REQUEST_SECONDS / 10)
    with pytest.raises(SecretsAppException, match="VerificationFailed"):
        helper_wait(DELAY_AFTER_FAILED_REQUEST_SECONDS / 10)
        secretsApp.verify_code(CREDID, intentionally_wrong_code)


def test_set_pin(secretsApp):
    """
    Simple test for setting the PIN on the device.
    """
    secretsApp.reset()
    state = secretsApp.select()
    print(state)
    assert state.algorithm is None
    assert state.challenge is None
    assert state.pin_attempt_counter is None

    secretsApp.set_pin_raw(PIN)

    state = secretsApp.select()
    print(state)
    assert state.challenge is None
    assert state.algorithm is None
    assert state.pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT

    # Should fail when setting the second time
    with pytest.raises(SecretsAppException, match="SecurityStatusNotSatisfied"):
        secretsApp.set_pin_raw(PIN)


def test_change_pin(secretsApp):
    """
    Simple test for setting the proper code on the device.
    """
    secretsApp.reset()

    state = secretsApp.select()
    assert state.pin_attempt_counter is None

    secretsApp.set_pin_raw(PIN)
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT

    secretsApp.change_pin_raw(PIN, PIN2)
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT

    secretsApp.change_pin_raw(PIN2, PIN)
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT

    # Should fail when setting the second time with the PIN2
    with pytest.raises(SecretsAppException, match="VerificationFailed"):
        secretsApp.change_pin_raw(PIN2, PIN)
    # after providing the wrong PIN, the attempt counter should decrement itself by 1
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT - 1


def test_change_pin_data_dont_change(secretsAppResetLogin):
    """
    Test for changing the proper PIN on the device.
    Check if data remain the same, both PIN and Hardware key encrypted
    """

    def helper_test_calculated_codes_totp(secretsApp, secret: str, PIN: str):
        """Test TOTP codes against another OTP library."""
        oath = pytest.importorskip("oath")
        lib_at = lambda t: oath.totp(
            secret, format="dec6", period=30, t=t * 30
        ).encode()
        for i in range(10):
            # Use non-modified verify_pin_raw_always call to always verify PIN, regardless of the fixture type
            secretsApp.verify_pin_raw_always(PIN)
            assert secretsApp.calculate(CREDID, i) == lib_at(i)

    # Initial setup for the TOTP slot and test
    secret = "00" * 20
    secretsApp = secretsAppResetLogin
    secretb = binascii.a2b_hex(secret)
    secretsApp.register(CREDID, secretb, digits=6, kind=Kind.Totp, algo=Algorithm.Sha1)
    helper_test_calculated_codes_totp(secretsApp, secret, PIN)

    # Change PIN and check whether the data remain the same
    secretsApp.change_pin_raw(PIN, PIN2)
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT
    helper_test_calculated_codes_totp(secretsApp, secret, PIN2)

    # And again
    secretsApp.change_pin_raw(PIN2, PIN)
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT
    helper_test_calculated_codes_totp(secretsApp, secret, PIN)

    # Should fail when setting the second time with the PIN2
    with pytest.raises(SecretsAppException, match="VerificationFailed"):
        secretsApp.change_pin_raw(PIN2, PIN)

    # After providing the wrong PIN, the attempt counter should decrement itself by 1
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT - 1

    # After failed PIN change the data should remain the same
    helper_test_calculated_codes_totp(secretsApp, secret, PIN)

    # After providing the correct PIN, the attempt counter should reset itself
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT


def test_verify_pin(secretsApp):
    """
    Simple test for PIN verification
    """
    secretsApp.reset()
    secretsApp.set_pin_raw(PIN)
    secretsApp.verify_pin_raw(PIN)
    secretsApp.list()
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT

    # Make sure all the expected commands are working, as in specification
    secretsApp.list()

    # With PIN verified this should work as well
    secretsApp.verify_pin_raw(PIN)
    secretsApp.list()


def test_use_up_pin_counter(secretsAppRaw):
    secretsApp = secretsAppRaw
    secretsApp.reset()
    secretsApp.set_pin_raw(PIN)
    assert not secretsApp.list()
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT

    cred_no_pbek = [f"CredNoPBEK{i}".encode() for i in range(1, 5)]
    cred_pbek = [f"CredPBEK{i}".encode() for i in range(1, 5)]

    for i, c in enumerate(cred_no_pbek):
        secretsApp.register(
            c,
            SECRET,
            DIGITS,
            initial_counter_value=i,
            pin_based_encryption=False,
            kind=Kind.Hotp,
        )
    assert sorted(secretsApp.list()) == cred_no_pbek

    for c in cred_pbek:
        secretsApp.verify_pin_raw(PIN)
        secretsApp.register(
            c, SECRET, DIGITS, pin_based_encryption=True, kind=Kind.Totp
        )
    assert sorted(secretsApp.list()) == cred_no_pbek

    # Use all PIN counter attempts
    while secretsApp.select().pin_attempt_counter > 0:
        with pytest.raises(SecretsAppException, match="VerificationFailed"):
            secretsApp.verify_pin_raw(PIN2)

    # With the PIN attempt counter used up, verifying with the correct PIN should not recover the device
    assert secretsApp.select().pin_attempt_counter == 0
    with pytest.raises(SecretsAppException, match="VerificationFailed"):
        secretsApp.verify_pin_raw(PIN)
    assert secretsApp.select().pin_attempt_counter == 0

    # Standard commands should not require authentication
    # Check if non-encrypted are still there and usable
    assert sorted(secretsApp.list()) == cred_no_pbek
    for c in cred_no_pbek:
        secretsApp.calculate(c)

    assert secretsApp.select().pin_attempt_counter == 0
    with pytest.raises(SecretsAppException, match="VerificationFailed"):
        secretsApp.verify_pin_raw(PIN)
    for c in cred_pbek:
        with pytest.raises(SecretsAppException, match="NotFound"):
            secretsApp.calculate(c)

    secretsApp.reset()
    secretsApp.set_pin_raw(PIN)
    assert not secretsApp.list()
    assert secretsApp.select().pin_attempt_counter == PIN_ATTEMPT_COUNTER_DEFAULT


def test_list_pin_no_pin(secretsAppRaw):
    """
    Check list command behavior in the presence of PIN and without it
    1. Credential list should be empty after reset
    2. Credential list should show only non-PIN-encrypted credentials, when unauthorized
    3. Credential list should show both non- and PIN-encrypted credentials, when authorized
    @param secretsAppRaw: Direct access to the Secret App API, without any additional setup
    """
    secretsApp = secretsAppRaw

    secretsApp.reset()
    secretsApp.set_pin_raw(PIN)
    secretsApp.verify_pin_raw(PIN)
    # 1. Credential list should be empty after reset
    assert not secretsApp.list()

    cred_no_pbek = [f"CredNoPBEK{i}".encode() for i in range(1, 5)]
    cred_pbek = [f"CredPBEK{i}".encode() for i in range(1, 5)]

    for c in cred_no_pbek:
        secretsApp.register(
            c, SECRET, DIGITS, pin_based_encryption=False, kind=Kind.Hotp
        )

    assert sorted(secretsApp.list()) == cred_no_pbek

    for c in cred_pbek:
        secretsApp.verify_pin_raw(PIN)
        secretsApp.register(c, SECRET, DIGITS, pin_based_encryption=True)

    # 2. Credential list should show only non-PIN-encrypted credentials, when unauthorized
    assert sorted(secretsApp.list()) == cred_no_pbek

    # 3. Credential list should show both non- and PIN-encrypted credentials, when authorized
    secretsApp.verify_pin_raw(PIN)
    assert sorted(secretsApp.list()) == sorted([*cred_no_pbek, *cred_pbek])

    # 2. Credential list should show only non-PIN-encrypted credentials, when unauthorized
    assert sorted(secretsApp.list()) == cred_no_pbek

    # 1. Credential list should be empty after reset
    secretsApp.reset()
    secretsApp.set_pin_raw(PIN)
    assert not secretsApp.list()
    secretsApp.verify_pin_raw(PIN)
    assert not secretsApp.list()


def test_check_commands_access(secretsAppRaw):
    """
    Access to all commands should be always available. Sending garbage, and expecting parsing error.
    If this was access guarded, the parsing would not happen.
    """

    # Not tested with challenge-response enabled
    assert not FEATURE_CHALLENGE_RESPONSE_ENABLED

    for ins in set(Instruction) - {
        Instruction.CalculateAll,
        *CHALLENGE_RESPONSE_COMMANDS,
    }:
        structure = [RawBytes([0x02] * 10)]
        if ins not in [Instruction.Reset, Instruction.List, Instruction.SendRemaining]:
            # Check if we get parsing error from these
            with pytest.raises(SecretsAppException, match="IncorrectDataParameter"):
                secretsAppRaw._send_receive(ins, structure)
        elif ins == Instruction.SendRemaining:
            # This one should not be allowed without data awaiting
            with pytest.raises(
                SecretsAppException, match="ConditionsOfUseNotSatisfied"
            ):
                secretsAppRaw._send_receive(ins, structure)
        else:
            # These commands do not accept arguments, so there is no parsing error
            secretsAppRaw._send_receive(ins, structure)


def test_register_pin_encrypted_without_auth(secretsAppRaw):
    """
    PIN-encrypted Credential registration should not be possible without previous verification
    """
    secretsAppRaw.reset()
    with pytest.raises(SecretsAppException, match="SecurityStatusNotSatisfied"):
        secretsAppRaw.register(
            CREDID, SECRET, DIGITS, pin_based_encryption=True, kind=Kind.Hotp
        )
    assert not secretsAppRaw.list()

    secretsAppRaw.set_pin_raw(PIN)
    secretsAppRaw.verify_pin_raw(PIN)
    secretsAppRaw.register(
        CREDID, SECRET, DIGITS, pin_based_encryption=True, kind=Kind.Hotp
    )
    secretsAppRaw.verify_pin_raw(PIN)
    assert secretsAppRaw.list()


def test_pin_operations_do_not_authenticate(secretsAppRaw):
    """
    Make sure that PIN operations other than Verify do not authenticate
    """
    secretsAppRaw.reset()
    with pytest.raises(SecretsAppException, match="SecurityStatusNotSatisfied"):
        secretsAppRaw.register(
            CREDID, SECRET, DIGITS, pin_based_encryption=True, kind=Kind.Hotp
        )
    assert not secretsAppRaw.list()

    secretsAppRaw.set_pin_raw(PIN)
    with pytest.raises(SecretsAppException, match="SecurityStatusNotSatisfied"):
        secretsAppRaw.register(
            CREDID, SECRET, DIGITS, pin_based_encryption=True, kind=Kind.Hotp
        )
    assert not secretsAppRaw.list()

    secretsAppRaw.change_pin_raw(PIN, PIN2)
    with pytest.raises(SecretsAppException, match="SecurityStatusNotSatisfied"):
        secretsAppRaw.register(
            CREDID, SECRET, DIGITS, pin_based_encryption=True, kind=Kind.Hotp
        )
    assert not secretsAppRaw.list()
    secretsAppRaw.verify_pin_raw(PIN2)
    assert not secretsAppRaw.list()

    secretsAppRaw.verify_pin_raw(PIN2)
    secretsAppRaw.register(
        CREDID, SECRET, DIGITS, pin_based_encryption=True, kind=Kind.Hotp
    )
    secretsAppRaw.verify_pin_raw(PIN2)
    assert secretsAppRaw.list()


def test_credential_encryption_does_not_change(secretsAppRaw):
    """
    Check if counter-updated HOTP Credential does not change its encryption type after use.
    """

    secretsAppRaw.reset()
    assert not secretsAppRaw.list()
    secretsAppRaw.set_pin_raw(PIN)

    # Register PIN-protected credential
    secretsAppRaw.verify_pin_raw(PIN)
    secretsAppRaw.register(
        CREDID, SECRET, DIGITS, pin_based_encryption=True, kind=Kind.Hotp
    )
    assert not secretsAppRaw.list()
    secretsAppRaw.verify_pin_raw(PIN)
    assert secretsAppRaw.list()

    # Credential should not be available for use without presenting the PIN
    with pytest.raises(SecretsAppException, match="NotFound"):
        secretsAppRaw.calculate(CREDID, CHALLENGE)
    secretsAppRaw.verify_pin_raw(PIN)
    secretsAppRaw.calculate(CREDID, CHALLENGE)

    # After use the HOTP counter was updated, and the Credential saved back. The credential should still be PIN-protected.
    with pytest.raises(SecretsAppException, match="NotFound"):
        secretsAppRaw.calculate(CREDID, CHALLENGE)
    assert not secretsAppRaw.list()


def test_send_remaining(secretsApp):
    secrets_app = secretsApp
    secrets_app.reset()
    secrets_app.set_pin_raw(PIN)

    with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
        secrets_app._send_receive(Instruction.SendRemaining)

    # Call list which will have populated "remaining" buffer
    # Call other command
    # The send_remaining call should be denied
    # We need a lot of data to push here, so the ctaphid buffer will be filled (3kB)
    credential_name_length = 127
    count = 3072 // credential_name_length + 1
    secrets_app.logfn(f"Registering {count} credentials")
    credentials = [
        f"Credential{i}".zfill(credential_name_length).encode() for i in range(1, count)
    ]
    for c in credentials:
        secrets_app.verify_pin_raw(PIN)
        secrets_app.register(c, SECRET, DIGITS, kind=Kind.Hotp)
    secrets_app.verify_pin_raw(PIN)
    assert sorted(secrets_app.list()) == sorted(credentials)

    def _trunc(s: str, l: int = 100) -> str:
        return f"{s[:l]}.." if len(s) > l else s

    def send_receive_ins(app: SecretsApp, ins, structure=None):
        """
        Helper for direct communication with the device
        """
        from pynitrokey.start.gnuk_token import iso7816_compose

        ins_b, p1, p2 = app._encode_command(ins)
        encoded_structure = app._custom_encode(structure)
        data = iso7816_compose(ins_b, p1, p2, encoded_structure)
        app.logfn(f">> {_trunc(data.hex())}")
        res = app.dev.otp(data=data)
        app.logfn(f"<< {_trunc(res.hex())}")
        status_bytes, result = res[:2], res[2:]
        return status_bytes, result

    # Run PIN verification so all Credentials on List command will be visible
    secrets_app.verify_pin_raw(PIN)
    status_bytes, result = send_receive_ins(secrets_app, Instruction.List)
    # Make sure there are remaining data to receive
    MORE_DATA_STATUS_BYTE = 0x61
    assert status_bytes[0] == MORE_DATA_STATUS_BYTE
    # Call a different command now, like Delete, which should not add any new data to the buffer
    status_bytes, result = send_receive_ins(
        secrets_app,
        Instruction.Delete,
        structure=[
            tlv8.Entry(Tag.CredentialId.value, credentials[-1]),
        ],
    )
    assert status_bytes.hex() == "9000"

    # Now that the buffer should be emptied, the SendRemaining call should be rejected
    with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
        secrets_app._send_receive(Instruction.SendRemaining)


@pytest.mark.parametrize(
    "length",
    [
        # Average daily use case
        30,
        # Maximum field length -> 128B
        128 - 1,
    ],
)
def test_password_safe(secretsAppResetLogin: SecretsApp, length: int) -> None:
    """
    Create a full credential, with both OTP and PWS fields populated. Test working both, with and without PIN-based encryption.
    """
    secretsApp = secretsAppResetLogin
    oath = pytest.importorskip("oath")
    login = b"login".center(length, b"=")
    password = b"password".center(length, b"=")
    metadata = b"metadata".center(length, b"=")
    name = CREDID.center(length, "=").encode()
    secretb = binascii.a2b_hex(SECRET)
    secretsApp.register(
        name,
        secretb,
        digits=6,
        kind=Kind.Totp,
        algo=Algorithm.Sha1,
        login=login,
        password=password,
        metadata=metadata,
    )
    lib_at = lambda t: oath.totp(
        SECRET.decode(), format="dec6", period=30, t=t * 30
    ).encode()
    for i in range(10):
        secretsApp.verify_pin_raw(PIN)
        assert secretsApp.calculate(name, i) == lib_at(i)

    secretsApp.verify_pin_raw(PIN)
    p: PasswordSafeEntry = secretsApp.get_credential(name)
    assert p.name == name
    assert p.login == login
    assert p.password == password
    assert p.metadata == metadata


def test_password_safe_empty_credential(secretsAppResetLogin):
    """
    It should be possible to create an empty credential, with just the name presented
    """
    secretsAppResetLogin.verify_pin_raw(PIN)
    secretsAppResetLogin.register(CREDID)

    with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
        secretsAppResetLogin.verify_pin_raw(PIN)
        secretsAppResetLogin.calculate(CREDID, 0)

    secretsAppResetLogin.verify_pin_raw(PIN)
    p = secretsAppResetLogin.get_credential(CREDID)
    assert p.name == CREDID.encode()
    assert p.login is None
    assert p.password is None
    assert p.metadata is None

    secretsAppResetLogin.verify_pin_raw(PIN)
    assert CREDID.encode() in secretsAppResetLogin.list()


def test_password_safe_just_pws_entry(secretsAppResetLogin):
    """
    It should be possible to create a PWS-only credential
    """
    length = 20
    login = b"login".center(length, b"=")
    password = b"password".center(length, b"=")
    metadata = b"metadata".center(length, b"=")

    secretsAppResetLogin.verify_pin_raw(PIN)
    secretsAppResetLogin.register(
        CREDID, login=login, password=password, metadata=metadata
    )

    # Since OTP details were not specified, calling Calculate on it should fail
    secretsAppResetLogin.verify_pin_raw(PIN)
    with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
        secretsAppResetLogin.calculate(CREDID, 0)

    # Reverse HOTP is rejecting that too
    secretsAppResetLogin.verify_pin_raw(PIN)
    with pytest.raises(SecretsAppException, match="ConditionsOfUseNotSatisfied"):
        secretsAppResetLogin.verify_code(CREDID, 0)

    # Let's check what is the content of the credential
    secretsAppResetLogin.verify_pin_raw(PIN)
    p = secretsAppResetLogin.get_credential(CREDID)
    assert p.name == CREDID.encode()
    assert p.login == login
    assert p.password == password
    assert p.metadata == metadata

    secretsAppResetLogin.verify_pin_raw(PIN)
    assert CREDID.encode() in secretsAppResetLogin.list()
