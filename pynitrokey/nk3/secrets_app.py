"""
Oath Authenticator client

Used through CTAPHID transport, via the custom vendor command.
Can be used directly over CCID as well.
"""
import dataclasses
import hmac
import logging
import typing
from enum import Enum
from hashlib import pbkdf2_hmac
from secrets import token_bytes
from struct import pack
from typing import List, Optional

import tlv8

from pynitrokey.nk3 import Nitrokey3Device
from pynitrokey.start.gnuk_token import iso7816_compose


@dataclasses.dataclass
class RawBytes:
    data: List


@dataclasses.dataclass
class SelectResponse:
    # Application version
    version: Optional[bytes]
    # PIN attempt counter
    pin_attempt_counter: Optional[int]
    # Salt, challenge-response auth only, tag Name
    salt: Optional[bytes]
    # Challenge field, challenge-response auth only
    challenge: Optional[bytes]
    # Selected algorithm, challenge-response auth only
    algorithm: Optional[bytes]

    def version_str(self) -> str:
        if self.version:
            return f"{self.version[0]}.{self.version[1]}.{self.version[2]}"
        else:
            return "unknown"

    def __str__(self) -> str:
        return (
            "Nitrokey Secrets\n"
            f"\tVersion: {self.version_str()}\n"
            f"\tPIN attempt counter: {self.pin_attempt_counter}"
        )


@dataclasses.dataclass
class SecretsAppException(Exception):
    code: str
    context: str

    def to_string(self) -> str:
        d = {
            "61FF": "MoreDataAvailable",
            "6300": "VerificationFailed",
            "6400": "UnspecifiedNonpersistentExecutionError",
            "6500": "UnspecifiedPersistentExecutionError",
            "6700": "WrongLength",
            "6881": "LogicalChannelNotSupported",
            "6882": "SecureMessagingNotSupported",
            "6884": "CommandChainingNotSupported",
            "6982": "SecurityStatusNotSatisfied",
            "6985": "ConditionsOfUseNotSatisfied",
            "6983": "OperationBlocked",
            "6a80": "IncorrectDataParameter",
            "6a81": "FunctionNotSupported",
            "6a82": "NotFound",
            "6a84": "NotEnoughMemory",
            "6a86": "IncorrectP1OrP2Parameter",
            "6a88": "KeyReferenceNotFound",
            "6d00": "InstructionNotSupportedOrInvalid",
            "6e00": "ClassNotSupported",
            "6f00": "UnspecifiedCheckingError",
            "9000": "Success",
        }
        return d.get(self.code, "Unknown SW code")

    def __repr__(self) -> str:
        return f"OTPAppException(code={self.code}/{self.to_string()})"

    def __str__(self) -> str:
        return self.__repr__()


class Instruction(Enum):
    Put = 0x1
    Delete = 0x2
    SetCode = 0x3
    Reset = 0x4
    List = 0xA1
    Calculate = 0xA2
    Validate = 0xA3
    CalculateAll = 0xA4
    SendRemaining = 0xA5
    VerifyCode = 0xB1
    Select = 0xA4
    # Place extending commands in 0xBx space
    VerifyPIN = 0xB2
    ChangePIN = 0xB3
    SetPIN = 0xB4


class Tag(Enum):
    CredentialId = 0x71  # also known as Name
    NameList = 0x72
    Key = 0x73
    Challenge = 0x74
    Response = 0x75
    Properties = 0x78
    InitialCounter = 0x7A
    Version = 0x79
    Algorithm = 0x7B
    # Touch = 0x7c,
    # Extension starting from 0x80
    Password = 0x80
    NewPassword = 0x81
    PINCounter = 0x82


class Kind(Enum):
    Hotp = 0x10
    Totp = 0x20
    HotpReverse = 0x30


STRING_TO_KIND = {
    "HOTP": Kind.Hotp,
    "TOTP": Kind.Totp,
    "HOTP_REVERSE": Kind.HotpReverse,
}


class Algorithm(Enum):
    Sha1 = 0x01
    Sha256 = 0x02
    Sha512 = 0x03


class SecretsApp:
    """
    This is a Secrets App client
    https://github.com/Nitrokey/trussed-secrets-app
    """

    log: logging.Logger
    logfn: typing.Callable
    dev: Nitrokey3Device
    write_corpus_fn: Optional[typing.Callable]
    _cache_status: Optional[SelectResponse]

    def __init__(self, dev: Nitrokey3Device, logfn: Optional[typing.Callable] = None):
        self._cache_status = None
        self.write_corpus_fn = None
        self.log = logging.getLogger("otpapp")
        if logfn is not None:
            self.logfn = logfn  # type: ignore [assignment]
        else:
            self.logfn = self.log.info  # type: ignore [assignment]
        self.dev = dev

    def _custom_encode(self, structure: Optional[List] = None) -> bytes:
        if not structure:
            return b""

        def transform(d: typing.Union[tlv8.Entry, RawBytes, None]) -> bytes:
            if not d:
                return b""
            if isinstance(d, RawBytes):
                # return b"".join(d.data)
                return bytes(d.data)
            if isinstance(d, tlv8.Entry):
                return tlv8.encode([d])
            return b""

        encoded_structure = b"".join(map(transform, structure))
        return encoded_structure

    def _send_receive(
        self, ins: Instruction, structure: Optional[List] = None
    ) -> bytes:
        encoded_structure = self._custom_encode(structure)
        ins_b, p1, p2 = self._encode_command(ins)
        bytes_data = iso7816_compose(ins_b, p1, p2, data=encoded_structure)
        if self.write_corpus_fn:
            self.write_corpus_fn(ins, bytes_data)
        return self._send_receive_inner(bytes_data, log_info=f"{ins}")

    def _send_receive_inner(self, data: bytes, log_info: str = "") -> bytes:
        self.logfn(
            f"Sending {log_info if log_info else ''} {data.hex() if data else data!r}"
        )

        try:
            result = self.dev.otp(data=data)
        except Exception as e:
            self.logfn(f"Got exception: {e}")
            raise

        status_bytes, result = result[:2], result[2:]
        self.logfn(
            f"Received [{status_bytes.hex()}] {result.hex() if result else result!r}"
        )

        log_multipacket = False
        data_final = result
        MORE_DATA_STATUS_BYTE = 0x61
        while status_bytes[0] == MORE_DATA_STATUS_BYTE:
            if log_multipacket:
                self.logfn(
                    f"Got RemainingData status: [{status_bytes.hex()}] {result.hex() if result else result!r}"
                )
            log_multipacket = True
            ins_b, p1, p2 = self._encode_command(Instruction.SendRemaining)
            bytes_data = iso7816_compose(ins_b, p1, p2, data=[])
            try:
                result = self.dev.otp(data=bytes_data)
            except Exception as e:
                self.logfn(f"Got exception: {e}")
                raise
            status_bytes, result = result[:2], result[2:]
            self.logfn(
                f"Received [{status_bytes.hex()}] {result.hex() if result else result!r}"
            )
            if status_bytes[0] in [0x90, MORE_DATA_STATUS_BYTE]:
                data_final += result

        if status_bytes != b"\x90\x00" and status_bytes[0] != MORE_DATA_STATUS_BYTE:
            raise SecretsAppException(status_bytes.hex(), "Received error")

        if log_multipacket:
            self.logfn(
                f"Received final data: [{status_bytes.hex()}] {data_final.hex() if data_final else data_final!r}"
            )

        return data_final

    @classmethod
    def _encode_command(cls, command: Instruction) -> bytes:
        p1 = 0
        p2 = 0
        if command == Instruction.Reset:
            p1 = 0xDE
            p2 = 0xAD
        elif command == Instruction.Select:
            p1 = 0x04
            p2 = 0x00
        elif command == Instruction.Calculate or command == Instruction.CalculateAll:
            p1 = 0x00
            p2 = 0x01
        return bytes([command.value, p1, p2])

    def reset(self) -> None:
        """
        Remove all credentials from the database
        """
        self.logfn("Executing reset")
        self._send_receive(Instruction.Reset)

    def list(self) -> List[bytes]:
        """
        Return a list of the registered credentials
        :return: List of bytestrings
        """
        raw_res = self._send_receive(Instruction.List)
        resd: tlv8.EntryList = tlv8.decode(raw_res)
        res = []
        for e in resd:
            # e: tlv8.Entry
            res.append(e.data[1:])
        return res

    def delete(self, cred_id: bytes) -> None:
        """
        Delete credential with the given id. Does not fail, if the given credential does not exist.
        :param credid: Credential ID
        """
        self.logfn(f"Sending delete request for {cred_id!r}")
        structure = [
            tlv8.Entry(Tag.CredentialId.value, cred_id),
        ]
        self._send_receive(Instruction.Delete, structure)

    def register(
        self,
        credid: bytes,
        secret: bytes,
        digits: int,
        kind: Kind = Kind.Hotp,
        algo: Algorithm = Algorithm.Sha1,
        initial_counter_value: int = 0,
        touch_button_required: bool = False,
    ) -> None:
        """
        Register new OTP credential
        :param credid: Credential ID
        :param secret: The shared key
        :param digits: Digits of the produced code
        :param kind: OTP variant - HOTP or TOTP
        :param algo: The hash algorithm to use - SHA1, SHA256 or SHA512
        :param initial_counter_value: The counter's initial value for the HOTP credential (HOTP only)
        :param touch_button_required: User Presence confirmation is required to use this Credential
        :return: None
        """
        if initial_counter_value > 0xFFFFFFFF:
            raise Exception("Initial counter value must be smaller than 4 bytes")
        if algo == Algorithm.Sha512:
            raise NotImplementedError(
                "This hash algorithm is not supported by the firmware"
            )

        self.logfn(
            f"Setting new credential: {credid!r}, {secret.hex()}, {kind}, {algo}, counter: {initial_counter_value}"
        )

        structure = [
            tlv8.Entry(Tag.CredentialId.value, credid),
            # header (2) + secret (N)
            tlv8.Entry(
                Tag.Key.value, bytes([kind.value | algo.value, digits]) + secret
            ),
            RawBytes([Tag.Properties.value, 0x02 if touch_button_required else 0x00]),
            tlv8.Entry(
                Tag.InitialCounter.value, initial_counter_value.to_bytes(4, "big")
            ),
        ]
        self._send_receive(Instruction.Put, structure)

    def calculate(self, cred_id: bytes, challenge: int) -> bytes:
        """
        Calculate the OTP code for the credential named `cred_id`, and with challenge `challenge`.
        :param cred_id: The name of the credential
        :param challenge: Challenge for the calculations (TOTP only).
            Should be equal to: timestamp/period. The commonly used period value is 30.
        :return: OTP code as a byte string
        """
        self.logfn(
            f"Sending calculate request for {cred_id!r} and challenge {challenge!r}"
        )
        structure = [
            tlv8.Entry(Tag.CredentialId.value, cred_id),
            tlv8.Entry(Tag.Challenge.value, pack(">Q", challenge)),
        ]
        res = self._send_receive(Instruction.Calculate, structure=structure)
        header = res[:2]
        assert header.hex() in ["7605", "7700"]
        digits = res[2]
        digest = res[3:]
        truncated_code = int.from_bytes(digest, byteorder="big", signed=False)
        code = (truncated_code & 0x7FFFFFFF) % pow(10, digits)
        codes: bytes = str(code).zfill(digits).encode()
        self.logfn(
            f"Received digest: {digest.hex()}, for challenge {challenge}, digits: {digits}, truncated code: {truncated_code!r}, pre-code: {code!r},"
            f" final code: {codes!r}"
        )
        return codes

    def verify_code(self, cred_id: bytes, code: int) -> bool:
        """
        Proceed with the incoming OTP code verification (aka reverse HOTP).
        :param cred_id: The name of the credential
        :param code: The HOTP code to verify. u32 representation.
        :return: fails with OTPAppException error; returns True if code matches the value calculated internally.
        """
        structure = [
            tlv8.Entry(Tag.CredentialId.value, cred_id),
            tlv8.Entry(Tag.Response.value, pack(">L", code)),
        ]
        self._send_receive(Instruction.VerifyCode, structure=structure)
        return True

    def set_code(self, passphrase: str) -> None:
        """
        Set the code with the defaults as suggested in the protocol specification:
        - https://developers.yubico.com/OATH/YKOATH_Protocol.html
        """
        secret = self.get_secret_for_passphrase(passphrase)
        challenge = token_bytes(8)
        response = self.get_response_for_secret(challenge, secret)
        self.set_code_raw(secret, challenge, response)

    def get_secret_for_passphrase(self, passphrase: str) -> bytes:
        #   secret = PBKDF2(USER_PASSPHRASE, DEVICEID, 1000)[:16]
        # salt = self.select().name
        # FIXME use the proper SALT
        # FIXME USB/IP Sim changes its ID after each reset and after setting the code (??)
        salt = b"a" * 8
        secret = pbkdf2_hmac("sha256", passphrase.encode(), salt, 1000)
        return secret[:16]

    def get_response_for_secret(self, challenge: bytes, secret: bytes) -> bytes:
        response = hmac.HMAC(key=secret, msg=challenge, digestmod="sha1").digest()
        return response

    def set_code_raw(self, key: bytes, challenge: bytes, response: bytes) -> None:
        """
        Set or clear the passphrase used to authenticate to other commands. Raw interface.
        :param key: User passphrase processed through PBKDF2(ID,1000), and limited to the first 16 bytes.
        :param challenge: The current challenge taken from the SELECT command.
        :param response: The data calculated on the client, as a proof of a correct setup.
        """
        algo = Algorithm.Sha1.value
        kind = Kind.Totp.value
        structure = [
            tlv8.Entry(Tag.Key.value, bytes([kind | algo]) + key),
            tlv8.Entry(Tag.Challenge.value, challenge),
            tlv8.Entry(Tag.Response.value, response),
        ]
        self._send_receive(Instruction.SetCode, structure=structure)

    def clear_code(self) -> None:
        """
        Clear the passphrase used to authenticate to other commands.
        """
        structure = [
            tlv8.Entry(Tag.Key.value, bytes()),
        ]
        self._send_receive(Instruction.SetCode, structure=structure)

    def authentication_required(self, stat: Optional[SelectResponse] = None) -> bool:
        return True

    def validate(self, passphrase: str) -> None:
        """
        Authenticate using a passphrase
        """
        stat = self.select()
        if not self.authentication_required(stat):
            # Assuming this should have been checked before calling validate()
            raise RuntimeWarning(
                "No passphrase is set. Authentication is not required."
            )
        if stat.algorithm != bytes([Algorithm.Sha1.value]):
            raise RuntimeError("For the authentication only SHA1 is supported")
        challenge = stat.challenge
        if challenge is None:
            # This should never happen
            raise RuntimeError(
                "There is some problem with the device's state. Challenge is not available."
            )
        secret = self.get_secret_for_passphrase(passphrase)
        response = self.get_response_for_secret(challenge, secret)
        self.validate_raw(challenge, response)

    def validate_raw(self, challenge: bytes, response: bytes) -> bytes:
        """
        Authenticate using a passphrase. Raw interface.
        :param challenge: The current challenge taken from the SELECT command.
        :param response: The response calculated against the challenge and the secret
        """
        structure = [
            tlv8.Entry(Tag.Response.value, response),
            tlv8.Entry(Tag.Challenge.value, challenge),
        ]
        raw_res = self._send_receive(Instruction.Validate, structure=structure)
        resd: tlv8.EntryList = tlv8.decode(raw_res)
        return resd.data

    def select(self) -> SelectResponse:
        """
        Execute SELECT command, which returns details about the device,
        including the challenge needed for the authentication.
        :return SelectResponse Status structure. Challenge and Algorithm fields are None, if the passphrase is not set.
        """
        AID = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
        structure = [RawBytes(AID)]
        raw_res = self._send_receive(Instruction.Select, structure=structure)
        resd: tlv8.EntryList = tlv8.decode(raw_res)
        rd = {}
        for e in resd:
            # e: tlv8.Entry
            rd[e.type_id] = e.data

        counter = rd.get(Tag.PINCounter.value)
        if counter is not None:
            # counter is passed as 1B array - convert it to int
            counter = int.from_bytes(counter, byteorder="big")

        r = SelectResponse(
            version=rd.get(Tag.Version.value),
            pin_attempt_counter=counter,
            salt=rd.get(Tag.CredentialId.value),
            challenge=rd.get(Tag.Challenge.value),
            algorithm=rd.get(Tag.Algorithm.value),
        )
        return r

    def set_pin_raw(self, password: str) -> None:
        structure = [
            tlv8.Entry(Tag.Password.value, password),
        ]
        self._send_receive(Instruction.SetPIN, structure=structure)

    def change_pin_raw(self, password: str, new_password: str) -> None:
        structure = [
            tlv8.Entry(Tag.Password.value, password),
            tlv8.Entry(Tag.NewPassword.value, new_password),
        ]
        self._send_receive(Instruction.ChangePIN, structure=structure)

    def verify_pin_raw(self, password: str) -> None:
        structure = [
            tlv8.Entry(Tag.Password.value, password),
        ]
        self._send_receive(Instruction.VerifyPIN, structure=structure)

    def get_feature_status_cached(self) -> SelectResponse:
        self._cache_status = (
            self.select() if self._cache_status is None else self._cache_status
        )
        return self._cache_status

    def feature_active_PIN_authentication(self) -> bool:
        return self.get_feature_status_cached().challenge is None

    def feature_old_application_version(self) -> bool:
        v = self.get_feature_status_cached().version
        return b"444" == v

    def feature_challenge_response_support(self) -> bool:
        if self.get_feature_status_cached().challenge is not None:
            return True
        return False
