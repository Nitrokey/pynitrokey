# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

import logging
import os
from typing import Any, Callable, Optional, Sequence, Union

import smartcard
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import NoCardException

from pynitrokey.helpers import local_critical
from pynitrokey.start.gnuk_token import iso7816_compose
from pynitrokey.tlv import Tlv

LogFn = Callable[[str], Any]


def find_by_id(tag: int, data: Sequence[tuple[int, bytes]]) -> Optional[bytes]:
    for t, b in data:
        if t == tag:
            return b
    return None


# size is in bytes
def prepare_for_pkcs1v15_sign_2048(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hashed = digest.finalize()

    prefix = bytearray.fromhex("3031300d060960864801650304020105000420")
    padding_len = 256 - 32 - 19 - 3
    padding = b"\x00\x01" + (b"\xff" * padding_len) + b"\x00"
    total = padding + prefix + hashed
    assert len(total) == 256
    return total


class StatusError(Exception):
    def __init__(self, value: int):
        self.value = value

    def __str__(self) -> str:
        return f"{hex(self.value)}"


class PivApp:
    log: logging.Logger
    logfn: LogFn
    connection: CardConnection

    def __init__(self, logfn: Optional[LogFn] = None):
        self.log = logging.getLogger("pivapp")
        readers = smartcard.System.readers()
        chosen_connection: Optional[CardConnection] = None
        for r in readers:
            connection = r.createConnection()
            try:
                connection.connect()
            except NoCardException:
                continue

            expected_atr = list(bytes.fromhex("3b8f01805d4e6974726f6b657900000000006a"))
            if not expected_atr == connection.getATR():
                continue
            print(r)

            select = [
                0x00,
                0xA4,
                0x04,
                0x00,
                0x0C,
                0xA0,
                0x00,
                0x00,
                0x03,
                0x08,
                0x00,
                0x00,
                0x10,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
            ]
            data, sw1, sw2 = connection.transmit(select)
            if sw1 != 0x90 or sw2 != 0x00:
                continue
            chosen_connection = connection

        if not chosen_connection:
            raise NoCardException("No PIV card found", -1)

        self.connection = chosen_connection

        if logfn is not None:
            self.logfn = logfn
        else:
            self.logfn = self.log.info

    def send_receive(
        self,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b"",
    ) -> bytes:
        bytes_data = iso7816_compose(ins, p1, p2, data)
        return self._send_receive_inner(bytes_data, log_info=f"{ins}")

    def _send_receive_inner(self, data: bytes, log_info: str = "") -> bytes:
        self.logfn(
            f"Sending {log_info if log_info else ''} {data.hex() if data else data!r}"
        )

        try:
            result_list, sw1, sw2 = self.connection.transmit(list(data))
        except Exception as e:
            self.logfn(f"Got exception: {e}")
            raise

        result = bytes(result_list)
        status_bytes = bytes([sw1, sw2])
        self.logfn(f"Received [{status_bytes.hex()}] {result.hex()}")

        log_multipacket = False
        data_final = bytes(result)
        MORE_DATA_STATUS_BYTE = 0x61
        while status_bytes[0] == MORE_DATA_STATUS_BYTE:
            if log_multipacket:
                self.logfn(
                    f"Got RemainingData status: [{status_bytes.hex()}] {result.hex() if result else result!r}"
                )
            log_multipacket = True
            ins = 0xC0
            p1 = 0
            p2 = 0
            le = sw2 if sw2 != 0 else 0xFF
            bytes_data = iso7816_compose(ins, p1, p2, le=le)
            try:
                result_list, sw1, sw2 = self.connection.transmit(list(bytes_data))
            except Exception as e:
                self.logfn(f"Got exception: {e}")
                raise
            # Data order is different here than in APDU - SW is first, then the data if any
            result = bytes(result_list)
            status_bytes = bytes([sw1, sw2])
            self.logfn(f"Received [{status_bytes.hex()}] {bytes(result).hex()}")
            if status_bytes[0] in [0x90, MORE_DATA_STATUS_BYTE]:
                data_final += bytes(result)

        if status_bytes != b"\x90\x00" and status_bytes[0] != MORE_DATA_STATUS_BYTE:
            raise StatusError(int.from_bytes(status_bytes, byteorder="big"))

        if log_multipacket:
            self.logfn(
                f"Received final data: [{status_bytes.hex()}] {data_final.hex() if data_final else data_final!r}"
            )

        if data_final:
            try:
                self.logfn(f"Decoded received: {data_final.hex()}")
            except Exception:
                pass

        return data_final

    def authenticate_admin(self, admin_key: bytes) -> None:

        if len(admin_key) == 24:
            algorithm: Union[TripleDES, algorithms.AES128, algorithms.AES256] = (
                TripleDES(admin_key)
            )
            # algo = "tdes"
            algo_byte = 0x03
            expected_len = 8
        elif len(admin_key) == 16:
            algorithm = algorithms.AES128(admin_key)
            # algo = "aes128"
            algo_byte = 0x08
            expected_len = 16
        elif len(admin_key) == 32:
            algorithm = algorithms.AES256(admin_key)
            # algo = "aes256"
            algo_byte = 0x0C
            expected_len = 16
        else:
            local_critical(
                "Unsupported key length",
                support_hint=False,
            )

        challenge_body = Tlv.build([(0x7C, Tlv.build([(0x80, b"")]))])
        challenge_response = self.send_receive(0x87, algo_byte, 0x9B, challenge_body)
        general_auth_data = find_by_id(0x7C, Tlv.parse(challenge_response))
        if general_auth_data is None:
            local_critical("Failed to get response to GENERAL AUTHENTICATE")
            return

        challenge = find_by_id(
            0x80,
            Tlv.parse(general_auth_data),
        )

        if challenge is None:
            local_critical("Failed to get authentication challenge from the device")
            return

        # challenge = decoded.first_by_id(0x7C).data.first_by_id(0x80).data
        if len(challenge) != expected_len:
            local_critical("Got unexpected authentication challenge length")

        our_challenge = os.urandom(expected_len)
        cipher = Cipher(algorithm, mode=modes.ECB())
        decryptor = cipher.decryptor()
        response = decryptor.update(challenge) + decryptor.finalize()
        decryptor = cipher.decryptor()
        our_challenge_encrypted = decryptor.update(our_challenge) + decryptor.finalize()
        response_body = Tlv.build(
            [(0x7C, Tlv.build([(0x80, response), (0x81, our_challenge_encrypted)]))]
        )

        final_response = self.send_receive(0x87, algo_byte, 0x9B, response_body)
        general_auth_data = find_by_id(0x7C, Tlv.parse(final_response))
        if general_auth_data is None:
            local_critical("Failed to get response to GENERAL AUTHENTICATE")
            return

        decoded_challenge = find_by_id(
            0x82,
            Tlv.parse(general_auth_data),
        )

        if decoded_challenge != our_challenge:
            local_critical(
                "Failed to authenticate with administrator key", support_hint=False
            )

    def set_admin_key(self, new_key: bytes) -> None:
        if len(new_key) == 24:
            # algo = "tdes"
            algo_byte = 0x03
        elif len(new_key) == 16:
            # algo = "aes128"
            algo_byte = 0x08
        elif len(new_key) == 32:
            # algo = "aes256"
            algo_byte = 0x0C
        else:
            local_critical(
                "Unsupported key length",
                support_hint=False,
            )
        data = bytes([algo_byte, 0x9B, len(new_key)]) + new_key
        self.send_receive(0xFF, 0xFF, 0xFE, data)

    def encode_pin(self, pin: str) -> bytes:
        body = pin.encode("utf-8")
        if len(body) > 8:
            local_critical("PIN can only be up to 8 bytes long", support_hint=False)

        body += bytes([0xFF for i in range(8 - len(body))])
        return body

    def login(self, pin: str) -> None:
        body = self.encode_pin(pin)
        self.send_receive(0x20, 0x00, 0x80, body)

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        body = self.encode_pin(old_pin) + self.encode_pin(new_pin)
        self.send_receive(0x24, 0, 0x80, body)

    def change_puk(self, old_puk: str, new_puk: str) -> None:
        old_puk_bytes = old_puk.encode("utf-8")
        new_puk_bytes = new_puk.encode("utf-8")
        if len(old_puk_bytes) != 8 or len(new_puk) != 8:
            local_critical("PUK must be 8 bytes long", support_hint=False)
        body = old_puk_bytes + new_puk_bytes
        self.send_receive(0x24, 0, 0x81, body)

    def reset_retry_counter(self, puk: str, new_pin: str) -> None:
        puk_bytes = puk.encode("utf-8")

        if len(puk_bytes) != 8:
            local_critical("PUK must be 8 bytes long", support_hint=False)

        body = puk_bytes + self.encode_pin(new_pin)
        self.send_receive(0x2C, 0, 0x80, body)

    def factory_reset(self) -> None:
        self.send_receive(0xFB, 0, 0)

    def sign_p256(self, data: bytes, key: int) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        payload = digest.finalize()
        return self.raw_sign(payload, key, 0x11)

    def sign_rsa2048(self, data: bytes, key: int) -> bytes:
        payload = prepare_for_pkcs1v15_sign_2048(data)
        return self.raw_sign(payload, key, 0x07)

    def raw_sign(self, payload: bytes, key: int, algo: int) -> bytes:
        body = Tlv.build([(0x7C, Tlv.build([(0x81, payload), (0x82, b"")]))])
        result = self.send_receive(0x87, algo, key, body)
        general_auth_data = find_by_id(0x7C, Tlv.parse(result))
        if general_auth_data is None:
            local_critical("Failed to get response to GENERAL AUTHENTICATE")
            return bytes()

        signature = find_by_id(
            0x82,
            Tlv.parse(general_auth_data),
        )

        if signature is None:
            local_critical("Failed to get signature from device")
            # Satisfy the type checker.
            # local_critical raises always raises an error
            return b""

        return signature

    def init(self) -> bytes:
        # Template for card capabilities with nothing but a random ID
        template_begin = bytearray.fromhex("f015a000000116")
        template_end = bytearray.fromhex(
            "f10121f20121f300f40100f50110f600f700fa00fb00fc00fd00fe00"
        )
        card_id = os.urandom(16)
        cardcaps = template_begin + card_id + template_end
        cardcaps_body = Tlv.build(
            [(0x5C, bytes(bytearray.fromhex("5fc107"))), (0x53, bytes(cardcaps))]
        )
        self.send_receive(0xDB, 0x3F, 0xFF, cardcaps_body)

        pinfo_body = Tlv.build(
            [
                (0x5C, bytes(bytearray.fromhex("5FC109"))),
                (
                    0x53,
                    Tlv.build(
                        [
                            (0x01, "Nitrokey PIV user".encode("ascii")),
                            # TODO: use representation of real serial number of card (currently static value)
                            # Base 10 representation of
                            # https://github.com/Nitrokey/piv-authenticator/blob/2c948a966f3e410e9a4cee3c351ca20b956383e0/src/lib.rs#L197
                            (0x05, "5437251".encode("ascii")),
                        ]
                    ),
                ),
            ]
        )
        self.send_receive(0xDB, 0x3F, 0xFF, pinfo_body)
        return card_id

    def serial(self) -> int:
        response = self.send_receive(0x01, 0x00, 0x00)
        return int.from_bytes(response, byteorder="big")

    def reader(self) -> str:
        reader: str = self.connection.getReader()  # type: ignore
        return reader

    def guid(self) -> bytes:
        payload = Tlv.build([(0x5C, bytes(bytearray.fromhex("5FC102")))])
        chuid = self.send_receive(0xCB, 0x3F, 0xFF, payload)

        chuid_tmp = find_by_id(0x53, Tlv.parse(chuid))
        if chuid_tmp is None:
            local_critical("Failed to get chuid from device")
            return b""

        chuid_data = find_by_id(0x34, Tlv.parse(chuid_tmp))
        if chuid_data is None:
            local_critical("Failed to get chuid from device")
            # Satisfy the type checker.
            # local_critical raises always raises an error
            return b""

        return chuid_data

    def cert(self, container_id: bytes) -> Optional[bytes]:
        payload = Tlv.build([(0x5C, container_id)])
        try:
            cert = self.send_receive(0xCB, 0x3F, 0xFF, payload)
            parsed = Tlv.parse(cert)
            if len(parsed) != 1:
                local_critical("Bad number of elements", support_hint=False)

            tag, value = parsed[0]
            if tag != 0x53:
                local_critical("Bad tag", support_hint=False)

            parsed = Tlv.parse(value)
            if len(parsed) < 1:
                local_critical("Bad number of sub-elements", support_hint=False)

            tag, value = parsed[0]
            if tag != 0x70:
                local_critical("Bad tag", support_hint=False)

            return value

        except StatusError as e:
            if e.value == 0x6A82:
                return None
            else:
                raise ValueError(f"{hex(e.value)}, Received error")
