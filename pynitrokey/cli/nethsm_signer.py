import datetime
import hashlib
import os
from typing import Optional, cast

import nethsm as nethsm_sdk
from nethsm import Base64, NetHSM
from nitrokey.trussed._bootloader.nrf52_upload.dfu.signing import Signing

from pynitrokey.cli.nethsm import Config

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey,
        EllipticCurvePublicNumbers,
    )
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
except Exception:
    print("Failed to import cryptography, cannot do signing")


class NetHSM_Signing(Signing):
    sk: Optional[str]
    nethsm_config: Config

    def __init__(self, config: Config) -> None:
        self.nethsm_config = config

    @staticmethod
    def from_config(config: Config) -> "NetHSM_Signing":
        if config.host is None:
            v = "NETHSM_HOST"
            if v not in os.environ:
                raise AssertionError(
                    f"Missing NetHSM host: set the --host option or the {v} environment variable"
                )
            config.host = os.environ.get(v)

        signer = NetHSM_Signing(config)
        return signer

    def connect_nethsm(self) -> NetHSM:
        config = self.nethsm_config
        auth = None
        if config.username and config.password:
            auth = nethsm_sdk.Authentication(username=config.username, password=config.password)
        assert config.host, "Host undefined"
        nethsm = NetHSM(
            config.host, auth=auth, verify_tls=config.verify_tls, ca_certs=config.ca_certs
        )
        try:
            return nethsm
        except nethsm_sdk.NetHSMError as e:
            raise AssertionError(f"NetHSM request failed: {e}")
        except nethsm_sdk.NetHSMRequestError as e:
            if e.type == nethsm_sdk.RequestErrorType.SSL_ERROR:
                raise AssertionError(
                    f"Could not connect to the NetHSM: {e.reason}\nIf you use a self-signed certificate, please set the --no-verify-tls option."
                )
            else:
                raise AssertionError(
                    f"Cound not connect to the NetHSM: {e.reason}\nIs the NetHSM running and reachable?"
                )

    def gen_key(self, filename: str) -> None:
        client = self.connect_nethsm()
        self.sk = client.generate_key(
            type=nethsm_sdk.KeyType.EC_P256,
            length=256,
            mechanisms=[nethsm_sdk.KeyMechanism.ECDSA_SIGNATURE],
        )
        client.close()

        with open(filename, "w") as sk_file:
            sk_file.write(self.sk)

    def load_key(self, filename: str) -> bool:
        with open(filename, "r") as sk_file:
            self.sk = sk_file.read()

        return False  # Not using default key of nrfutil

    def sign(self, init_packet_data: bytes) -> bytes:
        if self.sk is None:
            raise AssertionError("Can't sign. No key created/loaded")

        hash_data = hashlib.sha256(init_packet_data).digest()
        data = Base64.encode(hash_data)

        client = self.connect_nethsm()
        der_signature = client.sign(
            key_id=self.sk, data=data, mode=nethsm_sdk.SignMode.ECDSA
        ).decode()
        client.close()
        r, s = decode_dss_signature(der_signature)

        signature = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

        return signature[31::-1] + signature[63:31:-1]

    def get_pub_numbers(self) -> EllipticCurvePublicNumbers:
        if self.sk is None:
            raise AssertionError("Can't get pubkey. No key created/loaded")

        pem_data = self.get_vk_pem()

        if isinstance(pem_data, str):
            pem_data_bytes = pem_data.encode()

        public_key = serialization.load_pem_public_key(pem_data_bytes, backend=default_backend())
        ec_key = cast(EllipticCurvePublicKey, public_key)
        return ec_key.public_numbers()

    def get_vk(self, output_type: Optional[str], dbg: bool) -> str:
        """
        Get public key (as hex, code or pem)
        """
        if self.sk is None:
            raise AssertionError("Can't get key. No key created/loaded")

        if output_type is None:
            raise ValueError("Invalid output type for public key.")
        elif output_type == "hex":
            return self.get_vk_hex()
        elif output_type == "code":
            return self.get_vk_code(dbg)
        elif output_type == "pem":
            return self.get_vk_pem()
        else:
            raise ValueError("Invalid argument. Can't get key")

    def get_vk_hex(self) -> str:
        """
        Get the verification key as hex
        """
        if self.sk is None:
            raise AssertionError("Can't get key. No key created/loaded")

        # Reverse the two halves of key for display. This
        # emulates a memory dump of the key interpreted as two
        # 256bit little endian integers.
        pub_numbers = self.get_pub_numbers()
        key = pub_numbers.x.to_bytes(32, byteorder="big") + pub_numbers.y.to_bytes(
            32, byteorder="big"
        )
        displayed_key = (key[:32][::-1] + key[32:][::-1]).hex()

        return f"Public (verification) key pk:\n{displayed_key}"

    def wrap_code(self, key_code: str, dbg: bool) -> str:
        header = """
/* This file was automatically generated by nrfutil on {0} */

#include "stdint.h"
#include "compiler_abstraction.h"
""".format(datetime.datetime.now().strftime("%Y-%m-%d (YY-MM-DD) at %H:%M:%S"))

        dbg_header = """
/* This file was generated with a throwaway private key, that is only intended for a debug version of the DFU project.
  Please see https://github.com/NordicSemiconductor/pc-nrfutil/blob/master/README.md to generate a valid public key. */

#ifdef NRF_DFU_DEBUG_VERSION
"""
        dbg_footer = """
#else
#error "Debug public key not valid for production. Please see https://github.com/NordicSemiconductor/pc-nrfutil/blob/master/README.md to generate it"
#endif
"""
        if dbg:
            code = header + dbg_header + key_code + dbg_footer
        else:
            code = header + key_code
        return code

    def get_vk_code(self, dbg: bool) -> str:
        """
        Get the verification key as code
        """
        if self.sk is None:
            raise AssertionError("Can't get key. No key created/loaded")

        def to_two_digit_hex_with_0x(b: int) -> str:
            return "0x{:02x}".format(b)

        pub_numbers = self.get_pub_numbers()
        key = pub_numbers.x.to_bytes(32, byteorder="big") + pub_numbers.y.to_bytes(
            32, byteorder="big"
        )
        vk_x_separated = ", ".join(map(to_two_digit_hex_with_0x, key[:32][::-1]))
        vk_y_separated = ", ".join(map(to_two_digit_hex_with_0x, key[32:][::-1]))

        key_code = """
/** @brief Public key used to verify DFU images */
__ALIGN(4) const uint8_t pk[64] =
{{
    {0},
    {1}
}};
"""
        key_code = key_code.format(vk_x_separated, vk_y_separated)
        vk_code = self.wrap_code(key_code, dbg)

        return vk_code

    def get_vk_pem(self) -> str:
        """
        Get the verification key as PEM
        """
        if self.sk is None:
            raise AssertionError("Can't get key. No key created/loaded")

        client = self.connect_nethsm()
        pem_data = client.get_key_public_key(self.sk)
        client.close()
        return pem_data
