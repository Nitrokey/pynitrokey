import hashlib
import os
from typing import Optional

import nethsm as nethsm_sdk
from nethsm import Base64, NetHSM
from nitrokey.trussed._bootloader.nrf52_upload.dfu.signing import Signing

from pynitrokey.cli.nethsm import Config

try:
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
            sk = sk_file.read()

        client = self.connect_nethsm()
        keys_list = client.list_keys(prefix=sk)
        client.close()
        if sk in keys_list:
            self.sk = sk
            return False  # Not using default key of nrfutil

        raise AssertionError(f"Key {sk} not found in the HSM")

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
