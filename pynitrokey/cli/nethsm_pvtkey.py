import hashlib
import os
from typing import Any

import nethsm as nethsm_sdk
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from nethsm import Base64, NetHSM

from pynitrokey.cli.nethsm import Config

try:
    pass
except Exception:
    print("Failed to import cryptography, cannot do signing")


class NetHSMKey(ec.EllipticCurvePrivateKey):
    _sk: str
    _public_key: ec.EllipticCurvePublicKey
    _nethsm_config: Config

    def __init__(self, config: Config, sk: str) -> None:
        if config.host is None:
            v = "NETHSM_HOST"
            if v not in os.environ:
                raise AssertionError(
                    f"Missing NetHSM host: set the --host option or the {v} environment variable"
                )
            config.host = os.environ.get(v)
        self._nethsm_config = config
        if sk:
            self._load_key(sk)

    def _connect_nethsm(self) -> NetHSM:
        config = self._nethsm_config
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

    def _load_key(self, key_id: str) -> bool:
        sk = key_id
        client = self._connect_nethsm()
        keys_list = client.list_keys(prefix=sk)
        client.close()
        if sk in keys_list:
            self._sk = sk
            pem_data = client.get_key_public_key(self._sk)
            pub_temp = serialization.load_pem_public_key(pem_data.encode())
            assert isinstance(pub_temp, ec.EllipticCurvePublicKey)
            self._public_key = pub_temp

            return False  # Not using default key of nrfutil

        raise AssertionError(f"Key {sk} not found in the HSM")

    def sign(self, data: bytes, signature_algorithm: ec.EllipticCurveSignatureAlgorithm) -> bytes:
        if self._sk is None:
            raise AssertionError("Can't sign. No key created/loaded")
        assert isinstance(signature_algorithm, ec.ECDSA)
        assert isinstance(signature_algorithm.algorithm, hashes.SHA256)

        hash_data = hashlib.sha256(data).digest()
        to_data = Base64.encode(hash_data)

        client = self._connect_nethsm()
        der_signature = client.sign(
            key_id=self._sk, data=to_data, mode=nethsm_sdk.SignMode.ECDSA
        ).decode()
        client.close()
        return der_signature

    def exchange(self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        raise NotImplementedError()

    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._public_key

    @property
    def curve(self) -> ec.EllipticCurve:
        return self._public_key.curve

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        raise NotImplementedError()

    @property
    def key_size(self) -> int:
        return self._public_key.key_size

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()

    def __copy__(self) -> "NetHSMKey":
        raise NotImplementedError()

    def __deepcopy__(self, memo: dict[Any, Any]) -> "NetHSMKey":
        raise NotImplementedError()
