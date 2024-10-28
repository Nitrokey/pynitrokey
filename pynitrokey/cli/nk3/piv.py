import datetime
import sys
from typing import Optional, Sequence, Tuple, Union

import click
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import Encoding

from pynitrokey.cli.nk3 import nk3
from pynitrokey.helpers import check_experimental_flag, local_critical, local_print
from pynitrokey.nk3.piv_app import PivApp, find_by_id
from pynitrokey.tlv import Tlv


class RsaPivSigner(rsa.RSAPrivateKey):
    _device: PivApp
    _key_reference: int
    _public_key: rsa.RSAPublicKey

    def __init__(
        self, device: PivApp, key_reference: int, public_key: rsa.RSAPublicKey
    ):
        self._device = device
        self._key_reference = key_reference
        self._public_key = public_key

    def public_key(self) -> rsa.RSAPublicKey:
        return self._public_key

    @property
    def key_size(self) -> int:
        return self._public_key.key_size

    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> bytes:
        assert not isinstance(algorithm, asym_utils.Prehashed)
        assert isinstance(padding, PKCS1v15)
        assert isinstance(algorithm, hashes.SHA256)

        return self._device.sign_rsa2048(data, self._key_reference)

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError()

    def private_numbers(self) -> rsa.RSAPrivateNumbers:
        raise NotImplementedError()

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError()


class P256PivSigner(ec.EllipticCurvePrivateKey):
    _device: PivApp
    _key_reference: int
    _public_key: ec.EllipticCurvePublicKey

    def __init__(
        self, device: PivApp, key_reference: int, public_key: ec.EllipticCurvePublicKey
    ):
        self._device = device
        self._key_reference = key_reference
        self._public_key = public_key

    def exchange(
        self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
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

    def sign(
        self, data: bytes, signature_algorithm: ec.EllipticCurveSignatureAlgorithm
    ) -> bytes:
        assert isinstance(signature_algorithm, ec.ECDSA)
        assert isinstance(signature_algorithm.algorithm, hashes.SHA256)

        return self._device.sign_p256(data, self._key_reference)


@nk3.group()
@click.option(
    "--experimental",
    default=False,
    is_flag=True,
    help="Allow to execute experimental features",
)
def piv(experimental: bool) -> None:
    """Nitrokey PIV App"""
    check_experimental_flag(experimental)
    pass


@piv.command(help="Authenticate with the admin key.")
@click.argument(
    "admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
)
def admin_auth(admin_key: str) -> None:
    try:
        admin_key_bytes = bytearray.fromhex(admin_key)
    except ValueError:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )

    device = PivApp()
    device.authenticate_admin(admin_key_bytes)
    local_print("Authenticated successfully")


@piv.command(help="Initialize the PIV application.")
@click.argument(
    "admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
)
def init(admin_key: str) -> None:
    try:
        admin_key_bytes = bytearray.fromhex(admin_key)
    except ValueError:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )

    device = PivApp()
    device.authenticate_admin(admin_key_bytes)
    guid = device.init()
    local_print("Device intialized successfully")
    local_print(f"GUID: {guid.hex().upper()}")


@piv.command(help="Print information about the PIV application.")
def info() -> None:
    device = PivApp()
    serial_number = device.serial()
    local_print(f"Device: {serial_number}")
    reader = device.reader()
    local_print(f"Reader: {reader}")
    guid = device.guid()
    local_print(f"GUID: {guid.hex().upper()}")

    printed_head = False
    for key, slot in KEY_TO_CERT_OBJ_ID_MAP.items():
        cert = device.cert(bytes(bytearray.fromhex(slot)))
        if cert is not None:
            if not printed_head:
                local_print("Keys:")
                printed_head = True
            parsed_cert = x509.load_der_x509_certificate(cert)
            local_print(f"    {key}")
            local_print(
                f"        algorithm: {parsed_cert.signature_algorithm_oid._name}"
            )
    if not printed_head:
        local_print("No certificate found")
    pass


@piv.command(help="Change the admin key.")
@click.option(
    "--current-admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
    help="Current admin key.",
)
@click.argument(
    "new-admin-key",
    type=click.STRING,
)
def change_admin_key(current_admin_key: str, new_admin_key: str) -> None:
    try:
        current_admin_key_bytes = bytearray.fromhex(current_admin_key)
        new_admin_key_bytes = bytearray.fromhex(new_admin_key)
    except ValueError:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )

    device = PivApp()
    device.authenticate_admin(current_admin_key_bytes)
    device.set_admin_key(new_admin_key_bytes)
    local_print("Changed key successfully")


@piv.command(help="Change the PIN.")
@click.option(
    "--current-pin",
    type=click.STRING,
    prompt="Enter the current PIN",
    hide_input=True,
    help="Current PIN.",
)
@click.option(
    "--new-pin",
    type=click.STRING,
    prompt="Enter the new PIN",
    hide_input=True,
    help="New PIN.",
)
def change_pin(current_pin: str, new_pin: str) -> None:
    device = PivApp()
    device.change_pin(current_pin, new_pin)
    local_print("Changed pin successfully")


@piv.command(help="Change the PUK.")
@click.option(
    "--current-puk",
    type=click.STRING,
    prompt="Enter the current PUK",
    hide_input=True,
    help="Current PUK.",
)
@click.option(
    "--new-puk",
    type=click.STRING,
    prompt="Enter the new PUK",
    hide_input=True,
    help="New PUK.",
)
def change_puk(current_puk: str, new_puk: str) -> None:
    device = PivApp()
    device.change_puk(current_puk, new_puk)
    local_print("Changed puk successfully")


@piv.command(help="Reset the retry counter.")
@click.option(
    "--puk",
    type=click.STRING,
    prompt="Enter the PUK",
    hide_input=True,
    help="Current PUK.",
)
@click.option(
    "--new-pin",
    type=click.STRING,
    prompt="Enter the new PIN",
    hide_input=True,
    help="New PIN.",
)
def reset_retry_counter(puk: str, new_pin: str) -> None:
    device = PivApp()
    device.reset_retry_counter(puk, new_pin)
    local_print("Unlocked PIN successfully")


@piv.command(help="Reset the PIV application.")
def factory_reset() -> None:
    device = PivApp()
    try:
        device.factory_reset()
    except ValueError:
        local_critical(
            "Factory reset could not be performed. You first need to lock the PIN with 3 failed attempts",
            support_hint=False,
        )
    local_print("Factory reset successfully")


KEY_TO_CERT_OBJ_ID_MAP = {
    "9A": "5FC105",
    "9C": "5FC10A",
    "9D": "5FC10B",
    "9E": "5FC101",
    "82": "5FC10D",
    "83": "5FC10E",
    "84": "5FC10F",
    "85": "5FC110",
    "86": "5FC111",
    "87": "5FC112",
    "88": "5FC113",
    "89": "5FC114",
    "8A": "5FC115",
    "8B": "5FC116",
    "8C": "5FC117",
    "8D": "5FC118",
    "8E": "5FC119",
    "8F": "5FC11A",
    "90": "5FC11B",
    "91": "5FC11C",
    "92": "5FC11D",
    "93": "5FC11E",
    "94": "5FC11F",
    "95": "5FC120",
}


@piv.command(help="Generate a new key and certificate signing request.")
@click.option(
    "--admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
    help="Current admin key",
)
@click.option(
    "--key",
    type=click.Choice(
        [
            "9A",
            "9C",
            "9D",
            "9E",
            "82",
            "83",
            "84",
            "85",
            "86",
            "87",
            "88",
            "89",
            "8A",
            "8B",
            "8C",
            "8D",
            "8E",
            "8F",
            "90",
            "91",
            "92",
            "93",
            "94",
            "95",
        ],
        case_sensitive=False,
    ),
    default="9A",
    help="Key slot for operation.",
)
@click.option(
    "--algo",
    type=click.Choice(["rsa2048", "nistp256"], case_sensitive=False),
    default="nistp256",
    help="Algorithm for the key.",
)
@click.option(
    "--domain-component",
    type=click.STRING,
    multiple=True,
    help="Domain component for the certificate signing request.",
)
@click.option(
    "--subject-name",
    type=click.STRING,
    multiple=True,
    help="Subject name for the certificate signing request.",
)
@click.option(
    "--subject-alt-name-upn",
    type=click.STRING,
    help="Subject alternative name (UPN) for the certificate signing request.",
)
@click.option(
    "--pin",
    type=click.STRING,
    prompt="Enter the PIN",
    hide_input=True,
    help="Current PIN.",
)
@click.option(
    "--path",
    type=click.Path(allow_dash=True),
    default="-",
    help="Write certificate signing request to path.",
)
def generate_key(
    admin_key: str,
    key: str,
    algo: str,
    domain_component: Optional[Sequence[str]],
    subject_name: Optional[Sequence[str]],
    subject_alt_name_upn: Optional[str],
    pin: str,
    path: str,
) -> None:
    try:
        admin_key_bytes = bytearray.fromhex(admin_key)
    except ValueError:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )
    key_hex = key.upper()
    key_ref = int(key_hex, 16)

    device = PivApp()
    device.authenticate_admin(admin_key_bytes)
    device.login(pin)

    algo = algo.lower()
    if algo == "rsa2048":
        algo_id = b"\x07"
    elif algo == "nistp256":
        algo_id = b"\x11"
    else:
        local_critical("Unimplemented algorithm", support_hint=False)

    body = Tlv.build([(0xAC, Tlv.build([(0x80, algo_id)]))])
    ins = 0x47
    p1 = 0
    p2 = key_ref
    response = device.send_receive(ins, p1, p2, body)

    data = Tlv.parse(response)
    data_tmp = find_by_id(0x7F49, data)
    if data_tmp is None:
        local_critical("Device did not send public key data")
        return

    data = Tlv.parse(data_tmp)

    if algo == "nistp256":
        key_data = find_by_id(0x86, data)
        if key_data is None:
            local_critical("Device did not send public key data")
            return
        key_data = key_data[1:]
        public_x = int.from_bytes(key_data[:32], byteorder="big", signed=False)
        public_y = int.from_bytes(key_data[32:], byteorder="big", signed=False)
        public_numbers_ecc = ec.EllipticCurvePublicNumbers(
            public_x,
            public_y,
            cryptography.hazmat.primitives.asymmetric.ec.SECP256R1(),
        )
        public_key_ecc = public_numbers_ecc.public_key()
    elif algo == "rsa2048":
        modulus_data = find_by_id(0x81, data)
        exponent_data = find_by_id(0x82, data)
        if modulus_data is None or exponent_data is None:
            local_critical("Device did not send public key data")
            return

        modulus = int.from_bytes(modulus_data, byteorder="big", signed=False)
        exponent = int.from_bytes(exponent_data, byteorder="big", signed=False)
        public_numbers_rsa = rsa.RSAPublicNumbers(exponent, modulus)
        public_key_rsa = public_numbers_rsa.public_key()
    else:
        local_critical("Unimplemented algorithm")

    certificate_builder = x509.CertificateBuilder()
    csr_builder = x509.CertificateSigningRequestBuilder()

    if domain_component is None:
        domain_component = []

    if subject_name is None:
        crypto_rdns = x509.Name([])
    else:
        crypto_rdns = x509.Name(
            [
                x509.RelativeDistinguishedName(
                    [
                        x509.NameAttribute(x509.NameOID.DOMAIN_COMPONENT, subject)
                        for subject in domain_component
                    ]
                ),
                x509.RelativeDistinguishedName(
                    [
                        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)
                        for subject in subject_name
                    ]
                ),
            ]
        )

    certificate_builder = (
        certificate_builder.subject_name(crypto_rdns)
        .issuer_name(crypto_rdns)
        .not_valid_before(datetime.datetime(2000, 1, 1, 0, 0))
        .not_valid_after(datetime.datetime(2099, 1, 1, 0, 0))
        .serial_number(x509.random_serial_number())
    )
    csr_builder = csr_builder.subject_name(crypto_rdns)

    # SEQUENCE
    # SEQUENCE
    # OBJECT            :aes-256-cbc
    # SEQUENCE
    # OBJECT            :id-aes256-wrap
    # SEQUENCE
    # OBJECT            :aes-192-cbc
    # SEQUENCE
    # OBJECT            :id-aes192-wrap
    # SEQUENCE
    # OBJECT            :aes-128-cbc
    # SEQUENCE
    # OBJECT            :id-aes128-wrap
    # SEQUENCE
    # OBJECT            :des-ede3-cbc
    # SEQUENCE
    # OBJECT            :des-cbc
    # SEQUENCE
    # OBJECT            :rc2-cbc
    # INTEGER           :80
    # SEQUENCE
    # OBJECT            :rc4
    # INTEGER           :0200
    smime_extension = bytes(
        bytearray.fromhex(
            "308183300B060960864801650304012A300B060960864801650304012D300B0609608648016503040116300B0609608648016503040119300B0609608648016503040102300B0609608648016503040105300A06082A864886F70D0307300706052B0E030207300E06082A864886F70D030202020080300E06082A864886F70D030402020200"
        )
    )

    crypto_extensions: Sequence[Tuple[x509.ExtensionType, bool]] = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        ),
        (
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.oid.ExtendedKeyUsageOID.SMARTCARD_LOGON,
                ]
            ),
            False,
        ),
        (
            x509.UnrecognizedExtension(
                oid=x509.oid.ObjectIdentifier("1.2.840.113549.1.9.15"),
                value=smime_extension,
            ),
            False,
        ),
    ]

    for ext, critical in crypto_extensions:
        certificate_builder = certificate_builder.add_extension(ext, critical)
        csr_builder = csr_builder.add_extension(ext, critical)

    if subject_alt_name_upn is not None:
        crypto_sujbect_alt_name = x509.SubjectAlternativeName(
            [
                x509.OtherName(
                    x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                    # bytes, because it's different from bytearray, and tlv because
                    # it expects already DER encoded ASN1
                    bytes(Tlv.build([(0x0C, subject_alt_name_upn.encode("utf-8"))])),
                )
            ]
        )
        certificate_builder = certificate_builder.add_extension(
            crypto_sujbect_alt_name, False
        )
        csr_builder = csr_builder.add_extension(crypto_sujbect_alt_name, False)

    if algo == "nistp256":
        csr = csr_builder.sign(
            P256PivSigner(device, key_ref, public_key_ecc), hashes.SHA256()
        )
        certificate = certificate_builder.public_key(public_key_ecc).sign(
            P256PivSigner(device, key_ref, public_key_ecc), hashes.SHA256()
        )
    elif algo == "rsa2048":
        csr = csr_builder.sign(
            RsaPivSigner(device, key_ref, public_key_rsa), hashes.SHA256()
        )
        certificate = certificate_builder.public_key(public_key_rsa).sign(
            RsaPivSigner(device, key_ref, public_key_rsa), hashes.SHA256()
        )
    else:
        local_critical("Unimplemented algorithm")

    with click.open_file(path, mode="wb") as file:
        file.write(csr.public_bytes(Encoding.DER))

    payload = Tlv.build(
        [
            (0x5C, bytes(bytearray.fromhex(KEY_TO_CERT_OBJ_ID_MAP[key_hex]))),
            (
                0x53,
                Tlv.build(
                    [(0x70, certificate.public_bytes(Encoding.DER)), (0x71, bytes([0]))]
                ),
            ),
        ]
    )

    device.send_receive(0xDB, 0x3F, 0xFF, payload)


@piv.command(help="Write a certificate to a key slot.")
@click.argument(
    "admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
)
@click.option(
    "--format",
    type=click.Choice(["DER", "PEM"], case_sensitive=False),
    default="PEM",
    help="Format of certificate.",
)
@click.option(
    "--key",
    type=click.Choice(
        [
            "9A",
            "9C",
            "9D",
            "9E",
            "82",
            "83",
            "84",
            "85",
            "86",
            "87",
            "88",
            "89",
            "8A",
            "8B",
            "8C",
            "8D",
            "8E",
            "8F",
            "90",
            "91",
            "92",
            "93",
            "94",
            "95",
        ],
        case_sensitive=False,
    ),
    default="9A",
    help="Key slot for operation.",
)
@click.option(
    "--path",
    type=click.Path(allow_dash=True),
    default="-",
    help="Write certificate to path.",
)
def write_certificate(admin_key: str, format: str, key: str, path: str) -> None:
    try:
        admin_key_bytes: bytes = bytearray.fromhex(admin_key)
    except ValueError:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )

    device = PivApp()
    device.authenticate_admin(admin_key_bytes)

    with click.open_file(path, mode="rb") as f:
        cert_bytes = f.read()
    format = format.upper()
    if format == "DER":
        cert_serialized = cert_bytes
        cert = x509.load_der_x509_certificate(cert_bytes)
    elif format == "PEM":
        cert = x509.load_pem_x509_certificate(cert_bytes)
        cert_serialized = cert.public_bytes(Encoding.DER)

    payload = Tlv.build(
        [
            (0x5C, bytes(bytearray.fromhex(KEY_TO_CERT_OBJ_ID_MAP[key.upper()]))),
            (0x53, Tlv.build([(0x70, cert_serialized), (0x71, bytes([0]))])),
        ]
    )

    device.send_receive(0xDB, 0x3F, 0xFF, payload)


@piv.command(help="Read a certificate from a key slot.")
@click.option(
    "--format",
    type=click.Choice(["DER", "PEM"], case_sensitive=False),
    default="PEM",
    help="Format of certificate.",
)
@click.option(
    "--key",
    type=click.Choice(
        [
            "9A",
            "9C",
            "9D",
            "9E",
            "82",
            "83",
            "84",
            "85",
            "86",
            "87",
            "88",
            "89",
            "8A",
            "8B",
            "8C",
            "8D",
            "8E",
            "8F",
            "90",
            "91",
            "92",
            "93",
            "94",
            "95",
        ],
        case_sensitive=False,
    ),
    default="9A",
    help="Key slot for operation.",
)
@click.option(
    "--path",
    type=click.Path(allow_dash=True),
    default="-",
    help="Read certificate from path.",
)
def read_certificate(format: str, key: str, path: str) -> None:
    device = PivApp()

    value = device.cert(bytes(bytearray.fromhex(KEY_TO_CERT_OBJ_ID_MAP[key.upper()])))

    if value is None:
        print("Certificate not found", file=sys.stderr)
        return

    format = format.upper()
    if format == "DER":
        cert_serialized = value
        x509.load_der_x509_certificate(value)
    elif format == "PEM":
        cert = x509.load_der_x509_certificate(value)
        cert_serialized = cert.public_bytes(Encoding.PEM)

    with click.open_file(path, mode="wb") as f:
        f.write(cert_serialized)
