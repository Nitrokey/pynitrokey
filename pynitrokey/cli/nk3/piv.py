import datetime
import sys
from typing import Optional, Sequence

import click
import cryptography
from asn1crypto import x509
from asn1crypto.csr import CertificationRequest, CertificationRequestInfo
from asn1crypto.keys import PublicKeyInfo
from ber_tlv.tlv import Tlv
from click_aliases import ClickAliasedGroup
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding

from pynitrokey.cli.nk3 import nk3
from pynitrokey.helpers import local_critical, local_print
from pynitrokey.nk3.piv_app import PivApp, find_by_id


@nk3.group(cls=ClickAliasedGroup)
def piv() -> None:
    """Nitrokey PIV App"""
    pass


@piv.command()
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


@piv.command()
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


@piv.command()
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
            parsed_cert = cryptography.x509.load_der_x509_certificate(cert)
            local_print(f"    {key}")
            local_print(
                f"        algorithm: {parsed_cert.signature_algorithm_oid._name}"
            )
    if not printed_head:
        local_print("No certificate found")
    pass


@piv.command()
@click.option(
    "--current-admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
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


@piv.command()
@click.option(
    "--current-pin",
    type=click.STRING,
    prompt="Enter the PIN",
    hide_input=True,
)
@click.option(
    "--new-pin",
    type=click.STRING,
    prompt="Enter the PIN",
    hide_input=True,
)
def change_pin(current_pin: str, new_pin: str) -> None:
    device = PivApp()
    device.change_pin(current_pin, new_pin)
    local_print("Changed pin successfully")


@piv.command()
@click.option(
    "--current-puk",
    type=click.STRING,
    prompt="Enter the current PUK",
    hide_input=True,
)
@click.option(
    "--new-puk",
    type=click.STRING,
    prompt="Enter the new PUK",
    hide_input=True,
)
def change_puk(current_puk: str, new_puk: str) -> None:
    device = PivApp()
    device.change_puk(current_puk, new_puk)
    local_print("Changed puk successfully")


@piv.command()
@click.option(
    "--puk",
    type=click.STRING,
    prompt="Enter the PUK",
    hide_input=True,
)
@click.option(
    "--new-pin",
    type=click.STRING,
    prompt="Enter the new PIN",
    hide_input=True,
)
def reset_retry_counter(puk: str, new_pin: str) -> None:
    device = PivApp()
    device.reset_retry_counter(puk, new_pin)
    local_print("Unlocked PIN successfully")


@piv.command()
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


@piv.command()
@click.option(
    "--admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
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
        ]
    ),
    default="9A",
)
@click.option(
    "--algo",
    type=click.Choice(["rsa2048", "nistp256"]),
    default="nistp256",
)
@click.option(
    "--domain-component",
    type=click.STRING,
    multiple=True,
)
@click.option(
    "--subject-name",
    type=click.STRING,
    multiple=True,
)
@click.option(
    "--subject-alt-name-upn",
    type=click.STRING,
)
@click.option(
    "--pin",
    type=click.STRING,
    prompt="Enter the PIN",
    hide_input=True,
)
@click.option(
    "--out-file",
    type=click.Path(allow_dash=True),
    default="-",
)
def generate_key(
    admin_key: str,
    key: str,
    algo: str,
    domain_component: Optional[Sequence[str]],
    subject_name: Optional[Sequence[str]],
    subject_alt_name_upn: Optional[str],
    pin: str,
    out_file: str,
) -> None:
    try:
        admin_key_bytes = bytearray.fromhex(admin_key)
    except ValueError:
        local_critical(
            "Key is expected to be an hexadecimal string",
            support_hint=False,
        )
    key_hex = key
    key_ref = int(key_hex, 16)

    device = PivApp()
    device.authenticate_admin(admin_key_bytes)
    device.login(pin)

    if algo == "rsa2048":
        algo_id = b"\x07"
        signature_algorithm = "sha256_rsa"
    elif algo == "nistp256":
        algo_id = b"\x11"
        signature_algorithm = "sha256_ecdsa"
    else:
        local_critical("Unimplemented algorithm", support_hint=False)

    body = Tlv.build({0xAC: {0x80: algo_id}})
    ins = 0x47
    p1 = 0
    p2 = key_ref
    response = device.send_receive(ins, p1, p2, body)

    data = Tlv.parse(response, recursive=False)
    data = Tlv.parse(find_by_id(0x7F49, data), recursive=False)

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
        public_key_der = public_key_ecc.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
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
        public_key_der = public_key_rsa.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        local_critical("Unimplemented algorithm")

    public_key_info = PublicKeyInfo.load(public_key_der, strict=True)

    if domain_component is None:
        domain_component = []

    if subject_name is None:
        rdns = []
    else:
        rdns = [
            x509.RelativeDistinguishedName(
                [
                    x509.NameTypeAndValue(
                        {
                            "type": x509.NameType.map("domain_component"),
                            "value": x509.DNSName(subject),
                        }
                    )
                ]
            )
            for subject in domain_component
        ] + [
            x509.RelativeDistinguishedName(
                [
                    x509.NameTypeAndValue(
                        {
                            "type": x509.NameType.map("common_name"),
                            "value": x509.DirectoryString(
                                name="utf8_string", value=subject
                            ),
                        }
                    )
                ]
            )
            for subject in subject_name
        ]

    extensions = [
        {
            "extn_id": "basic_constraints",
            "critical": True,
            "extn_value": x509.BasicConstraints({"ca": False}),
        },
        {
            "extn_id": "key_usage",
            "critical": True,
            "extn_value": x509.KeyUsage({"digital_signature", "non_repudiation"}),
        },
        {
            "extn_id": "extended_key_usage",
            "critical": False,
            "extn_value": x509.ExtKeyUsageSyntax(
                ["client_auth", "microsoft_smart_card_logon"]
            ),
        },
    ]

    if subject_alt_name_upn is not None:
        extensions.append(
            {
                "extn_id": "subject_alt_name",
                "critical": False,
                "extn_value": [
                    x509.GeneralName(
                        "other_name",
                        {
                            "type_id": "1.3.6.1.4.1.311.20.2.3",
                            "value": x509.UTF8String(subject_alt_name_upn).retag(
                                {"explicit": 0}
                            ),
                        },
                    )
                ],
            }
        )

    csr_info = CertificationRequestInfo(
        {
            "version": "v1",
            "subject": x509.Name(name="", value=x509.RDNSequence(rdns)),
            "subject_pk_info": public_key_info,
            "attributes": [{"type": "extension_request", "values": [extensions]}],
        }
    )

    # To Be Signed
    tbs = csr_info.dump()

    if algo == "nistp256":
        signature = device.sign_p256(tbs, key_ref)
    elif algo == "rsa2048":
        signature = device.sign_rsa2048(tbs, key_ref)
    else:
        local_critical("Unimplemented algorithm")

    csr = CertificationRequest(
        {
            "certification_request_info": csr_info,
            "signature_algorithm": {
                "algorithm": signature_algorithm,
            },
            "signature": signature,
        }
    )

    with click.open_file(out_file, mode="wb") as file:
        file.write(csr.dump())

    cert_info = x509.TbsCertificate(
        {
            "version": "v3",
            "subject": x509.Name(name="", value=x509.RDNSequence(rdns)),
            "issuer": x509.Name(name="", value=x509.RDNSequence(rdns)),
            "serial_number": 0,
            "signature": {
                "algorithm": signature_algorithm,
            },
            "validity": {
                "not_before": x509.GeneralizedTime(
                    datetime.datetime(
                        2000, 1, 1, tzinfo=datetime.timezone(datetime.timedelta())
                    )
                ),
                "not_after": x509.GeneralizedTime(
                    datetime.datetime(
                        2099, 1, 1, tzinfo=datetime.timezone(datetime.timedelta())
                    )
                ),
            },
            "subject_public_key_info": public_key_info,
            "extensions": extensions,
        }
    )

    tbs = cert_info.dump()
    if algo == "nistp256":
        signature = device.sign_p256(tbs, key_ref)
    elif algo == "rsa2048":
        signature = device.sign_rsa2048(tbs, key_ref)
    else:
        local_critical("Unimplemented algorithm")

    certificate = x509.Certificate(
        {
            "tbs_certificate": cert_info,
            "signature_value": signature,
            "signature_algorithm": {"algorithm": signature_algorithm},
        }
    ).dump()
    payload = Tlv.build(
        {
            0x5C: bytes(bytearray.fromhex(KEY_TO_CERT_OBJ_ID_MAP[key_hex])),
            0x53: Tlv.build({0x70: certificate, 0x71: bytes([0])}),
        }
    )

    device.send_receive(0xDB, 0x3F, 0xFF, payload)


@piv.command()
@click.argument(
    "admin-key",
    type=click.STRING,
    default="010203040506070801020304050607080102030405060708",
)
@click.option("--format", type=click.Choice(["DER", "PEM"]), default="PEM")
@click.option(
    "--key",
    type=click.Choice(
        [
            "9A",
            " 9C",
            " 9D",
            " 9E",
            " 82",
            " 83",
            " 84",
            " 85",
            " 86",
            " 87",
            " 88",
            " 89",
            " 8A",
            " 8B",
            " 8C",
            " 8D",
            " 8E",
            " 8F",
            " 90",
            " 91",
            " 92",
            " 93",
            " 94",
            " 95",
        ]
    ),
    default="9A",
)
@click.option(
    "--path",
    type=click.Path(allow_dash=True),
    default="-",
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
    if format == "DER":
        cert_serialized = cert_bytes
        cert = cryptography.x509.load_der_x509_certificate(cert_bytes)
    elif format == "PEM":
        cert = cryptography.x509.load_pem_x509_certificate(cert_bytes)
        cert_serialized = cert.public_bytes(Encoding.DER)

    payload = Tlv.build(
        {
            0x5C: bytes(bytearray.fromhex(KEY_TO_CERT_OBJ_ID_MAP[key])),
            0x53: Tlv.build({0x70: cert_serialized, 0x71: bytes([0])}),
        }
    )

    device.send_receive(0xDB, 0x3F, 0xFF, payload)


@piv.command()
@click.option("--out-format", type=click.Choice(["DER", "PEM"]), default="PEM")
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
        ]
    ),
    default="9A",
)
@click.option("--path", type=click.Path(allow_dash=True), default="-")
def read_certificate(out_format: str, key: str, path: str) -> None:
    device = PivApp()

    value = device.cert(bytes(bytearray.fromhex(KEY_TO_CERT_OBJ_ID_MAP[key])))

    if value is None:
        print("Certificate not found", file=sys.stderr)
        return

    if out_format == "DER":
        cert_serialized = value
        cryptography.x509.load_der_x509_certificate(value)
    elif out_format == "PEM":
        cert = cryptography.x509.load_der_x509_certificate(value)
        cert_serialized = cert.public_bytes(Encoding.PEM)

    with click.open_file(path, mode="wb") as f:
        f.write(cert_serialized)
