import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.sbfile.sb2.images import BootImageV21
from spsdk.sbfile.sb2.sly_bd_parser import BDParser
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import write_file

# The following private key is dummy used to initialize the MBI class
dummy_priv_key = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxpxN6kHTCoCRMGIR
4H4B58AHx5gjn3MnDgSa3qEF7kShRANCAATlvf3y1hlRnVdYcLE1UfBKSoEbwrWn
kjsIL8fJEMWfrcTY1Mlnz1eQ12F4xHIGG2sN014rXyUK+DlA8hLsJF34
-----END PRIVATE KEY-----
"""


class EcSignatureProvider(SignatureProvider):
    identifier = "ec"

    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        self.key = key

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data, ec.ECDSA(hashes.SHA256()))

    @property
    def signature_length(self) -> int:
        return (self.key.key_size + 7) // 8 * 2


def _clean_tempfile(tfile: tempfile._TemporaryFileWrapper) -> None:  # type: ignore
    Path(tfile.name).unlink(missing_ok=True)


def mbi_export(cert_path: str, binary: str, signer: ec.EllipticCurvePrivateKey) -> bytes:
    family = "lpc55s6x"
    cert_block_yaml = f'''
family: {family}
imageBuildNumber: 0

rootCertificate0File: "{cert_path}/nk-firmware-root-cert.der"
rootCertificate1File: "{cert_path}/nk-firmware-ee2-cert.der"
rootCertificate2File: "{cert_path}/nk-firmware-ee3-cert.der"
rootCertificate3File: "{cert_path}/nk-firmware-ee4-cert.der"

mainRootCertId: 0

chainCertificate0File0: "{cert_path}/nk-firmware-ee1-cert.der"
'''

    cert_block_file = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w+t", delete=False)
    cert_block_file.write(cert_block_yaml)
    cert_block_file.close()
    dummy_priv_file = tempfile.NamedTemporaryFile(suffix=".pem", mode="w+t", delete=False)
    dummy_priv_file.write(dummy_priv_key)
    dummy_priv_file.close()

    config_dict = {
        "family": family,
        "outputImageExecutionTarget": "Internal Flash (XIP)",
        "outputImageAuthenticationType": "Signed",
        "inputImageFile": binary,
        "enableTrustZone": True,
        "certBlock": cert_block_file.name,
        "signer": dummy_priv_file.name,
    }

    config = Config(config_dict)
    familyrev = FamilyRevision.load_from_config(config)
    mbi_cls = MasterBootImage.get_mbi_class(config)(family=familyrev)
    for base in mbi_cls._get_mixins():
        base.mix_load_from_config(mbi_cls, config)  # type: ignore
    new_provider = EcSignatureProvider(signer)
    mbi_cls.signature_provider = new_provider  # type: ignore
    mbi_data = mbi_cls.export_image()
    _clean_tempfile(cert_block_file)
    _clean_tempfile(dummy_priv_file)

    return mbi_data.export()


def _get_config_sb2(command_path: str, external_files: list[str]) -> Config:
    family = "lpc55s6x"
    with open(command_path, "r") as f:
        content = f.read().replace("\t", "    ")

    parser = BDParser()
    parsed_conf = Config(parser.parse(content, extern=external_files))

    assert "options" in parsed_conf
    parsed_conf["options"]["family"] = family
    options: dict[str, Any] = parsed_conf["options"]
    parsed_conf["family"] = options.pop("family")
    parsed_conf["revision"] = options.pop("revision", "latest")
    return parsed_conf


def sb21_export(
    parsed_config: Config,
    key: str,
    pkey: ec.EllipticCurvePrivateKey,
    cert_path: str,
    hash_of_hashes: str,
) -> bytes:
    cert = [f"{cert_path}/nk-firmware-root-cert.der", f"{cert_path}/nk-firmware-ee1-cert.der"]

    root_key_cert = [
        f"{cert_path}/nk-firmware-root-cert.der",
        f"{cert_path}/nk-firmware-ee2-cert.der",
        f"{cert_path}/nk-firmware-ee3-cert.der",
        f"{cert_path}/nk-firmware-ee4-cert.der",
    ]
    signature_provider = EcSignatureProvider(pkey)
    sb2 = BootImageV21.load_from_config(
        config=parsed_config,
        key_file_path=key,
        signature_provider=signature_provider,
        signing_certificate_file_paths=cert,
        root_key_certificate_paths=root_key_cert,
        rkth_out_path=hash_of_hashes,
    )
    return sb2.export()


def lpc55_sign_sb2(
    cert_path: str,
    binary_path: str,
    commands: str,
    key: str,
    rkth: str,
    out_file: str,
    signer: ec.EllipticCurvePrivateKey,
) -> None:
    mbi = mbi_export(cert_path, binary_path, signer)
    signed_file = tempfile.NamedTemporaryFile(suffix=".bin", mode="w+b", delete=False)
    signed_file.write(mbi)
    signed_file.close()
    config = _get_config_sb2(commands, [signed_file.name])
    sb21_file = sb21_export(config, key, signer, cert_path, rkth)
    _clean_tempfile(signed_file)
    write_file(sb21_file, out_file, mode="wb")
