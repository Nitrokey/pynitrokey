import base64
import datetime
import io
import ipaddress
import re
import secrets
import shlex
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from click import Command, Context
from conftest import UserData
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from nethsm import NetHSM, Role
from utilities import add_user

from pynitrokey.cli.nethsm import Config
from pynitrokey.cli.nethsm import nethsm as nethsmgrp

operator_user = UserData(
    user_id="operator", real_name="operator", role=Role.OPERATOR, passphrase="operatoroperator"
)
metrics_user = UserData(
    user_id="metrics", real_name="metrics", role=Role.METRICS, passphrase="metricsmetrics"
)
backup_user = UserData(
    user_id="backup", real_name="backup", role=Role.BACKUP, passphrase="backupbackup"
)


class CA:
    """
    CA implementation based on the cryptography documentation:
    https://cryptography.io/en/latest/x509/tutorial/#creating-a-ca-hierarchy
    """

    def __init__(self) -> None:
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_id = secrets.token_hex(8)

        now = datetime.datetime.now(datetime.timezone.utc)
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )

        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"NetHSM Test CA {self.ca_id}")])
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(name)
        builder = builder.public_key(self.ca_key.public_key())
        builder = builder.issuer_name(name)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=1))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(key_usage, critical=True)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()), critical=False
        )
        self.ca_cert = builder.sign(self.ca_key, hashes.SHA256())

    def sign(self, csr: x509.CertificateSigningRequest) -> bytes:
        issuer_cert = self.ca_cert
        issuer_key = self.ca_key

        now = datetime.datetime.now(datetime.timezone.utc)
        ip = x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(issuer_cert.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + datetime.timedelta(days=1))
        builder = builder.add_extension(x509.SubjectAlternativeName([ip]), critical=False)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        cert = builder.sign(issuer_key, hashes.SHA256())

        # sanity check
        store = x509.verification.Store([self.ca_cert])
        verifier = x509.verification.PolicyBuilder().store(store).build_server_verifier(ip)
        verifier.verify(cert, intermediates=[])

        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
        return cert_bytes

    @property
    def ca_cert_pem(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)


def get_context(nethsm: NetHSM) -> Context:
    config = Config(
        host=nethsm.host,
        username=nethsm.auth.username if nethsm.auth else None,
        password=nethsm.auth.password if nethsm.auth else None,
        verify_tls=nethsm.client.configuration.verify_ssl,
        ca_certs=nethsm.client.configuration.ssl_ca_cert,
        debug=True,
    )
    return Context(Command("test"), obj=config)


def authenticate_ctx(ctx: Context, user: UserData) -> Context:
    config = ctx.obj
    config.username = user.user_id
    config.password = user.passphrase
    return Context(Command("test"), obj=config)


def run_command(ctx: Context, command: str) -> str:
    stdout = io.StringIO()
    stderr = io.StringIO()
    args = shlex.split(command)
    cmd_name, cmd, rest = nethsmgrp.resolve_command(ctx, args)
    assert cmd
    with redirect_stdout(stdout):
        with redirect_stderr(stderr):
            with cmd.make_context(cmd_name, rest, parent=ctx) as sub_ctx:
                cmd.invoke(sub_ctx)

    output = stdout.getvalue()
    error = stderr.getvalue()
    # This is visible when running pytest with -s. Otherwise it is ignored.
    print(f"stdout: {output}")
    print(f"stderr: {error}")
    assert error == ""

    return output


def test_nethsm_state(nethsm: NetHSM) -> None:
    cmd = "state"
    ctx = get_context(nethsm)
    result = run_command(ctx, cmd)
    assert f"NetHSM {nethsm.host} is Operational\n" == result


def test_nethsm_random(nethsm: NetHSM) -> None:
    cmd = "random 5"
    ctx = get_context(nethsm)
    add_user(nethsm, operator_user)
    operator_ctx = authenticate_ctx(ctx, operator_user)
    result = run_command(operator_ctx, cmd)
    raw_random = base64.b64decode(result)
    assert len(raw_random) == 5


def test_nethsm_metrics(nethsm: NetHSM) -> None:
    cmd = "metrics"
    ctx = get_context(nethsm)
    add_user(nethsm, metrics_user)
    metrics_ctx = authenticate_ctx(ctx, metrics_user)
    result = run_command(metrics_ctx, cmd)
    assert "uptime" in result  # We may modify this later to test something else


def test_nethsm_sysinfo(nethsm: NetHSM) -> None:
    cmd = "system-info"
    ctx = get_context(nethsm)
    result = run_command(ctx, cmd)
    pattern = f"""\
Host:             {nethsm.host}
Firmware version: N/A
Software version: \\d+\\.\\d+
Hardware version: N/A
Build tag:        [a-zA-Z0-9.\\-]+
"""
    assert re.compile(pattern).fullmatch(result) is not None, result


def test_nethsm_getconfig(nethsm: NetHSM) -> None:
    cmd = "get-config --logging --network --time --ntp --unattended-boot --public-key --certificate"
    ctx = get_context(nethsm)
    result = run_command(ctx, cmd)
    assert "Logging" in result
    assert "Network" in result
    assert "Time" in result
    assert "NTP" in result
    assert "Unattended boot" in result
    assert "Public key" in result
    assert "Certificate" in result


def test_nethsm_keygen(nethsm: NetHSM) -> None:
    cmd = "generate-key -t ec_p256 -m ECDSA_Signature -l 512 -k testkeyecdsa -s testkeylabel"
    ctx = get_context(nethsm)
    result = run_command(ctx, cmd)
    assert f"Key testkeyecdsa generated on NetHSM {nethsm.host}\n" == result


def test_nethsm_delete_key(nethsm: NetHSM) -> None:
    cmd = "generate-key -t ec_p256 -m ECDSA_Signature -l 512 -k testkeydel -s testkeylabeldel"
    ctx = get_context(nethsm)
    result = run_command(ctx, cmd)
    assert f"Key testkeydel generated on NetHSM {nethsm.host}\n" == result
    cmd = "delete-key testkeydel"
    result = run_command(ctx, cmd)
    assert f"Key testkeydel deleted on NetHSM {nethsm.host}\n" == result


def test_nethsm_move_key(nethsm: NetHSM) -> None:
    cmd = "generate-key -t ec_p256 -m ECDSA_Signature -l 512 -k testkeymoveold -s testkeylabelmove"
    ctx = get_context(nethsm)
    result = run_command(ctx, cmd)
    assert f"Key testkeymoveold generated on NetHSM {nethsm.host}\n" == result
    cmd = "move-key testkeymoveold testkeymovenew"
    result = run_command(ctx, cmd)
    assert f"Key testkeymoveold moved to testkeymovenew on NetHSM {nethsm.host}\n" == result


def test_nethsm_cluster_ca_cert(nethsm: NetHSM) -> None:
    ctx = get_context(nethsm)

    cmd = "generate-cluster-key --type rsa --length 4096"
    result = run_command(ctx, cmd)
    assert f"Key for cluster peer traffic generated on NetHSM {nethsm.host}\n" == result

    cmd = "get-cluster-public-key"
    result = run_command(ctx, cmd)
    public_key = serialization.load_pem_public_key(result.encode())

    cmd = (
        "csr --cluster --country DE --state-or-province Brandenburg --locality Teltow --organization Nitrokey "
        "--organizational-unit Test --common-name 'NetHSM cluster test' --email-address test@example.com"
    )
    result = run_command(ctx, cmd)
    csr = x509.load_pem_x509_csr(result.encode())
    assert csr.public_key() == public_key

    ca = CA()
    cert = ca.sign(csr)

    with TemporaryDirectory() as d:
        path = Path(d)
        cert_path = path / "cert.pem"
        cert_path.write_bytes(cert)
        ca_path = path / "ca.pem"
        ca_path.write_bytes(ca.ca_cert_pem)

        cmd = f"set-certificate --cluster {cert_path}"
        result = run_command(ctx, cmd)
        assert f"Updated the cluster certificate for NetHSM {nethsm.host}\n" == result

        cmd = f"set-cluster-ca-certificate {ca_path}"
        result = run_command(ctx, cmd)
        assert f"Updated the cluster CA certificate for NetHSM {nethsm.host}\n" == result
