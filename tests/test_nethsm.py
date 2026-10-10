import base64
import io
import re
import shlex
from contextlib import redirect_stderr, redirect_stdout

from click import Command, Context
from conftest import UserData
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
