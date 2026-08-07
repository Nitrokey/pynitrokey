# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""
Tests for the formatting of the credentials in the secrets list command.
These do not require a device.
"""

from nitrokey.nk3.secrets_app import Algorithm, Kind, ListItem, ListItemProperties

from pynitrokey.cli.nk3.secrets import format_credential, format_label


def credential(
    label: str,
    kind: Kind = Kind.Totp,
    touch_required: bool = False,
    secret_encryption: bool = False,
    pws_data_exist: bool = False,
) -> ListItem:
    return ListItem(
        kind=kind,
        algorithm=Algorithm.Sha1,
        label=label.encode(),
        properties=ListItemProperties(
            touch_required=touch_required,
            secret_encryption=secret_encryption,
            pws_data_exist=pws_data_exist,
        ),
    )


CREDENTIALS = [
    credential("gitlab", kind=Kind.Totp, touch_required=True),
    credential("Bank", kind=Kind.Hotp, secret_encryption=True),
    credential("github", kind=Kind.Totp, pws_data_exist=True),
    credential("archive", kind=Kind.NotSet, pws_data_exist=True),
    credential("Login", kind=Kind.HotpReverse, touch_required=True, secret_encryption=True),
]


def test_format_label() -> None:
    assert format_label(b"github") == "github"
    assert format_label(b"") == ""
    assert format_label("äöü".encode()) == "äöü"
    assert format_label(b"github", hexa=True) == "0x676974687562"


def test_format_label_does_not_fail_on_non_utf8_labels() -> None:
    assert format_label(b"\xed\x4c\x2e") == "0xed4c2e"
    assert format_label(b"\xed\x4c\x2e", hexa=True) == "0xed4c2e"


def test_format_credential_keeps_the_established_output() -> None:
    for item in CREDENTIALS:
        assert format_credential(item) == str(item)


def test_format_credential_uses_hex_labels_on_demand() -> None:
    item = credential("github", kind=Kind.Totp, pws_data_exist=True)
    assert format_credential(item, hexa=True) == "0x676974687562\tTotp/Sha1\tPWS data available"
