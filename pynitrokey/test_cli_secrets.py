# Copyright Nitrokey GmbH
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""
Tests for the sorting, filtering and formatting of the credentials in the secrets list command.
These do not require a device.
"""

from typing import List, Optional, Sequence

import pytest
from nitrokey.nk3.secrets_app import Algorithm, Kind, ListItem, ListItemProperties

from pynitrokey.cli.nk3.secrets import (
    filter_credentials,
    format_credential,
    format_label,
    sort_credentials,
)


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


def labels(credentials: Sequence[ListItem]) -> List[str]:
    return [item.label.decode() for item in credentials]


def test_sort_by_label_is_case_insensitive() -> None:
    assert labels(sort_credentials(CREDENTIALS)) == ["archive", "Bank", "github", "gitlab", "Login"]


def test_sort_reverse() -> None:
    assert labels(sort_credentials(CREDENTIALS, reverse=True)) == [
        "Login",
        "gitlab",
        "github",
        "Bank",
        "archive",
    ]


def test_sort_by_kind_falls_back_to_label() -> None:
    assert labels(sort_credentials(CREDENTIALS, key="kind")) == [
        "Bank",
        "Login",
        "archive",
        "github",
        "gitlab",
    ]


def test_sort_rejects_unknown_key() -> None:
    with pytest.raises(ValueError):
        sort_credentials(CREDENTIALS, key="algorithm")


def test_sort_handles_non_utf8_labels() -> None:
    credentials = [ListItem(Kind.Totp, Algorithm.Sha1, b"\xff\xfe", CREDENTIALS[0].properties)]
    assert sort_credentials(credentials + CREDENTIALS)[0].label == b"archive"


def test_filter_without_criteria_keeps_all() -> None:
    assert filter_credentials(CREDENTIALS) == CREDENTIALS


def test_filter_by_pattern_is_case_insensitive_substring() -> None:
    assert labels(filter_credentials(CREDENTIALS, pattern="GIT")) == ["gitlab", "github"]
    assert labels(filter_credentials(CREDENTIALS, pattern="hub")) == ["github"]
    assert filter_credentials(CREDENTIALS, pattern="missing") == []


def test_filter_by_kind() -> None:
    assert labels(filter_credentials(CREDENTIALS, kinds=["totp"])) == ["gitlab", "github"]
    assert labels(filter_credentials(CREDENTIALS, kinds=["PWS"])) == ["archive"]
    assert labels(filter_credentials(CREDENTIALS, kinds=["HOTP", "HOTP_REVERSE"])) == [
        "Bank",
        "Login",
    ]


@pytest.mark.parametrize(
    ["touch_button", "pin_protected", "pws", "expected"],
    [
        (True, None, None, ["gitlab", "Login"]),
        (False, None, None, ["Bank", "github", "archive"]),
        (None, True, None, ["Bank", "Login"]),
        (None, None, True, ["github", "archive"]),
        (None, None, False, ["gitlab", "Bank", "Login"]),
        (True, True, None, ["Login"]),
        (True, None, True, []),
    ],
)
def test_filter_by_properties(
    touch_button: Optional[bool],
    pin_protected: Optional[bool],
    pws: Optional[bool],
    expected: List[str],
) -> None:
    filtered = filter_credentials(
        CREDENTIALS, touch_button=touch_button, pin_protected=pin_protected, pws=pws
    )
    assert labels(filtered) == expected


def test_filter_combines_criteria_with_and() -> None:
    filtered = filter_credentials(CREDENTIALS, pattern="git", kinds=["TOTP"], touch_button=True)
    assert labels(filtered) == ["gitlab"]


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
