from dataclasses import dataclass
from os import environ
from typing import TYPE_CHECKING, Iterator

import pytest

from nethsm import DecryptMode, KeyMechanism, KeyType, LogLevel, NetHSM, Role, UnattendedBootStatus

if TYPE_CHECKING:
    from utilities import Container


@dataclass
class UserData:
    user_id: str
    real_name: str
    role: Role
    passphrase: str


ADMIN_USER = UserData(
    user_id="admin", real_name="admin", role=Role.ADMINISTRATOR, passphrase="adminadmin"
)


@pytest.fixture(scope="module")
def container() -> Iterator["Container"]:
    from utilities import KeyfenderManager

    container = KeyfenderManager.get().spawn()
    try:
        container.start()
        container.wait()
        yield container
    finally:
        container.kill()


@pytest.fixture(scope="module")
def nethsm(container: "Container") -> Iterator[NetHSM]:
    """Start Docker container with Nethsm image and connect to Nethsm

    This Pytest Fixture will run before the tests to provide the tests with
    a nethsm instance via Docker container, also the first provision of the
    NetHSM will be done in here"""

    from utilities import connect, provision

    with connect(ADMIN_USER) as nethsm:
        provision(nethsm)
        yield nethsm
