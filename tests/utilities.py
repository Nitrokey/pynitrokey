import contextlib
from abc import ABC, abstractmethod
from os import environ
from time import sleep
from typing import Iterator, Optional

import docker  # type: ignore
import docker.errors  # type: ignore
import docker.models.images  # type: ignore
import nethsm as nethsm_module
import podman
import podman.domain.containers
import podman.domain.images
import podman.errors
import urllib3
from conftest import ADMIN_USER, UserData
from nethsm import Authentication, NetHSM

IMAGE = environ.get("NETHSM_IMAGE", "nitrokey/nethsm:testing")
HOST = environ.get("NETHSM_HOST", "127.0.0.1:8443")


class Container(ABC):
    def restart(self) -> None:
        self.kill()
        self.start()
        self.wait()

    def wait(self) -> None:
        http = urllib3.PoolManager(cert_reqs="CERT_NONE")
        print("Waiting for container to be ready")
        while True:
            try:
                response = http.request("GET", f"https://{HOST}/api/v1/health/alive")
                print(f"Response: {response.status}")
                if response.status == 200:
                    break
            except Exception as e:
                print(e)
                pass
            sleep(0.5)

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def kill(self) -> None: ...


class DockerContainer(Container):
    def __init__(
        self, client: docker.client.DockerClient, image: docker.models.images.Image
    ) -> None:
        self.client = client
        self.image = image
        self.container = None

    def start(self) -> None:
        self.container = self.client.containers.run(
            self.image, "", ports={"8443": 8443}, remove=True, detach=True
        )

    def kill(self) -> None:
        if self.container:
            try:
                self.container.kill()
                self.container.wait()
            except docker.errors.APIError:
                pass


class PodmanContainer(Container):
    def __init__(
        self, client: podman.client.PodmanClient, image: podman.domain.images.Image
    ) -> None:
        self.client = client
        self.image = image
        self.container: Optional[podman.domain.containers.Container] = None

    def start(self) -> None:
        container = self.client.containers.run(
            self.image, "", ports={"8443": 8443}, remove=True, detach=True
        )
        assert isinstance(container, podman.domain.containers.Container)
        self.container = container

    def kill(self) -> None:
        if self.container:
            try:
                self.container.kill()
                self.container.wait()
                # without this sleep, we occasionally get a "port in use" error when restarting
                # the container
                sleep(0.1)
            except podman.errors.APIError:
                pass


class KeyfenderManager(ABC):
    @abstractmethod
    def spawn(self) -> Container: ...

    @staticmethod
    def get() -> "KeyfenderManager":
        test_mode = environ.get("TEST_MODE", "docker")
        if test_mode == "docker":
            return KeyfenderDockerManager()
        elif test_mode == "podman":
            return KeyfenderPodmanManager()
        else:
            raise Exception(f"Invalid Test Mode {test_mode}")


class KeyfenderDockerManager(KeyfenderManager):
    def __init__(self) -> None:
        client = docker.from_env()

        while True:
            containers = client.containers.list(filters={"ancestor": IMAGE}, ignore_removed=True)
            print(containers)
            if len(containers) == 0:
                break

            for container in containers:
                try:
                    container.remove(force=True)
                except docker.errors.APIError as e:
                    print(e)
                    pass
            sleep(1)

        repository, tag = IMAGE.split(":")
        image = client.images.pull(repository, tag=tag)

        self.client = client
        self.image = image

    def spawn(self) -> Container:
        return DockerContainer(self.client, self.image)


class KeyfenderPodmanManager(KeyfenderManager):
    def __init__(self) -> None:
        client = podman.from_env()

        while True:
            containers = client.containers.list(filters={"ancestor": IMAGE}, ignore_removed=True)
            print(containers)
            if len(containers) == 0:
                break

            for container in containers:
                try:
                    container.remove(force=True)
                except docker.errors.APIError as e:
                    print(e)
                    pass
            sleep(1)

        repository, tag = IMAGE.split(":")
        image = client.images.pull(repository, tag=tag)
        assert isinstance(image, podman.domain.images.Image)

        self.client = client
        self.image = image

    def spawn(self) -> Container:
        return PodmanContainer(self.client, self.image)


@contextlib.contextmanager
def connect(user: UserData) -> Iterator[NetHSM]:
    auth = Authentication(user.user_id, user.passphrase)
    with nethsm_module.connect(HOST, auth, False) as nethsm_out:
        yield nethsm_out


def provision(nethsm: NetHSM) -> None:
    """Initial provisioning of a NetHSM.

    If unlock or admin passphrases are not set, they have to be entered
    interactively.  If the system time is not set, the current system time is
    used."""
    nethsm.provision("unlockunlock", ADMIN_USER.passphrase)


def add_user(nethsm: NetHSM, user: UserData) -> None:
    """Create a new user on the NetHSM.

    If the real name, role or passphrase are not specified, they have to be
    specified interactively.  If the user ID is not set, it is generated by the
    NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    try:
        nethsm.get_user(user_id=user.user_id)
    except nethsm_module.NetHSMError:
        nethsm.add_user(user.real_name, user.role, user.passphrase, user.user_id)
