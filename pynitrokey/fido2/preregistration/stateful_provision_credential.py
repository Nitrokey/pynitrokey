from abc import abstractmethod
from typing import Any

from fido2.client import Fido2Client

from pynitrokey.fido2.provision_credential import ProvisionCredential


class StatefulProvisionCredential(ProvisionCredential):
    """
    Inherit from this class for other providers
    """

    service_name: str
    rp_id: str

    def __init__(self) -> None:
        self.config: dict[str, Any] = {}

    def set_config(self, config: dict[str, Any]) -> None:
        self.validate_config(config)
        self.config = config

    @abstractmethod
    def create_user(self, user: str) -> bool:
        """Return if user creation was successful"""
        pass

    @abstractmethod
    def enroll_device(self, user: str, client: Fido2Client) -> str:  # Return a status string
        """Enroll the device for the user"""
        pass

    @abstractmethod
    def validate_config(self, config: dict[str, Any]) -> None:  # Raise error if validation fails
        """Validate config"""
        pass

    @abstractmethod
    def move_next(self, client: Fido2Client | None, config: Any | None) -> bool:
        """try to move to the next state for this credential. returns True on success"""
        pass

    @abstractmethod
    def get_current_enrollment_state(self) -> str:
        """provide the current state flag for debug and logging purposes"""
        pass

    @abstractmethod
    def begin_new(self, user: str, create_user: bool) -> None:
        """initialize this state with provided starting data"""
        pass

    @abstractmethod
    def extract_state(self) -> dict[str, str]:
        """extract serialized state from this provisioner"""
        pass

    @abstractmethod
    def inject_state(self, raw: dict[str, str]) -> None:
        """load external, serialized state into this provisioner"""
        pass

    @abstractmethod
    def provide_data_field_names(self, running: list[str]) -> list[str]:
        """load external, serialized state into this provisioner"""
        pass
