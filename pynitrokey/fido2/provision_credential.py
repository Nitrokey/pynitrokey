from abc import ABC, abstractmethod
from typing import Any

from fido2.client import Fido2Client
from nitrokey.nk3 import NK3
from nitrokey.nkpk import NKPK


class ProvisionCredential(ABC):
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

    def get_device_name(self, client: Fido2Client) -> str:
        device = client._backend.ctap2.device  # type: ignore
        try:
            name = f"NK3 {str(NK3(device).uuid())[:5]}"
        except Exception:
            try:
                name = f"NKPK {str(NKPK(device).uuid())[:5]}"
            except Exception:
                name = "Nitrokey"
        return name

    @classmethod
    def get_rp_id(cls) -> str:
        return cls.rp_id

    @classmethod
    def get_service_name(cls) -> str:
        return cls.service_name

    def provision(self, create: bool, user: str, client: Fido2Client) -> str:
        if create:
            if self.create_user(user):
                print(f"User {user} created on {self.get_service_name()}")
            else:
                print(f"User {user} not created on {self.get_service_name()}")
        return self.enroll_device(user, client)
