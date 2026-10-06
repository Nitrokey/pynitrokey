from typing import Any

from fido2.client import Fido2Client
from fido2.utils import websafe_encode
from fido2.webauthn import PublicKeyCredentialCreationOptions

from pynitrokey.fido2.preregistration.Entra.entra_enrollment_state import EntraEnrollmentState
from pynitrokey.fido2.preregistration.Entra.entra_enrollment_state_data import (
    EntraEnrollmentStateData,
)
from pynitrokey.fido2.preregistration.Entra.entra_remote_operator import EntraRemoteOperator
from pynitrokey.fido2.preregistration.stateful_provision_credential import (
    StatefulProvisionCredential,
)


class EntraStateEncodedCredential(StatefulProvisionCredential):
    service_name = "Entra"
    rp_id = "login.microsoft.com"

    entra_conf: EntraRemoteOperator
    enrollment_data: EntraEnrollmentStateData

    entra_conf_path: str

    def extract_state(self) -> dict[str, str]:
        return self.enrollment_data.serialize()

    def inject_state(self, raw: dict[str, str]) -> None:
        self.enrollment_data = EntraEnrollmentStateData.deserialize(raw)

    def provide_data_field_names(self, running: list[str]) -> list[str]:
        return EntraEnrollmentStateData.provide_data_field_names(running)

    def move_next(self, client: Fido2Client, config: Any) -> bool:
        match self.enrollment_data.enrollment_state:
            case EntraEnrollmentState.BEGIN:
                self.enrollment_data.enrollment_state = self.begin_enroll_entra(config)
                return True

            case EntraEnrollmentState.ENTRA_SETUP:
                self.enrollment_data.enrollment_state = self.generate_credentials_on_key(client)
                return True

            case EntraEnrollmentState.CREDS_ON_KEY:
                self.enrollment_data.enrollment_state = self.save_credenitals_to_entra(config)
                return True

            case EntraEnrollmentState.COMPLETE:
                return False

            case _:
                raise ValueError(
                    "Invalid state reached! Cannot proceed with registration enrollment"
                )

    def ensure_has_entra_config(self, config: Any) -> bool:
        if config is None:
            return False

        self.entra_conf = EntraRemoteOperator(config)
        self.set_config(config)

        return True

    # todo refact
    def validate_config(self, config: dict[str, Any]) -> None:
        assert "tenant" in config, "Tenant not found"
        assert "client" in config, "Client ID not found"
        assert "secret" in config, "Client Secret not found"
        assert "domain" in config, "Domain not found"

    def ensure_has_entra_nitrokey_hardware(self, client: Fido2Client) -> bool:
        return client is not None

    def begin_enroll_entra(self, config: Any) -> EntraEnrollmentState:
        if self.ensure_has_entra_config(config):
            self.enrollment_data.user_entra_id = self.entra_conf.get_user_id(
                self.enrollment_data.username_or_email,
                self.enrollment_data.create_user_if_not_exist,
            )

            self.enrollment_data.fido_challenge = self.entra_conf.get_creation_options(
                self.enrollment_data.user_entra_id
            )

            return EntraEnrollmentState.ENTRA_SETUP
        else:
            raise ValueError(
                "State [BEGIN] requires access to Entra serivces to continue! Please ensure an entra_config.json is provided, and try again"
            )

    def generate_credentials_on_key(self, client: Fido2Client) -> EntraEnrollmentState:
        if self.ensure_has_entra_nitrokey_hardware(client):
            self.enrollment_data.nitrokey_device_name = self.get_device_name(client)
            self.enrollment_data.fido_response = self.make_creds(
                self.enrollment_data.fido_challenge, client
            )

            return EntraEnrollmentState.CREDS_ON_KEY
        else:
            raise ValueError(
                "State [ENTRA_SETUP] requires access to the NitroKey hardware to be provisioned! Please insert a key and try again"
            )

    def save_credenitals_to_entra(self, config: Any) -> EntraEnrollmentState:
        if self.ensure_has_entra_config(config):
            self.enrollment_data.fido_credential_id = self.entra_conf.save_creds(
                self.enrollment_data.fido_response,
                self.enrollment_data.user_entra_id,
                self.enrollment_data.nitrokey_device_name,
            )

            return EntraEnrollmentState.COMPLETE
        else:
            raise ValueError(
                "State [CREDS_ON_KEY] requires access to Entra serivces to continue! Please ensure an entra_config.json is provided, and try again"
            )

    def __init__(self) -> None:
        return

    def begin_new(self, user: str, create_user: bool) -> None:
        self.enrollment_data = EntraEnrollmentStateData.begin_new(user, create_user)

    def create_user(self, user: str) -> bool:
        return self.entra_conf.create_user(user)

    def make_creds(self, pubkey: dict[str, Any], client: Fido2Client) -> dict[str, Any]:
        result = client.make_credential(PublicKeyCredentialCreationOptions.from_dict(pubkey))
        attestation_obj = result.response.attestation_object
        client_data = result.response.client_data
        cred_id = (
            attestation_obj.auth_data.credential_data.credential_id
            if attestation_obj.auth_data.credential_data is not None
            else b""
        )

        return {
            "id": websafe_encode(cred_id),
            "response": {
                "clientDataJson": websafe_encode(client_data),
                "attestationObject": websafe_encode(attestation_obj),
            },
        }

    def enroll_device(self, user: str, client: Fido2Client) -> str:
        entraEnrollment = self.begin_enroll_entra(user)

        nitroResponse = self.continue_enroll_nitrokey(client, entraEnrollment)

        cred_id = self.save_creds(
            nitroResponse.response, nitroResponse.user_id, nitroResponse.device_name
        )

        return f"Entra credential for {user} pre-registered on {nitroResponse.device_name} with Credential ID {cred_id}."
