from typing import Any

from pynitrokey.fido2.preregistration.Entra.entra_enrollment_state import EntraEnrollmentState
from pynitrokey.fido2.preregistration.Entra.entra_fido_creation_options import (
    EntraFidoCreationOptions,
)
from pynitrokey.fido2.preregistration.serializable_fido_response import SerializableFidoResponse


class EntraEnrollmentStateData:
    service_name = "Entra"
    enrollment_state: EntraEnrollmentState

    # stateful data needed to BEGIN enrollment
    username_or_email: str | None  # check username and/or email?
    create_user_if_not_exist: bool

    def __init__(self) -> None:
        self.enrollment_state = EntraEnrollmentState.BEGIN

    @staticmethod
    def begin_new(user: str, create_user: bool) -> Any:
        slf = EntraEnrollmentStateData()

        slf.username_or_email = user
        slf.create_user_if_not_exist = create_user
        slf.enrollment_state = EntraEnrollmentState.BEGIN

        return slf

    @staticmethod
    def deserialize(kv: dict[str, str | None]) -> Any:
        slf = EntraEnrollmentStateData()

        if "service_name" in kv and kv["service_name"] != "Entra":
            raise AssertionError(
                f"State provided is for service {kv['service_name']}, and cannot be deserialized for service Entra"
            )

        if "enrollment_state" not in kv or kv["enrollment_state"] is None:
            raise AssertionError()
        slf.enrollment_state = EntraEnrollmentState[str(kv.get("enrollment_state"))]
        slf.username_or_email = kv.get("username_or_email")
        slf.create_user_if_not_exist = bool(kv.get("create_user_if_not_exist"))

        slf.fido_challenge = EntraFidoCreationOptions.deserialize(kv)

        slf.nitrokey_device_name = kv.get("nitrokey_device_name")

        slf.user_entra_id = kv.get("user_entra_id")
        slf.fido_response = SerializableFidoResponse.deserialize(kv)

        slf.fido_credential_id = kv.get("fido_credential_id")

        return slf

    @staticmethod
    def provide_data_field_names(running: list[str]) -> list[str]:
        if running is None:
            running = []

        fields = [
            "service_name",
            "enrollment_state",
            "username_or_email",
            "create_user_if_not_exist",
            "nitrokey_device_name",
            "user_entra_id",
            "fido_credential_id",
        ]
        for field in fields:
            if field not in running:
                running.append(field)

        EntraFidoCreationOptions.provide_data_field_names(running)

        SerializableFidoResponse.provide_data_field_names(running)

        return running

    # stateful data populated by running BEGIN; needed to step past ENTRA_SETUP
    user_entra_id: str | None
    fido_challenge: EntraFidoCreationOptions | None

    def get_fido_challenge(self) -> Any:
        return self.fido_challenge

    def set_fido_challenge(self, challenge: Any) -> None:
        if self.fido_challenge is None:
            self.fido_challenge = EntraFidoCreationOptions()
        self.fido_challenge.fillRaw(challenge)
        return

    # stateful data populated by running ENTRA_SETUP; needed to step past CREDS_ON_KEY
    nitrokey_device_name: str | None
    fido_response: SerializableFidoResponse | None  ###pickle on save

    # stateful data populated by running CREDS_ON_KEY; once fullfilled, enrollment is COMPLETE
    fido_credential_id: str | None

    def serialize(self) -> dict[str, str | None]:
        ret: dict[str, str | None] = {}

        ret["service_name"] = self.service_name

        ret["enrollment_state"] = self.enrollment_state.name
        ret["username_or_email"] = getattr(self, "username_or_email", None)
        ret["create_user_if_not_exist"] = getattr(self, "create_user_if_not_exist", None)
        ret["nitrokey_device_name"] = getattr(self, "nitrokey_device_name", None)

        ret["user_entra_id"] = getattr(self, "user_entra_id", None)

        chlg = getattr(self, "fido_challenge", None)
        if chlg is not None and isinstance(chlg, EntraFidoCreationOptions):
            kv = chlg.serialize()
            for key, value in kv.items():
                ret[key] = value

        respnc = getattr(self, "fido_response", None)
        if respnc is not None and isinstance(respnc, SerializableFidoResponse):
            kv = respnc.serialize()
            for key, value in kv.items():
                ret[key] = value

        ret["fido_credential_id"] = getattr(self, "fido_credential_id", None)

        return ret
