import codecs
import pickle
from typing import Any

from pynitrokey.fido2.preregistration.Entra.entra_enrollment_state import EntraEnrollmentState

class EntraEnrollmentStateData:
    service_name = "Entra"
    enrollment_state: EntraEnrollmentState

    #stateful data needed to BEGIN enrollment
    username_or_email: str #check username and/or email?
    create_user_if_not_exist: bool

    def __init__(self):
        self.enrollment_state = EntraEnrollmentState.BEGIN

    def begin_new(user: str, create_user: bool) -> Any:
        slf = EntraEnrollmentStateData()

        slf.username_or_email = user
        slf.create_user_if_not_exist = create_user
        slf.enrollment_state = EntraEnrollmentState.BEGIN

        return slf

    def deserialize(kv: dict[str, str]) -> Any:
        slf = EntraEnrollmentStateData()

        if kv["service_name"] != "Entra":
            AssertionError(f"State provided is for service {kv["service_name"]}, and cannot be deserialized for service Entra")

        slf.enrollment_state = EntraEnrollmentState[kv["enrollment_state"]]
        slf.username_or_email = kv["username_or_email"]
        slf.create_user_if_not_exist = kv["create_user_if_not_exist"]

        slf.user_entra_id = kv["user_entra_id"]
        if kv["fido_challenge_encoded"] is not None and kv["fido_challenge_encoded"] != "":
            slf.fido_challenge = pickle.loads(codecs.decode(kv["fido_challenge_encoded"].encode(), "base64"))
        else:
            slf.fido_challenge = None

        slf.nitrokey_device_name = kv["nitrokey_device_name"]

        if kv["fido_response_encoded"] is not None and kv["fido_response_encoded"] != "":
            slf.fido_response = pickle.loads(codecs.decode(kv["fido_response_encoded"].encode(), "base64"))
        else:
            slf.fido_response = None

        slf.fido_credential_id = kv["fido_credential_id"]

        return slf

    
    def provide_data_field_names(running: list[str]) -> list[str]:
        if running is None:
            running = []

        if "service_name" not in running:
            running.append("service_name")
        if "enrollment_state" not in running:
            running.append("enrollment_state")
        if "username_or_email" not in running:
            running.append("username_or_email")
        if "create_user_if_not_exist" not in running:
            running.append("create_user_if_not_exist")

        if "nitrokey_device_name" not in running:
            running.append("nitrokey_device_name")

        if "user_entra_id" not in running:
            running.append("user_entra_id")
        if "fido_challenge_encoded" not in running:
            running.append("fido_challenge_encoded")

        if "fido_response_encoded" not in running:
            running.append("fido_response_encoded")

        if "fido_credential_id" not in running:
            running.append("fido_credential_id")

        return running

    #stateful data populated by running BEGIN; needed to step past ENTRA_SETUP
    user_entra_id: str
    fido_challenge: Any ###pickle on save

    #stateful data populated by running ENTRA_SETUP; needed to step past CREDS_ON_KEY
    nitrokey_device_name: str
    fido_response: Any ###pickle on save

    #stateful data populated by running CREDS_ON_KEY; once fullfilled, enrollment is COMPLETE
    fido_credential_id: str

    def serialize(self) -> dict[str, str]:
        ret = {}

        ret["service_name"] = self.service_name

        ret["enrollment_state"] = self.enrollment_state.name
        ret["username_or_email"] = getattr(self, 'username_or_email', None)
        ret["create_user_if_not_exist"] = getattr(self, 'create_user_if_not_exist', None)
        ret["nitrokey_device_name"] = getattr(self, 'nitrokey_device_name', None)

        ret["user_entra_id"] = getattr(self, 'user_entra_id', None)
        pk = getattr(self, 'fido_challenge', None)
        if pk is not None:
            ret["fido_challenge_encoded"] = codecs.encode(pickle.dumps(pk), "base64").decode()
        else:
            ret["fido_challenge_encoded"] = None

        respnc = getattr(self, 'fido_response', None)
        if respnc is not None:
            ret["fido_response_encoded"] = codecs.encode(pickle.dumps(respnc), "base64").decode()
        else:
            ret["fido_response_encoded"] = None

        ret["fido_credential_id"] = getattr(self, 'fido_credential_id', None)

        return ret

