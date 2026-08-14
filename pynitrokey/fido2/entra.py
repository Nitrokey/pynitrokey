import json
import random
import re
import string
import time
from datetime import datetime, timedelta
from typing import Any

import requests
from fido2.client import Fido2Client
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import PublicKeyCredentialCreationOptions

from .preregister import PreRegister


class Entra(PreRegister):
    service_name = "Entra"
    rp_id = "login.microsoft.com"

    def __init__(self) -> None:
        self._reset_token()

    def _reset_token(self) -> None:
        self.token = ""
        self.token_validity = datetime.fromtimestamp(0)

    def _generate_password(self, length: int = 16) -> str:
        characters = string.ascii_letters + string.digits + string.punctuation
        password = "".join(random.choice(characters) for _ in range(length))
        return password

    def _get_endpoint(self, graph_version: str = "v1.0") -> str:
        graph_endpoint = f"https://graph.microsoft.com/{graph_version}"
        return graph_endpoint

    def _set_http_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": self.get_token(),
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate, br",
        }

    def _get_username(self, name: str) -> str:
        domain = self.config["domain"]
        assert name.count("@") < 1 or (name.count("@") == 1 and name.endswith(f"@{domain}")), (
            "Invalid name"
        )
        temp = name.split("@")[0]
        temp = re.sub(r"[^a-zA-Z0-9]", "", temp)
        return f"{temp}@{domain}"

    def _get_access_token_for_microsoft_graph(self) -> str:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_endpoint = (
            "https://login.microsoftonline.com/" + self.config["tenant"] + "/oauth2/v2.0/token"
        )

        body = {
            "grant_type": "client_credentials",
            "client_id": self.config["client"],
            "client_secret": self.config["secret"],
            "scope": "https://graph.microsoft.com/.default",
        }

        token_response = requests.post(token_endpoint, data=body, headers=headers)
        decoded_response = json.loads(token_response.content)
        assert "access_token" in decoded_response, "Authentication failed"
        self.token = decoded_response.get("access_token", "")
        expiry = decoded_response.get("expires_in", 0)
        self.token_validity = datetime.now() + timedelta(seconds=expiry)
        return str(decoded_response.get("access_token", ""))

    def get_token(self) -> str:
        if self.token and datetime.now() < self.token_validity:
            return self.token
        return self._get_access_token_for_microsoft_graph()

    def validate_config(self, config: dict[str, Any]) -> None:
        assert "tenant" in config, "Tenant not found"
        assert "client" in config, "Client ID not found"
        assert "secret" in config, "Client Secret not found"
        assert "domain" in config, "Domain not found"

    def create_user(self, user: str) -> bool:
        endpoint = f"{self._get_endpoint()}/users"
        email = self._get_username(user)
        name = email.split("@")[0]
        body = {
            "accountEnabled": True,
            "displayName": user,
            "mailNickName": name,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": self._generate_password(),
            },
            "userPrincipalName": email,
        }
        resp = requests.post(endpoint, json=body, headers=self._set_http_headers())
        success = resp.status_code == 201
        if success:
            print("Waiting 5 secs for Graph API to update")
            self._reset_token()  # Unable to read the user just after creation
            time.sleep(5)
        return success

    def get_user_id(self, user: str) -> str:
        email = self._get_username(user)
        endpoint = f"{self._get_endpoint()}/users/{email}?$select=id"
        resp = requests.get(endpoint, headers=self._set_http_headers())
        decoded_response = json.loads(resp.content)
        assert "id" in decoded_response, "User not found"
        return str(decoded_response.get("id"))

    def get_creation_options(self, user: str) -> dict[str, Any]:
        endpoint_base = self._get_endpoint("beta")
        endpoint = f"{endpoint_base}/users/{user}/authentication/fido2Methods/creationOptions"
        resp = requests.get(endpoint, headers=self._set_http_headers())
        decoded_response = json.loads(resp.content)
        assert "publicKey" in decoded_response
        pubkey: dict[str, Any] = decoded_response.get("publicKey")
        pubkey["challenge"] = websafe_decode(pubkey["challenge"])
        pubkey["user"]["id"] = websafe_decode(pubkey["user"]["id"])
        if "excludeCredentials" in pubkey:
            for i in range(len(pubkey["excludeCredentials"])):
                pubkey["excludeCredentials"][i]["id"] = websafe_decode(
                    pubkey["excludeCredentials"][i]["id"][:-1]
                )  # That -1 is because https://learn.microsoft.com/en-us/graph/api/fido2authenticationmethod-creationoptions?view=graph-rest-beta&tabs=http#response

        return pubkey

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

    def save_creds(self, att_resp: dict[str, Any], user: str, name: str) -> str:
        endpoint_base = self._get_endpoint("beta")
        endpoint = f"{endpoint_base}/users/{user}/authentication/fido2Methods"
        body = {"displayName": name, "publicKeyCredential": att_resp}
        resp = requests.post(endpoint, json=body, headers=self._set_http_headers())
        assert resp.status_code == 201, "Credential creation failed"
        decoded_response = json.loads(resp.content)
        return str(decoded_response.get("id"))

    def enroll_device(self, user: str, client: Fido2Client) -> str:
        user_id = self.get_user_id(user)
        device_name = self.get_device_name(client)
        pubkey = self.get_creation_options(user_id)
        resp = self.make_creds(pubkey, client)
        cred_id = self.save_creds(resp, user_id, device_name)
        return f"Entra credential for {user} pre-registered on {device_name} with Credential ID {cred_id}."
