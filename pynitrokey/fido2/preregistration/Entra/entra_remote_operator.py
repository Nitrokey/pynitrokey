import json
import re
import secrets
import string
import time
from datetime import datetime, timedelta
from typing import Any

import requests
from fido2.utils import websafe_decode


class EntraRemoteOperator:
    tenant: str
    client: str
    secret: str
    domain: str

    token: Any
    token_validity: datetime

    user_id: str

    def __init__(self, raw: Any) -> None:
        EntraRemoteOperator.validate_config(raw)

        self.tenant = raw["tenant"]
        self.client = raw["client"]
        self.secret = raw["secret"]
        self.domain = raw["domain"]

        self._reset_token()

    def validate_config(config: dict[str, Any]) -> None:
        assert "tenant" in config, "Tenant not found"
        assert "client" in config, "Client ID not found"
        assert "secret" in config, "Client Secret not found"
        assert "domain" in config, "Domain not found"

    def _reset_token(self) -> None:
        self.token = ""
        self.token_validity = datetime.fromtimestamp(0)

    def get_endpoint(self, graph_version: str = "v1.0") -> str:
        graph_endpoint = f"https://graph.microsoft.com/{graph_version}"
        return graph_endpoint

    def _set_http_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": self.get_token(),
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate, br",
        }

    def _generate_password(self, length: int = 16) -> str:
        characters = string.ascii_letters + string.digits + string.punctuation
        password = "".join(secrets.choice(characters) for _ in range(length))
        return password

    def _get_endpoint(self, graph_version: str = "v1.0") -> str:
        graph_endpoint = f"https://graph.microsoft.com/{graph_version}"
        return graph_endpoint

    def get_token(self) -> str:
        if self.token and datetime.now() < self.token_validity:
            return self.token
        return self._get_access_token_for_microsoft_graph()

    def _get_access_token_for_microsoft_graph(self) -> str:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_endpoint = "https://login.microsoftonline.com/" + self.tenant + "/oauth2/v2.0/token"

        body = {
            "grant_type": "client_credentials",
            "client_id": self.client,
            "client_secret": self.secret,
            "scope": "https://graph.microsoft.com/.default",
        }

        token_response = requests.post(token_endpoint, data=body, headers=headers)
        decoded_response = json.loads(token_response.content)
        assert "access_token" in decoded_response, "Authentication failed"
        self.token = decoded_response.get("access_token", "")
        expiry = decoded_response.get("expires_in", 0)
        self.token_validity = datetime.now() + timedelta(seconds=expiry)
        return str(decoded_response.get("access_token", ""))

    def get_user_id(self, user: str, create_if_missing: bool) -> str:
        if getattr(self, "user_id", None) is not None:
            return self.user_id

        email = self._get_username(user)
        endpoint = f"{self._get_endpoint()}/users/{email}?$select=id"
        resp = requests.get(endpoint, headers=self._set_http_headers())
        decoded_response = json.loads(resp.content)

        usrid = decoded_response.get("id")

        if (usrid is None) and create_if_missing:
            print(f"user {user} not found... creating new")
            usrid = self.create_user(user)
            check_get_user = self.try_get_user_by_id(usrid)

            backoff_wait = 1
            backoff_count = 10
            while (backoff_count > 0) and (check_get_user is None):
                print(
                    f"User {user} created, but not yet accessible... waiting {backoff_wait} seconds before trying again"
                )
                time.sleep(backoff_wait)
                check_get_user = self.try_get_user_by_id(usrid)
                backoff_wait *= 2
                backoff_count -= 1

            if (backoff_count <= 0) and (check_get_user is None):
                print(f"user creation for user {user} failed! please try again later")
                raise AssertionError(
                    f"user creation for user {user} failed! please try again later"
                )

        self.user_id = str(usrid)
        return self.user_id

    def try_get_user_by_id(self, user_id: str) -> Any:
        endpoint = f"{self._get_endpoint()}/users/{user_id}"
        resp = requests.get(endpoint, headers=self._set_http_headers())
        decoded_response = json.loads(resp.content)

        if resp.status_code == 200:
            return decoded_response
        else:
            return None

    def _get_username(self, name: str) -> str:
        assert name.count("@") < 1 or (name.count("@") == 1 and name.endswith(f"@{self.domain}")), (
            "Invalid name"
        )
        temp = name.split("@")[0]
        temp = re.sub(r"[^a-zA-Z0-9]", "", temp)
        return f"{temp}@{self.domain}"

    def create_user(self, user: str) -> str:
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
        decoded_response = json.loads(resp.content)

        success = resp.status_code == 201
        if success:
            r = str(decoded_response.get("id"))
            return r
        else:
            print(decoded_response)
            raise AssertionError()

    def get_creation_options(self, user: str) -> dict[str, Any]:
        endpoint_base = self._get_endpoint("beta")
        endpoint = f"{endpoint_base}/users/{user}/authentication/fido2Methods/creationOptions"
        resp = requests.get(endpoint, headers=self._set_http_headers())
        decoded_response = json.loads(resp.content)
        if "publicKey" not in decoded_response:
            print(decoded_response)
            raise AssertionError()

        pubkey: dict[str, Any] = decoded_response.get("publicKey")
        pubkey["challenge"] = websafe_decode(pubkey["challenge"])
        pubkey["user"]["id"] = websafe_decode(pubkey["user"]["id"])
        if "excludeCredentials" in pubkey:
            for i in range(len(pubkey["excludeCredentials"])):
                pubkey["excludeCredentials"][i]["id"] = websafe_decode(
                    pubkey["excludeCredentials"][i]["id"][:-1]
                )  # That -1 is because https://learn.microsoft.com/en-us/graph/api/fido2authenticationmethod-creationoptions?view=graph-rest-beta&tabs=http#response

        return pubkey

    def save_creds(self, att_resp: dict[str, Any], user: str, name: str) -> str:
        endpoint_base = self._get_endpoint("beta")
        endpoint = f"{endpoint_base}/users/{user}/authentication/fido2Methods"
        body = {"displayName": name, "publicKeyCredential": att_resp}
        resp = requests.post(endpoint, json=body, headers=self._set_http_headers())
        assert resp.status_code == 201, "Credential creation failed"
        decoded_response = json.loads(resp.content)
        return str(decoded_response.get("id"))
