from typing import Any, NamedTuple

from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import PublicKeyCredentialCreationOptions


class RP(NamedTuple):
    id: str | None
    name: str | None


class User(NamedTuple):
    id: bytes | None
    displayName: str | None
    name: str | None


class PubKeyCredParam(NamedTuple):
    type: str | None
    alg: int | None


class AuthenticatorSelection(NamedTuple):
    authenticatorAttachment: str | None
    requireResidentKey: bool | None
    userVerification: str | None


class Extensions(NamedTuple):
    hmacCreateSecret: bool | None
    enforceCredentialProtectionPolicy: bool | None
    credentialProtectionPolicy: str | None


class EntraFidoCreationOptions:
    def __init__(self) -> None:
        return

    @staticmethod
    def buildFromRaw(raw: Any) -> Any:
        slf = EntraFidoCreationOptions()
        slf.fillRaw(raw)
        return slf

    @staticmethod
    def deserialize(kv: dict[str, str | None]) -> Any:
        slf = EntraFidoCreationOptions()

        if "fido_challenge" in kv and kv["fido_challenge"]:
            slf.challenge = websafe_decode(kv["fido_challenge"])

        if "entra_fido_timeout" in kv and kv["entra_fido_timeout"]:
            slf.timeout = int(kv["entra_fido_timeout"])
        if "entra_fido_attestation" in kv and kv["entra_fido_attestation"]:
            slf.attestation = kv["entra_fido_attestation"]

        if (
            "entra_fido_rp_id" in kv
            and kv["entra_fido_rp_id"]
            and "entra_fido_rp_name" in kv
            and kv["entra_fido_rp_name"]
        ):
            slf.rp = RP(kv["entra_fido_rp_id"], kv["entra_fido_rp_name"])

        if (
            "entra_fido_user_id" in kv
            and kv["entra_fido_user_id"]
            and "entra_fido_user_display_name" in kv
            and kv["entra_fido_user_display_name"]
            and "entra_fido_user_name" in kv
            and kv["entra_fido_user_name"]
        ):
            slf.user = User(
                websafe_decode(kv["entra_fido_user_id"]),
                kv["entra_fido_user_display_name"],
                kv["entra_fido_user_name"],
            )

        if (
            "entra_fido_public_key_credential_parameters" in kv
            and kv["entra_fido_public_key_credential_parameters"]
        ):
            slf.pubKeyCredParams = EntraFidoCreationOptions.parseLinearPubKeyCredParams(
                kv["entra_fido_public_key_credential_parameters"]
            )

        if (
            "entra_fido_authenticator_attachement" in kv
            and kv["entra_fido_authenticator_attachement"]
            and "entra_fido_require_resident_key" in kv
            and kv["entra_fido_require_resident_key"]
            and "entra_fido_user_verification" in kv
            and kv["entra_fido_user_verification"]
        ):
            slf.authenticatorSelection = AuthenticatorSelection(
                kv["entra_fido_authenticator_attachement"],
                bool(kv["entra_fido_require_resident_key"]),
                kv["entra_fido_user_verification"],
            )

        if (
            "entra_fido_hmac_create_secret" in kv
            and kv["entra_fido_hmac_create_secret"]
            and "entra_fido_enforce_credential_protection_policy" in kv
            and kv["entra_fido_enforce_credential_protection_policy"]
            and "entra_fido_credential_protection_policy" in kv
            and kv["entra_fido_credential_protection_policy"]
        ):
            slf.extensions = Extensions(
                bool(kv["entra_fido_hmac_create_secret"]),
                bool(kv["entra_fido_enforce_credential_protection_policy"]),
                kv["entra_fido_credential_protection_policy"],
            )

        return slf

    @staticmethod
    def provide_data_field_names(running: list[str]) -> list[str]:
        if running is None:
            running = []

        fields = [
            "fido_challenge",
            "entra_fido_timeout",
            "entra_fido_attestation",
            "entra_fido_rp_id",
            "entra_fido_rp_name",
            "entra_fido_user_id",
            "entra_fido_user_display_name",
            "entra_fido_user_name",
            "entra_fido_public_key_credential_parameters",
            "entra_fido_authenticator_attachement",
            "entra_fido_require_resident_key",
            "entra_fido_user_verification",
            "entra_fido_hmac_create_secret",
            "entra_fido_enforce_credential_protection_policy",
            "entra_fido_credential_protection_policy",
        ]
        for field in fields:
            if field not in running:
                running.append(field)

        return running

    # fields and tuples reverse engineered from raw JSON return after calling the appropriate EntraID endpoint
    challenge: bytes | None
    timeout: int | None
    attestation: str | None
    rp: RP
    user: User
    pubKeyCredParams: list[PubKeyCredParam]
    # excludeCredentials: [], #not implemented; datatype unknown
    authenticatorSelection: AuthenticatorSelection
    extensions: Extensions

    def fillRaw(self, raw: Any) -> None:
        if "challenge" in raw:
            chlng = raw["challenge"]
            if isinstance(chlng, bytes):
                self.challenge = bytes(chlng)

        if "timeout" in raw:
            tmout = raw["timeout"]
            if isinstance(tmout, int):
                self.timeout = int(tmout)

        if "attestation" in raw:
            attst = raw["attestation"]
            if isinstance(attst, str):
                self.attestation = str(attst)

        if "rp" in raw:
            rip = raw["rp"]
            if isinstance(rip, dict) and "id" in rip and "name" in rip:
                ripId = rip["id"]
                ripName = rip["name"]
                self.rp = RP(ripId, ripName)

        if "user" in raw:
            usr = raw["user"]
            if isinstance(usr, dict) and "id" in usr and "name" in usr and "displayName" in usr:
                usrId = usr["id"]
                usrDisplayName = usr["displayName"]
                usrName = usr["name"]
                self.user = User(usrId, usrDisplayName, usrName)

        if "pubKeyCredParams" in raw:
            params = raw["pubKeyCredParams"]
            if isinstance(params, list):
                prmLst: list[PubKeyCredParam] = []
                for prm in params:
                    if isinstance(prm, dict) and "type" in prm and "alg" in prm:
                        typ = prm["type"]
                        alg = prm["alg"]
                        prmLst.append(PubKeyCredParam(typ, alg))
                self.pubKeyCredParams = prmLst

        if "authenticatorSelection" in raw:
            authSel = raw["authenticatorSelection"]
            if (
                isinstance(authSel, dict)
                and "authenticatorAttachment" in authSel
                and "requireResidentKey" in authSel
                and "userVerification" in authSel
            ):
                authenticatorAttachment = authSel["authenticatorAttachment"]
                requireResidentKey = authSel["requireResidentKey"]
                userVerification = authSel["userVerification"]
                self.authenticatorSelection = AuthenticatorSelection(
                    authenticatorAttachment, requireResidentKey, userVerification
                )

        if "extensions" in raw:
            exten = raw["extensions"]
            if (
                isinstance(exten, dict)
                and "hmacCreateSecret" in exten
                and "enforceCredentialProtectionPolicy" in exten
                and "credentialProtectionPolicy" in exten
            ):
                hmacCreateSecret = exten["hmacCreateSecret"]
                enforceCredentialProtectionPolicy = exten["enforceCredentialProtectionPolicy"]
                credentialProtectionPolicy = exten["credentialProtectionPolicy"]
                self.extensions = Extensions(
                    hmacCreateSecret, enforceCredentialProtectionPolicy, credentialProtectionPolicy
                )

        return

    credParamDelimeter = "^"

    def linearPubKeyCredParams(self) -> str | None:
        if not self.pubKeyCredParams:
            return None
        else:
            credPrm: str = ""
            for prm in self.pubKeyCredParams:
                if credPrm:
                    credPrm += EntraFidoCreationOptions.credParamDelimeter
                credPrm += f"{prm.type}{EntraFidoCreationOptions.credParamDelimeter}{prm.alg}"
            return credPrm

    @staticmethod
    def parseLinearPubKeyCredParams(lin: str) -> list[PubKeyCredParam]:
        if not lin:
            return []

        spl = lin.split(EntraFidoCreationOptions.credParamDelimeter)
        ret: list[PubKeyCredParam] = []
        for i in range(0, spl.__len__(), 2):
            ret.append(PubKeyCredParam(spl[i], int(spl[i + 1])))
        return ret

    def renderPublicKeyCredentialCreationOptions(self) -> PublicKeyCredentialCreationOptions:
        slfDict: dict[str, Any] = {}

        slfDict["challenge"] = self.challenge
        slfDict["timeout"] = self.timeout
        slfDict["attestation"] = self.attestation

        slfDict["rp"] = self.rp._asdict()
        slfDict["user"] = self.user._asdict()

        crdprms: list[dict[str, Any]] = []
        for prm in self.pubKeyCredParams:
            crdprms.append(prm._asdict())
        slfDict["pubKeyCredParams"] = crdprms

        slfDict["authenticatorSelection"] = self.authenticatorSelection._asdict()
        slfDict["extensions"] = self.extensions._asdict()

        return PublicKeyCredentialCreationOptions.from_dict(slfDict)

    def serialize(self) -> dict[str, str | None]:
        ret: dict[str, str | None] = {}

        if self.challenge is not None:
            ret["fido_challenge"] = websafe_encode(self.challenge)
        else:
            ret["fido_challenge"] = None

        ret["entra_fido_timeout"] = f"{self.timeout}"
        ret["entra_fido_attestation"] = f"{self.attestation}"

        ret["entra_fido_rp_id"] = self.rp.id
        ret["entra_fido_rp_name"] = self.rp.name

        if self.user.id is not None:
            ret["entra_fido_user_id"] = websafe_encode(self.user.id)
        else:
            ret["entra_fido_user_id"] = None
        ret["entra_fido_user_display_name"] = self.user.displayName
        ret["entra_fido_user_name"] = self.user.name

        ret["entra_fido_public_key_credential_parameters"] = self.linearPubKeyCredParams()

        ret["entra_fido_authenticator_attachement"] = (
            self.authenticatorSelection.authenticatorAttachment
        )
        ret["entra_fido_require_resident_key"] = f"{self.authenticatorSelection.requireResidentKey}"
        ret["entra_fido_user_verification"] = self.authenticatorSelection.userVerification

        ret["entra_fido_hmac_create_secret"] = f"{self.extensions.hmacCreateSecret}"
        ret["entra_fido_enforce_credential_protection_policy"] = (
            f"{self.extensions.enforceCredentialProtectionPolicy}"
        )
        ret["entra_fido_credential_protection_policy"] = self.extensions.credentialProtectionPolicy

        return ret
