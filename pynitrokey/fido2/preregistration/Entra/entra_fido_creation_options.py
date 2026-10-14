from typing import Any
from typing import NamedTuple
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import PublicKeyCredentialCreationOptions

class RP(NamedTuple):
    id: str
    name: str

class User(NamedTuple):
    id: bytes
    displayName: str
    name: str

class PubKeyCredParam(NamedTuple):
    type: str
    alg: int

class AuthenticatorSelection(NamedTuple):
    authenticatorAttachment: str
    requireResidentKey: bool
    userVerification: str

class Extensions(NamedTuple):
    hmacCreateSecret: bool
    enforceCredentialProtectionPolicy: bool 
    credentialProtectionPolicy: str

class EntraFidoCreationOptions:
    def __init__(self) -> None:
        return

    @staticmethod
    def buildFromRaw(self, raw: Any) -> Any:
        slf = EntraFidoCreationOptions()     
        slf.fillRaw(raw)
        return slf
    
    @staticmethod
    def deserialize(kv: dict[str, str | None]) -> Any:
        slf = EntraFidoCreationOptions()
        
        slf.challenge = websafe_decode(kv['fido_challenge'])
        
        slf.timeout = kv['entra_fido_timeout']
        slf.attestation = kv['entra_fido_attestation']
        
        slf.rp = RP(kv['entra_fido_rp_id'], kv['entra_fido_rp_name'])
        
        slf.user = User(websafe_decode(kv['entra_fido_user_id']), kv['entra_fido_user_display_name'], kv['entra_fido_user_name'])
        
        slf.pubKeyCredParams = EntraFidoCreationOptions.parseLinearPubKeyCredParams(kv['entra_fido_public_key_credential_parameters'])
        
        slf.authenticatorSelection = AuthenticatorSelection(kv['entra_fido_authenticator_attachement'], kv['entra_fido_require_resident_key'], kv['entra_fido_user_verification'])
        
        slf.extensions = Extensions(kv['entra_fido_hmac_create_secret'], kv['entra_fido_enforce_credential_protection_policy'], kv['entra_fido_credential_protection_policy'])
        
        return slf

    @staticmethod
    def provide_data_field_names(running: list[str]) -> list[str]:
        if running is None:
            running = []

        if "fido_challenge" not in running:
            running.append("fido_challenge")

        if "entra_fido_timeout" not in running:
            running.append("entra_fido_timeout")
        if "entra_fido_attestation" not in running:
            running.append("entra_fido_attestation")

        if "entra_fido_rp_id" not in running:
            running.append("entra_fido_rp_id")
        if "entra_fido_rp_name" not in running:
            running.append("entra_fido_rp_name")

        if "entra_fido_user_id" not in running:
            running.append("entra_fido_user_id")
        if "entra_fido_user_display_name" not in running:
            running.append("entra_fido_user_display_name")
        if "entra_fido_user_name" not in running:
            running.append("entra_fido_user_name")

        #todo: clever way to serialize list of PubKeyCredParam
        if "entra_fido_public_key_credential_parameters" not in running:
            running.append("entra_fido_public_key_credential_parameters")

        if "entra_fido_authenticator_attachement" not in running:
            running.append("entra_fido_authenticator_attachement")
        if "entra_fido_require_resident_key" not in running:
            running.append("entra_fido_require_resident_key")
        if "entra_fido_user_verification" not in running:
            running.append("entra_fido_user_verification")

        if "entra_fido_hmac_create_secret" not in running:
            running.append("entra_fido_hmac_create_secret")
        if "entra_fido_enforce_credential_protection_policy" not in running:
            running.append("entra_fido_enforce_credential_protection_policy")
        if "entra_fido_credential_protection_policy" not in running:
            running.append("entra_fido_credential_protection_policy")

        return running

    # fields and tuples reverse engineered from raw JSON return after calling the appropriate EntraID endpoint
    challenge: bytes
    timeout: int
    attestation: str
    rp: RP
    user: User
    pubKeyCredParams: list[PubKeyCredParam]
    #excludeCredentials: [], #not implemented; datatype unknown
    authenticatorSelection: AuthenticatorSelection
    extensions: Extensions

    def fillRaw(self, raw: Any) -> None:
        if 'challenge' in raw:
            chlng = raw['challenge']
            if isinstance(chlng, bytes):
                self.challenge = bytes(chlng)
        
        if 'timeout' in raw:
            tmout = raw['timeout']
            if isinstance(tmout, int):
                self.timeout = int(tmout)

        
        if 'attestation' in raw:
            attst = raw['attestation']
            if isinstance(attst, str):
                self.attestation = str(attst)

        if 'rp' in raw:
            rip = raw['rp']
            if isinstance(rip, dict) and 'id' in rip and 'name' in rip:
                ripId = rip['id']
                ripName = rip['name']
                self.rp = RP(ripId, ripName)


        if 'user' in raw:
            usr = raw['user']
            if isinstance(usr, dict) and 'id' in usr and 'name' in usr and 'displayName' in usr:
                usrId = usr['id']
                usrDisplayName = usr['displayName']
                usrName = usr['name']
                self.user = User(usrId, usrDisplayName, usrName)

        if 'pubKeyCredParams' in raw:
            params = raw['pubKeyCredParams']
            if isinstance(params, list):
                prmLst: list[PubKeyCredParam] = []
                for prm in params:
                    if isinstance(prm, dict) and 'type' in prm and 'alg' in prm:
                        typ = prm['type']
                        alg = prm['alg']
                        prmLst.append(PubKeyCredParam(typ, alg))
                self.pubKeyCredParams = prmLst
        
        if 'authenticatorSelection' in raw:
            authSel = raw['authenticatorSelection']
            if isinstance(authSel, dict) and 'authenticatorAttachment' in authSel and 'requireResidentKey' in authSel and 'userVerification' in authSel:
                authenticatorAttachment = authSel['authenticatorAttachment']
                requireResidentKey = authSel['requireResidentKey']
                userVerification = authSel['userVerification']
                self.authenticatorSelection = AuthenticatorSelection(authenticatorAttachment, requireResidentKey, userVerification)

        
        if 'extensions' in raw:
            exten = raw['extensions']
            if isinstance(exten, dict) and 'hmacCreateSecret' in exten and 'enforceCredentialProtectionPolicy' in exten and 'credentialProtectionPolicy' in exten:
                hmacCreateSecret = exten['hmacCreateSecret']
                enforceCredentialProtectionPolicy = exten['enforceCredentialProtectionPolicy']
                credentialProtectionPolicy = exten['credentialProtectionPolicy']
                self.extensions = Extensions(hmacCreateSecret, enforceCredentialProtectionPolicy, credentialProtectionPolicy)

        return

    credParamDelimeter = '^'
    def linearPubKeyCredParams(self) -> str | None:
        if not self.pubKeyCredParams:
            return None
        else:
            credPrm: str = ""
            for prm in self.pubKeyCredParams:
                if credPrm:
                    credPrm += EntraFidoCreationOptions.credParamDelimeter
                credPrm += f'{prm.type}{EntraFidoCreationOptions.credParamDelimeter}{prm.alg}'
            return credPrm

    @staticmethod
    def parseLinearPubKeyCredParams(lin: str) -> list[PubKeyCredParam]:
        if not lin:
            return []

        spl = lin.split(EntraFidoCreationOptions.credParamDelimeter)
        ret: list[PubKeyCredParam] = []
        for i in range(0, spl.__len__(), 2):
            ret.append(PubKeyCredParam(spl[i], spl[i+1]))
        return ret

    def renderPublicKeyCredentialCreationOptions(self) -> PublicKeyCredentialCreationOptions:
        slfDict = {}

        slfDict['challenge'] = self.challenge
        slfDict['timeout'] = self.timeout
        slfDict['attestation'] = self.attestation

        slfDict['rp'] = self.rp._asdict()
        slfDict['user'] = self.user._asdict()
        
        crdprms: list[dict[str, Any]] = []
        for prm in self.pubKeyCredParams:
            crdprms.append(prm._asdict())
        slfDict['pubKeyCredParams'] = crdprms
        
        slfDict['authenticatorSelection'] = self.authenticatorSelection._asdict()
        slfDict['extensions'] = self.extensions._asdict()

        return PublicKeyCredentialCreationOptions.from_dict(slfDict)

    def serialize(self) -> dict[str, str | None]:
        ret: dict[str, str | None] = {}

        ret["fido_challenge"] = websafe_encode(self.challenge)

        ret["entra_fido_timeout"] = self.timeout
        ret["entra_fido_attestation"] = self.attestation

        ret["entra_fido_rp_id"] = self.rp.id
        ret["entra_fido_rp_name"] = self.rp.name

        ret["entra_fido_user_id"] = websafe_encode(self.user.id)
        ret["entra_fido_user_display_name"] = self.user.displayName
        ret["entra_fido_user_name"] = self.user.name

        ret["entra_fido_public_key_credential_parameters"] = self.linearPubKeyCredParams()

        ret["entra_fido_authenticator_attachement"] = self.authenticatorSelection.authenticatorAttachment
        ret["entra_fido_require_resident_key"] = self.authenticatorSelection.requireResidentKey
        ret["entra_fido_user_verification"] = self.authenticatorSelection.userVerification

        ret["entra_fido_hmac_create_secret"] = self.extensions.hmacCreateSecret
        ret["entra_fido_enforce_credential_protection_policy"] = self.extensions.enforceCredentialProtectionPolicy
        ret["entra_fido_credential_protection_policy"] = self.extensions.credentialProtectionPolicy

        return ret
