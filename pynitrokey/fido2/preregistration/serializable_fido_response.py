from typing import Any, NamedTuple, TypeVar


class Response(NamedTuple):
    clientDataJson: str | None
    attestationObject: str | None


T = TypeVar("T", bound="SerializableFidoResponse")


class SerializableFidoResponse:
    def __init__(self) -> None:
        return

    @staticmethod
    def buildFromRaw(raw: Any) -> T:
        slf = SerializableFidoResponse()
        slf.fillRaw(raw)
        return slf

    @staticmethod
    def deserialize(kv: dict[str, str | None]) -> T:
        slf = SerializableFidoResponse()

        slf.id = kv.get("fido_response_id")

        slf.response = Response(
            kv.get("fido_response_client_data"), kv.get("fido_response_attestation_object")
        )

        return slf

    @staticmethod
    def provide_data_field_names(running: list[str]) -> list[str]:
        if running is None:
            running = []

        fields = [
            "fido_response_id",
            "fido_response_client_data",
            "fido_response_attestation_object",
        ]
        for field in fields:
            if field not in running:
                running.append(field)

        return running

    # fields and tuples reverse engineered from raw dict return after calling the appropriate function to create credentials on NitroKey3
    id: str | None
    response: Response

    def fillRaw(self, raw: Any) -> None:
        if "id" in raw:
            rwid = raw["id"]
            if isinstance(rwid, str):
                self.id = str(rwid)

        if "response" in raw:
            resp = raw["response"]
            if isinstance(resp, dict) and "clientDataJson" in resp and "attestationObject" in resp:
                clientDataJson = resp["clientDataJson"]
                attestationObject = resp["attestationObject"]
                self.response = Response(clientDataJson, attestationObject)

        return

    def renderRaw(self) -> dict[str, Any]:
        ret: dict[str, Any] = {}

        ret["id"] = self.id

        retresp: dict[str, Any] = {}
        retresp["clientDataJson"] = self.response.clientDataJson
        retresp["attestationObject"] = self.response.attestationObject

        ret["response"] = retresp

        return ret

    def serialize(self) -> dict[str, str | None]:
        ret: dict[str, str | None] = {}

        ret["fido_response_id"] = self.id

        if hasattr(self, "response") and self.response is not None:
            ret["fido_response_client_data"] = self.response.clientDataJson
            ret["fido_response_attestation_object"] = self.response.attestationObject

        return ret
