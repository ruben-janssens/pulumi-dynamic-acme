from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field, model_validator

from pulumi_dynamic_acme.models.shared import HttpUrlString


class RequestType(str, Enum):
    GET = "get"
    POST = "post"
    HEAD = "head"


class AcmeManagerDnsChallengeRecord(BaseModel):
    record: str
    value: str


class AcmeManagerDnsChallenge(BaseModel):
    order_url: HttpUrlString
    records: list[AcmeManagerDnsChallengeRecord]


class AcmeManagerJwk(BaseModel):
    public_exponent: str = Field(serialization_alias="e")
    public_modulus: str = Field(serialization_alias="n")
    key_type: Literal["RSA"] = Field(serialization_alias="kty")


class AcmeManagerIdentification(BaseModel):
    jwk: AcmeManagerJwk | None = Field(default=None)
    kid: HttpUrlString | None = Field(default=None)

    @model_validator(mode="after")
    def only_one_is_set(self) -> 'AcmeManagerIdentification':
        if (self.jwk is None and self.kid is None) or (self.jwk is not None and self.kid is not None):
            raise ValueError("Only one of `jwk` or `kid` may be provided for identification.")
        return self
