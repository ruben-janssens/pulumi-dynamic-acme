from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field, field_serializer

from pulumi_dynamic_acme.models.shared import AcmeIdentifier, HttpUrlString


class AcmeOrderStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class AcmeOrder(BaseModel):
    url: HttpUrlString
    status: AcmeOrderStatus = Field(alias="status")
    expires: datetime = Field("expires")
    identifiers: list[AcmeIdentifier] = Field(alias="identifiers")
    authorizations: list[HttpUrlString] = Field(alias="authorizations")
    finalize: HttpUrlString = Field(alias="finalize")
    certificate: HttpUrlString | None = Field(alias="certificate", default=None)
    not_before: datetime | None = Field(alias="notBefore", default=None)
    not_after: datetime | None = Field(alias="notAfter", default=None)


class AcmeNewOrderBody(BaseModel):
    identifiers: list[AcmeIdentifier] = Field(serialization_alias="identifiers")
    not_before: datetime | None = Field(serialization_alias="notBefore", default=None)
    not_after: datetime | None = Field(serialization_alias="notAfter", default=None)

    @field_serializer("not_before", "not_after")
    def serialize_date(self, date: datetime, _info) -> str:
        date.microsecond = 0
        return date.isoformat(sep="T")
