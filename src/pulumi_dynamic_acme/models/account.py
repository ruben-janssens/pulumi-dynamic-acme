from enum import Enum
from pydantic import BaseModel, Field, field_serializer
from pydantic import EmailStr

from pulumi_dynamic_acme.models.shared import HttpUrlString


class AcmeAccountStatus(str, Enum):
    VALID = "valid"
    DEACTIVATED = "deactivated"
    REVOKED = "revoked"


class AcmeAccount(BaseModel):
    url: HttpUrlString
    status: AcmeAccountStatus = Field(alias="status", )
    contact: list[str] = Field(alias="contact")
    # Not implemented everywhere yet, for ex.: https://github.com/letsencrypt/boulder/issues/3335
    # that's why it it is nullable. Following RFC 8555 this is mandatory
    orders: HttpUrlString | None = Field(alias="orders", default=None)


class AcmeNewAccountBody(BaseModel):
    terms_of_service_agreed: bool = Field(serialization_alias="termsOfServiceAgreed", default=True)
    contact: list[EmailStr] = Field(serialization_alias="contact", default=[])
    only_return_existing: bool = Field(serialization_alias="onlyReturnExisting", default=False)

    @field_serializer("contact")
    def serialize_contact(self, contact: list[EmailStr], _info) -> list[str]:
        return [f"mailto:{mail}" for mail in contact]
