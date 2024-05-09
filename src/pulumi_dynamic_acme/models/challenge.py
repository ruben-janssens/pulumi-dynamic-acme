from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field

from pulumi_dynamic_acme.models.shared import HttpUrlString


class AcmeChallengeStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class AcmeChallengeType(str, Enum):
    DNS_01 = "dns-01"
    HTTP_01 = "http-01"
    TLS_SNI_01 = "tls-sni-01"
    TLS_ALPN_01 = "tls-alpn-01"


class AcmeChallenge(BaseModel):
    url: HttpUrlString = Field(alias="url")
    type: AcmeChallengeType = Field(alias="type")
    status: AcmeChallengeStatus = Field(alias="status")
    token: str = Field(alias="token")
    validated: datetime | None = Field(alias="validated", default=None)
