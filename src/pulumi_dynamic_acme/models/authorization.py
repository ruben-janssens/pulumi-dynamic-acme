from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field, field_validator

from pulumi_dynamic_acme.models.shared import AcmeIdentifier
from pulumi_dynamic_acme.models.challenge import AcmeChallenge, AcmeChallengeType


class AcmeAuthorizationStatus(str, Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    REVOKED = "revoked"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"


class AcmeAuthorization(BaseModel):
    status: AcmeAuthorizationStatus = Field(alias="status")
    expires: datetime | None = Field(alias="expires", default=None)
    identifier: AcmeIdentifier = Field(alias="identifier")
    challenges: dict[AcmeChallengeType, AcmeChallenge] = Field(alias="challenges")
    wildcard: bool = Field(alias="wildcard", default=False)

    @field_validator("challenges", mode="before")
    @classmethod
    def challenges_converter(cls, v: list[dict[str, str]]) -> dict[AcmeChallengeType, AcmeChallenge]:
        """
        Incomming challenges object is as follows:
        [
            {
                "url": "https://example.com/acme/chall/prV_B7yEyA4",
                "type": "http-01",
                "status": "valid",
                "token": "DGyRejmCefe7v4NfDGDKfA",
                "validated": "2014-12-01T12:05:58.16Z"
            },
            ...
        ]
        Convert this to a dict with object to easly find our desired challenge
        """
        challenges = dict()
        for challenge in v:
            challenges[AcmeChallengeType(challenge["type"])] = AcmeChallenge(**challenge)
        return challenges
