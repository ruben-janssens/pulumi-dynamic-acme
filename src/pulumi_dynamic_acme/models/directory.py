from pydantic import BaseModel, Field

from pulumi_dynamic_acme.models.shared import HttpUrlString


class AcmeDirectory(BaseModel):
    new_nonce: HttpUrlString = Field(alias="newNonce")
    new_account: HttpUrlString = Field(alias="newAccount")
    new_order: HttpUrlString = Field(alias="newOrder")
    revoke_cert: HttpUrlString = Field(alias="revokeCert")
