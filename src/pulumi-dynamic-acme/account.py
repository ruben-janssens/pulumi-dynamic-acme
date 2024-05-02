from pulumi.dynamic.dynamic import CreateResult, DiffResult, ReadResult, UpdateResult
from pydantic import BaseModel, ConfigDict, ExtraValues
from pydantic import EmailStr

from pulumi import Resource, Input, ResourceOptions, output
from pulumi.dynamic import *


class LetsEncryptAccountArgs(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore")

    account_key_pem: Input[str]
    contact: EmailStr


class LetsEncryptAccountProvider(ResourceProvider):
    def create(self, props: output.Any) -> CreateResult:
        return CreateResult(
            id_="",
            outs={}
        )

    def read(self, id_: str, props: output.Any) -> ReadResult:
        return ReadResult(id_="", outs={})

    def update(self, _id: str, _olds: output.Any, _news: output.Any) -> UpdateResult:
        return UpdateResult(outs={})

    def delete(self, _id: str, _props: output.Any) -> None:
        pass
    
    def diff(self, _id: str, _olds: output.Any, _news: output.Any) -> DiffResult:
        return DiffResult(
            changes=False,
            replaces=[],
            stables=None,
            delete_before_replace=True
        )
