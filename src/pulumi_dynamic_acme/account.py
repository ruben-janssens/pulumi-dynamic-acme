from pulumi.dynamic.dynamic import CreateResult, DiffResult, ReadResult, ResourceProvider, UpdateResult
from pulumi.output import Inputs
from pydantic import BaseModel, ConfigDict, ExtraValues
from pydantic import EmailStr

from pulumi import Input, Output, ResourceOptions
from pulumi.dynamic import *

from pulumi_dynamic_acme.utilis.letsencrypt import LetsEncryptManager


class LetsEncryptAccountArgs(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore")

    account_key_pem: Input[str]
    contact: EmailStr


class LetsEncryptAccountProvider(ResourceProvider):
    def create(self, args: dict) -> CreateResult:
        manager = LetsEncryptManager(
            args["account_key_pem"]
        )

        account_uri = manager.account(contact=args["contact"])

        return CreateResult(
            id_=account_uri,
            outs={
                **args
            }
        )

    def read(self, id_: str, args: dict) -> ReadResult:
        manager = LetsEncryptManager(
            args["account_key_pem"]
        )

        account_uri = manager.account(contact=args["contact"])
        return ReadResult(
            id_=account_uri,
            outs={
                **args
            }
        )

    def update(self, _id: str, _olds: dict, _news: dict) -> UpdateResult:
        manager = LetsEncryptManager(
            _olds["account_key_pem"]
        )

        manager.update_account(
            contact=_news["contact"],
            account_uri=_id
        )

        return UpdateResult(
            outs={
                **_news
            }
        )

    def diff(self, _id: str, _olds: dict, _news: dict) -> DiffResult:
        changes = False
        if _olds["contact"] != _news["contact"]:
            changes = True

        return DiffResult(
            changes=changes,
            replaces=["account_key_pem"] if _olds["account_key_pem"] != _news["account_key_pem"] else [],
            stables=None,
            delete_before_replace=True
        )

class LetsEncryptAccount(Resource):
    account_key_pem: Output[str]
    contact: Output[str]

    def __init__(self, name: str, args: LetsEncryptAccountArgs, opts: ResourceOptions | None = None) -> None:
        super().__init__(LetsEncryptAccountProvider(), name, args.model_dump(), opts)
