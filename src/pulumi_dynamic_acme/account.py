from pydantic import BaseModel, ConfigDict, EmailStr

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

        account_uri = manager.create_account(contact=args["contact"])

        return CreateResult(
            id_=account_uri,
            outs={
                **args,
                "account_uri": account_uri
            }
        )

    def read(self, id_: str, args: dict) -> ReadResult:
        manager = LetsEncryptManager(
            args["account_key_pem"]
        )

        account_uri = manager.get_account()

        return ReadResult(
            id_=account_uri,
            outs={
                **args,
                "account_uri": account_uri
            }
        )

    # def update(self, _id: str, _olds: dict, _news: dict) -> UpdateResult:
    #     manager = LetsEncryptManager(
    #         _olds["account_key_pem"]
    #     )

    #     manager.update_account(
    #         contact=_news["contact"],
    #         account_uri=_id
    #     )

    #     return UpdateResult(
    #         outs={
    #             **_news,
    #             "account_uri": _id
    #         }
    #     )

    def diff(self, _id: str, _olds: dict, _news: dict) -> DiffResult:
        changes = False
        if _olds["contact"] != _news["contact"]:
            changes = True

        replaces = []
        if _olds["account_key_pem"] != _news["account_key_pem"]:
            replaces.append("account_key_pem")

        return DiffResult(
            changes=changes,
            replaces=replaces,
            stables=None,
            delete_before_replace=True
        )

class LetsEncryptAccount(Resource):
    account_key_pem: Output[str]
    account_uri: Output[str]
    contact: Output[str]

    def __init__(self, name: str, args: LetsEncryptAccountArgs, opts: ResourceOptions | None = None) -> None:
        super().__init__(LetsEncryptAccountProvider(), name, args.model_dump(), opts)
