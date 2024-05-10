from pulumi import Input, Output, ResourceOptions
from pulumi.dynamic import *
from pulumi.dynamic.dynamic import UpdateResult  # noqa: F403

from pulumi_dynamic_acme.utilis.acme import AcmeManager


class LetsEncryptAccountArgs:
    account_key_pem: Input[str]
    contact: Input[str]

    def __init__(self, account_key_pem: Input[str], contact: Input[str]) -> None:
        self.account_key_pem = Output.secret(account_key_pem)
        self.contact = contact


class LetsEncryptAccountProvider(ResourceProvider):
    def create(self, args: dict) -> CreateResult:
        manager = AcmeManager(
            args["account_key_pem"]
        )

        account = manager.create_account(contact=[args["contact"]])

        return CreateResult(
            id_=account.url,
            outs={
                **args,
                "account_uri": account.url
            }
        )

    def read(self, id_: str, args: dict) -> ReadResult:
        manager = AcmeManager(
            args["account_key_pem"]
        )

        account = manager.get_account()

        return ReadResult(
            id_=account.url,
            outs={
                **args,
                "account_uri": account.url
            }
        )

    def update(self, _id: str, _olds: dict, _news: dict) -> UpdateResult:
        manager = AcmeManager(
            _news["account_key_pem"]
        )

        account = manager.update_account(
            contact=[_news["contact"]],
            account_url=_id
        )

        return UpdateResult(
            outs={
                **_news,
                "account_uri": account.url
            }
        )

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
        super().__init__(LetsEncryptAccountProvider(), f"LetsEncryptAccount:{name}", {"account_uri": None, **vars(args)}, opts)
