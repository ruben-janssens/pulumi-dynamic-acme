from pydantic import BaseModel, ConfigDict

from pulumi import Input, Output, ResourceOptions
from pulumi.dynamic import *

from pulumi_dynamic_acme.utilis.letsencrypt import LetsEncryptManager


class LetsEncryptCertificateValidationArgs(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="ignore")

    account_key_pem: Input[str]
    order_url: Input[str]
    certificate_signing_key_pem: Input[str]


class LetsEncryptCertificateValidationProvider(ResourceProvider):
    def create(self, args: dict) -> CreateResult:
        manager = LetsEncryptManager(
            args["account_key_pem"]
        )

        account_uri = manager.get_account()

        manager.validate_dns_challenge(
            order_url=args["order_url"],
            certificate_signing_key_pem=args["certificate_signing_key_pem"],
            account_uri=account_uri
        )

        return CreateResult(
            id_=args["order_url"],
            outs={
                **args
            }
        )

    def diff(self, _id: str, _olds: dict, _news: dict) -> DiffResult:
        changes = False
        replaces = []
        if _olds["account_key_pem"] != _news["account_key_pem"]:
            replaces.append("account_key_pem")

        if _olds["order_url"] != _news["order_url"]:
            replaces.append("order_url")

        return DiffResult(
            changes=changes,
            replaces=replaces,
            stables=None,
            delete_before_replace=True
        )


class LetsEncryptCertificateValidation(Resource):
    account_key_pem: Output[str]
    order_url: Output[str]
    certificate_signing_key_pem: Output[str]

    def __init__(self, name: str, args: LetsEncryptCertificateValidationArgs, opts: ResourceOptions | None = None) -> None:
        super().__init__(LetsEncryptCertificateValidationProvider(), name, args.model_dump(), opts)
