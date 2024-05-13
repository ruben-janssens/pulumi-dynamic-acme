from pulumi import Input, Output, ResourceOptions
from pulumi.dynamic import *  # noqa: F403

from pulumi_dynamic_acme.utilis.acme import AcmeManager


class LetsEncryptCertificateValidationArgs:
    account_key_pem: Input[str]
    order_url: Input[str]
    certificate_signing_key_pem: Input[str]

    def __init__(self, account_key_pem: Input[str], order_url: Input[str], certificate_signing_key_pem: Input[str]) -> None:
        self.account_key_pem = Output.secret(account_key_pem)
        self.order_url = order_url
        self.certificate_signing_key_pem = Output.secret(certificate_signing_key_pem)


class LetsEncryptCertificateValidationProvider(ResourceProvider):
    def create(self, args: dict) -> CreateResult:
        manager = AcmeManager(
            args["account_key_pem"]
        )

        account = manager.get_account()

        manager.validate_dns_challenge(
            order_url=args["order_url"],
            certificate_signing_key_pem=args["certificate_signing_key_pem"],
            account_url=account.url
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
        super().__init__(LetsEncryptCertificateValidationProvider(), f"LetsEncryptCertificateValidation:{name}", {**vars(args)}, opts)
