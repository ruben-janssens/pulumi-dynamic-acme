from pulumi import Input, Output, ResourceOptions
from pulumi.dynamic import *  # noqa: F403

from pulumi_dynamic_acme.utilis.acme import AcmeManager


class LetsEncryptCertificateRequestArgs:
    account_key_pem: Input[str]
    domain: Input[str]

    def __init__(self, account_key_pem: Input[str], domain: Input[str]) -> None:
        self.account_key_pem = Output.secret(account_key_pem)
        self.domain = domain


class LetsEncryptCertificateRequestProvider(ResourceProvider):
    def create(self, args: dict) -> CreateResult:
        manager = AcmeManager(
            args["account_key_pem"]
        )

        account = manager.get_account()

        dns_challenge = manager.request_dns_challenge(
            domain=args["domain"],
            account_url=account.url
        )

        dns_import = f"{dns_challenge.records[0].record} 300 IN TXT \"{dns_challenge.records[0].value}\""

        return CreateResult(
            id_=dns_challenge.order_url,
            outs={
                **args,
                "order_url": dns_challenge.order_url,
                "record": dns_challenge.records[0].record,
                "record_value": dns_challenge.records[0].value,
                "dns_import": dns_import
            }
        )

    def diff(self, _id: str, _olds: dict, _news: dict) -> DiffResult:
        changes = False
        replaces = []
        if _olds["account_key_pem"] != _news["account_key_pem"]:
            replaces.append("account_key_pem")

        if _olds["domain"] != _news["domain"]:
            replaces.append("domain")

        return DiffResult(
            changes=changes,
            replaces=replaces,
            stables=None,
            delete_before_replace=True
        )


class LetsEncryptCertificateRequest(Resource):
    account_key_pem: Output[str]
    domain: Output[str]
    order_url: Output[str]
    record: Output[str]
    record_value: Output[str]
    dns_import: Output[str]

    def __init__(self, name: str, args: LetsEncryptCertificateRequestArgs, opts: ResourceOptions | None = None) -> None:
        super().__init__(LetsEncryptCertificateRequestProvider(), f"LetsEncryptCertificateRequest:{name}", {"order_url": None, "record": None, "record_value": None, "dns_import": None, **vars(args)}, opts)
