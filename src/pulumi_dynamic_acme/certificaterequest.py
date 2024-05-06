from pulumi import Input, Output, ResourceOptions
from pulumi.dynamic import *

from pulumi_dynamic_acme.utilis.letsencrypt import LetsEncryptManager


class LetsEncryptCertificateRequestArgs:
    account_key_pem: Input[str]
    domain: Input[str]

    def __init__(self, account_key_pem: Input[str], domain: Input[str]) -> None:
        self.account_key_pem = account_key_pem
        self.domain = domain


class LetsEncryptCertificateRequestProvider(ResourceProvider):
    def create(self, args: dict) -> CreateResult:
        manager = LetsEncryptManager(
            args["account_key_pem"]
        )

        account_uri = manager.get_account()

        record, record_value, order_url = manager.request_dns_challenge(
            domain=args["domain"],
            account_uri=account_uri
        )

        dns_import = f"{record} 300 IN TXT \"{record_value}\""

        return CreateResult(
            id_=order_url,
            outs={
                **args,
                "order_url": order_url,
                "record": record,
                "record_value": record_value,
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
        super().__init__(LetsEncryptCertificateRequestProvider(), name, {"order_url": None, "record": None, "record_value": None, "dns_import": None, **vars(args)}, opts)
