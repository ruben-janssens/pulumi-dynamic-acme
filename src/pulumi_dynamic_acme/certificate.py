from pulumi import Input, Output, ResourceOptions
from pulumi.dynamic import *  # noqa: F403

from pulumi_dynamic_acme.utilis.acme import AcmeManager
from pulumi_dynamic_acme.models import AcmeCertificateType


class LetsEncryptCertificateArgs:
    account_key_pem: Input[str]
    order_url: Input[str]
    certificate_signing_key_pem: Input[str] | None
    certificate_type: Input[AcmeCertificateType] | None

    def __init__(self, account_key_pem: Input[str], order_url: Input[str], certificate_signing_key_pem: Input[str] | None = None, certificate_type: AcmeCertificateType | None = None) -> None:
        self.account_key_pem = Output.secret(account_key_pem)
        self.order_url = order_url
        if certificate_signing_key_pem:
            self.certificate_signing_key_pem = Output.secret(certificate_signing_key_pem)
        else:
            self.certificate_signing_key_pem = certificate_signing_key_pem
        self.certificate_type = certificate_type


class LetsEncryptCertificateProvider(ResourceProvider):
    def create(self, args: dict) -> CreateResult:
        manager = AcmeManager(
            args["account_key_pem"]
        )

        account = manager.get_account()

        certificate = manager.get_certificate(
            order_url=args["order_url"],
            account_url=account.url,
            certificate_signing_key_pem=args["certificate_signing_key_pem"],
            certificate_type=args["certificate_type"]
        )

        return CreateResult(
            id_=args["order_url"],
            outs={
                **args,
                "certificate": certificate
            }
        )

    def diff(self, _id: str, _olds: dict, _news: dict) -> DiffResult:
        changes = False
        replaces = []
        if _olds["account_key_pem"] != _news["account_key_pem"]:
            replaces.append("account_key_pem")

        if _olds["order_url"] != _news["order_url"]:
            replaces.append("order_url")

        changes = True if replaces else changes

        return DiffResult(
            changes=changes,
            replaces=replaces,
            stables=None,
            delete_before_replace=True
        )


class LetsEncryptCertificate(Resource):
    account_key_pem: Output[str]
    order_url: Output[str]
    certificate: Output[str]

    def __init__(self, name: str, args: LetsEncryptCertificateArgs, opts: ResourceOptions | None = None) -> None:
        super().__init__(LetsEncryptCertificateProvider(), f"LetsEncryptCertificate:{name}", {"certificate": Output.secret(" "), **vars(args)}, opts)
