from pulumi import Input, Output, ResourceOptions
from pulumi.dynamic import *  # noqa: F403

from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, NoEncryption

from pulumi_dynamic_acme.utilis.acme import AcmeManager


class LetsEncryptCertificateArgs:
    account_key_pem: Input[str]
    order_url: Input[str]

    def __init__(self, account_key_pem: Input[str], order_url: Input[str]) -> None:
        self.account_key_pem = Output.secret(account_key_pem)
        self.order_url = order_url


class LetsEncryptCertificateProvider(ResourceProvider):
    def create(self, args: dict) -> CreateResult:
        manager = AcmeManager(
            args["account_key_pem"]
        )

        account = manager.get_account()

        certificate = manager.get_certificate(
            order_url=args["order_url"],
            account_uri=account.url
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
        super().__init__(LetsEncryptCertificateProvider(), f"LetsEncryptCertificate:{name}", {"certificate": Output.secret(""), **vars(args)}, opts)

    def __private_key_private_bytes(self, private_key: str) -> str:
        return load_pem_private_key(
            data=private_key.encode("utf-8"),
            password=None
        ).private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ).decode("utf-8")

    def azure_key_vault_certificate(
        self,
        certificate_signing_key_pem: Input[str]
    ) -> Output[str]:
        return Output.concat(Output.from_input(certificate_signing_key_pem).apply(lambda key: self.__private_key_private_bytes(private_key=key)), self.certificate)
