import json
import time
import hashlib
import binascii
from base64 import urlsafe_b64encode
from httpx import get, post, head, Response

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from pulumi_dynamic_acme.models import (
    RequestType,
    AcmeManagerDnsChallenge,
    AcmeManagerDnsChallengeRecord,
    AcmeManagerJwk,
    AcmeManagerIdentification,
    AcmeDirectory,
    AcmeAccount,
    AcmeNewAccountBody,
    AcmeOrder,
    AcmeNewOrderBody,
    AcmeOrderStatus,
    AcmeAuthorization,
    AcmeChallenge,
    AcmeChallengeType,
    AcmeChallengeStatus,
    AcmeIdentifier
)


class AcmeManager:
    __KEY_TYPE = "RSA"
    __ALGORITHM = "RS256"

    def __init__(
        self,
        rsa_account_pem_key: str
    ) -> None:
        """"""
        self.__rsa_account_pem_key = rsa_account_pem_key

        self.__rsa_account_private_key: RSAPrivateKey = load_pem_private_key(self.__rsa_account_pem_key.encode("utf-8"), password=None)
        self.__rsa_account_public_key = self.__rsa_account_private_key.public_key()
        e = "{0:x}".format(self.__rsa_account_public_key.public_numbers().e)
        e = f"0{e}" if len(e) % 2 else e
        n = "{0:x}".format(self.__rsa_account_public_key.public_numbers().n)
        self.__public_jwk = AcmeManagerJwk(
            public_exponent=self.__urlsafe_base64(binascii.unhexlify(e.encode("utf-8"))),
            public_modulus=self.__urlsafe_base64(binascii.unhexlify(n.encode("utf-8"))),
            key_type=self.__KEY_TYPE
        )
        self.__thumbprint = self.__urlsafe_base64(hashlib.sha256(json.dumps(self.__public_jwk.model_dump(by_alias=True), sort_keys=True, separators=(",", ":")).encode("utf-8")).digest())

        self.__api_endpoint = "https://acme-v02.api.letsencrypt.org"
        self.__directory = None

        self.__get_directory()

    def __do_request(
        self,
        endpoint: str,
        request_type: RequestType,
        body: dict | None = None
    ) -> Response:
        response: Response | None = None
        match request_type:
            case RequestType.GET:
                response = get(
                    url=endpoint
                )
            case RequestType.POST:
                response = post(
                    url=endpoint,
                    headers={
                        "Content-Type": "application/jose+json"
                    },
                    json=body
                )
            case RequestType.HEAD:
                response = head(
                    url=endpoint
                )
            case _:
                raise ValueError(f"Request type {str(request_type)} is not supported.")

        if response.is_error:
            raise Exception(
                response.text   # TODO: Change raise common exception to self made unique exceptions (Do not handle exception here)
            )
        return response

    def __urlsafe_base64(self, input_: str | bytes) -> str:
        if isinstance(input_, str):
            input_ = input_.encode("utf-8")
        return urlsafe_b64encode(input_).decode("utf-8").replace("=", "")

    def __do_signed_post(
        self,
        endpoint: str,
        identification: AcmeManagerIdentification,
        body: dict | None = None
    ) -> Response:
        payload_base64 = self.__urlsafe_base64(json.dumps(body)) if body is not None else ""
        nonce = self.__get_nonce()

        protected = {
            "url": endpoint,
            "alg": self.__ALGORITHM,
            "nonce": nonce,
            **identification.model_dump(mode="json", by_alias=True, exclude_none=True)
        }

        protected_base64 = self.__urlsafe_base64(json.dumps(protected))

        signature = self.__rsa_account_private_key.sign(
            data=f"{protected_base64}.{payload_base64}".encode("utf-8"),
            padding=PKCS1v15(),
            algorithm=hashes.SHA256()
        )

        signature_base64 = self.__urlsafe_base64(signature)

        signed_body = {
            "protected": protected_base64,
            "payload": payload_base64,
            "signature": signature_base64
        }

        return self.__do_request(
            endpoint=endpoint,
            request_type=RequestType.POST,
            body=signed_body
        )

    def __get_nonce(self) -> str:
        return self.__do_request(
            endpoint=self.__directory.new_nonce,
            request_type=RequestType.HEAD
        ).headers.get("Replay-Nonce")

    def __get_directory(self) -> AcmeDirectory:
        response = self.__do_request(
            endpoint=f"{self.__api_endpoint}/directory",
            request_type=RequestType.GET
        )
        self.__directory = AcmeDirectory(**response.json())

    def __account(self, body: dict) -> AcmeAccount:
        response = self.__do_signed_post(
            endpoint=self.__directory.new_account,
            identification=AcmeManagerIdentification(jwk=self.__public_jwk),
            body=body
        )

        return AcmeAccount(
            url=response.headers.get("Location"),
            **response.json()
        )

    def create_account(self, contact: list[str]) -> AcmeAccount:
        return self.__account(
            body=AcmeNewAccountBody(
                contact=contact
            ).model_dump(by_alias=True)
        )

    def get_account(self) -> AcmeAccount:
        return self.__account(body={})

    def update_account(self, contact: str, account_url: str) -> None:
        pass

    def delete_account(self, account_url: str) -> None:
        pass

    def create_order(self, domains: list[str], account_url: str) -> AcmeOrder:
        response = self.__do_signed_post(
            endpoint=self.__directory.new_order,
            identification=AcmeManagerIdentification(kid=account_url),
            body=AcmeNewOrderBody(
                identifiers=[
                    AcmeIdentifier(
                        value=domain
                    ) for domain in domains
                ]
            ).model_dump(by_alias=True, exclude_none=True)
        )

        return AcmeOrder(
            url=response.headers.get("Location"),
            **response.json()
        )

    def get_order(self, order_url: str, account_url: str) -> AcmeOrder:
        response = self.__do_signed_post(
            endpoint=order_url,
            identification=AcmeManagerIdentification(kid=account_url)
        )

        return AcmeOrder(
            url=order_url,
            **response.json()
        )

    def __get_authorization(self, authorization_url, account_url) -> AcmeAuthorization:
        response = self.__do_signed_post(
            endpoint=authorization_url,
            identification=AcmeManagerIdentification(kid=account_url)
        )

        return AcmeAuthorization(
            **response.json()
        )

    def request_dns_challenge(self, domain: str, account_url: str) -> AcmeManagerDnsChallenge:
        """ DNS-01 challenge for a single domain """
        order = self.create_order(account_url=account_url, domains=[domain])

        authorization = self.__get_authorization(authorization_url=order.authorizations[0], account_url=account_url)

        challenge = authorization.challenges.get(AcmeChallengeType.DNS_01)

        return AcmeManagerDnsChallenge(
            order_url=order.url,
            records=[
                AcmeManagerDnsChallengeRecord(
                    record=f"_acme-challenge.{authorization.identifier.value}.",
                    value=self.__urlsafe_base64(hashlib.sha256(f"{challenge.token}.{self.__thumbprint}".encode("utf-8")).digest())
                )
            ]
        )

    def validate_dns_challenge(self, order_url: str, certificate_signing_key_pem: str, account_url: str) -> None:
        """ Validate DNS-01 challenge for a single domain """
        rsa_signing_private_key: RSAPrivateKey = load_pem_private_key(certificate_signing_key_pem.encode("utf-8"), password=None)

        order = self.get_order(order_url=order_url, account_url=account_url)
        if len(order.authorizations) != 1:
            raise Exception("This does not have a single domain! Not continuing with validation!")

        authorization = self.__get_authorization(authorization_url=order.authorizations[0], account_url=account_url)
        challenge = authorization.challenges.get(AcmeChallengeType.DNS_01)

        # Request validation of challenge
        challenge = AcmeChallenge(**self.__do_signed_post(
            endpoint=challenge.url,
            identification=AcmeManagerIdentification(kid=account_url),
            body={}
        ).json())

        # Wait until validated
        attempts = 0
        while challenge.status in [AcmeChallengeStatus.PENDING, AcmeChallengeStatus.PROCESSING]:
            attempts += 1
            if attempts > (3600 / 5):  # ~1 hour max
                raise Exception("Timed out waiting for valid status for challenge.")
            challenge = AcmeChallenge(**self.__do_signed_post(
                endpoint=challenge.url,
                identification=AcmeManagerIdentification(kid=account_url),
            ).json())
            time.sleep(5)
        if challenge.status is not AcmeChallengeStatus.VALID:
            raise Exception("Challenge is not valid. Validate the TXT record name and value.")

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            name=x509.Name(
                [
                    x509.NameAttribute(
                        oid=NameOID.COMMON_NAME,
                        value=authorization.identifier.value
                    )
                ]
            )
        ).sign(private_key=rsa_signing_private_key, algorithm=hashes.SHA256())

        self.__do_signed_post(
            endpoint=order.finalize,
            identification=AcmeManagerIdentification(kid=account_url),
            body={
                "csr": self.__urlsafe_base64(csr.public_bytes(encoding=Encoding.DER))
            }
        )

        # Wait until validated
        attempts = 0
        while order.status in [AcmeOrderStatus.PENDING, AcmeOrderStatus.READY, AcmeOrderStatus.PROCESSING]:
            attempts += 1
            if attempts > (3600 / 5):  # ~1 hour max
                raise Exception("Timed out waiting for valid status for order.")
            order = self.get_order(order_url=order_url, account_url=account_url)
            time.sleep(5)
        if order.status is not AcmeOrderStatus.VALID:
            raise Exception("Order is not valid.")

    def get_certificate(self, order_url: str, account_url: str) -> str | None:
        """ Get certificate of a validated order """
        order = self.get_order(order_url=order_url, account_url=account_url)

        if not order.certificate:
            return None

        certificate_response = self.__do_signed_post(
            endpoint=order.certificate,
            identification=AcmeManagerIdentification(kid=account_url)
        )

        return certificate_response.text
