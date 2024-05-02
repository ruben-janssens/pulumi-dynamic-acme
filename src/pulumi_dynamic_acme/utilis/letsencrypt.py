import json
import binascii
import hashlib
from typing import Literal, Any
from enum import Enum
from base64 import urlsafe_b64encode
from pydantic import BaseModel, Field, AnyHttpUrl, EmailStr, field_serializer
from httpx import get, post, head, Response

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


class RequestType(str, Enum):
    GET = "get"
    POST = "post"
    HEAD = "head"


class LetsEncryptAcmeDirectory(BaseModel):
    new_nonce: AnyHttpUrl = Field(alias="newNonce")
    new_account: AnyHttpUrl = Field(alias="newAccount")
    new_order: AnyHttpUrl = Field(alias="newOrder")
    revoke_cert: AnyHttpUrl = Field(alias="revokeCert")


class LetsEncryptAcmeAccountPostBody(BaseModel):
    terms_of_service_agreed: bool = Field(serialization_alias="termsOfServiceAgreed", default=True)
    contact: list[EmailStr] = Field(serialization_alias="contact")

    @field_serializer("contact")
    def serialize_contact(self, contact: list[EmailStr], _info):
        return [f"mailto:{mail}" for mail in contact]


class LetsEncryptAcmeCertificateIdentifier(BaseModel):
    type: Literal["dns"] = Field(serialization_alias="type")
    value: str = Field(serialization_alias="value")


class LetsEncryptAcmeCertificatePostBody(BaseModel):
    identifiers: list[LetsEncryptAcmeCertificateIdentifier] = Field(serialization_alias="identifiers")


class LetsEncryptManager:
    __KEY_TYPE = "RSA"
    __ALGORITHM = "RS256"

    def __init__(self, rsa_pem_key: str) -> None:
        self.__rsa_pem_key = rsa_pem_key

        self.__rsa_private_key: RSAPrivateKey = load_pem_private_key(self.__rsa_pem_key.encode("utf-8"), password=None)
        self.__rsa_public_key = self.__rsa_private_key.public_key()
        e = "{0:x}".format(self.__rsa_public_key.public_numbers().e)
        e = f"0{e}" if len(e) % 2 else e
        n = "{0:x}".format(self.__rsa_public_key.public_numbers().n)
        self.__public_jwk = {
            "e": urlsafe_b64encode(binascii.unhexlify(e.encode("utf-8"))).decode("utf-8").replace("=", ""),
            "n": urlsafe_b64encode(binascii.unhexlify(n.encode("utf-8"))).decode("utf-8").replace("=", ""),
            "kty": self.__KEY_TYPE
        }
        self.__thumbprint = urlsafe_b64encode(hashlib.sha256(json.dumps(self.__public_jwk, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()).decode("utf-8").replace("=", "")

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
                response.text
            )
        return response

    def __do_signed_post(
        self,
        endpoint: AnyHttpUrl,
        identification:  dict,
        body: dict | None = None
    ) -> Response:
        payload_base64 = urlsafe_b64encode(json.dumps(body).encode("utf-8")).decode("utf-8").replace("=", "") if body else ""
        nonce = self.__get_nonce()

        protected = {
            "url": endpoint.__str__(),
            "alg": self.__ALGORITHM,
            "nonce": nonce,
            **identification
        }

        protected_base64 = urlsafe_b64encode(json.dumps(protected).encode("utf-8")).decode("utf-8").replace("=", "")

        signature = self.__rsa_private_key.sign(
            data=f"{protected_base64}.{payload_base64}".encode("utf-8"),
            padding=PKCS1v15(),
            algorithm=hashes.SHA256()
        )

        signature_base64 = urlsafe_b64encode(signature).decode("utf-8").replace("=", "")

        signed_body = {
            "protected": protected_base64,
            "payload": payload_base64,
            "signature": signature_base64
        }

        return self.__do_request(
            endpoint=endpoint.__str__(),
            request_type=RequestType.POST,
            body=signed_body
        )

    def __get_nonce(self) -> str:
        return self.__do_request(
            endpoint=self.__directory.new_nonce.__str__(),
            request_type=RequestType.HEAD
        ).headers.get("Replay-Nonce")

    def __get_directory(self) -> LetsEncryptAcmeDirectory:
        response = self.__do_request(
            endpoint=f"{self.__api_endpoint}/directory",
            request_type=RequestType.GET
        )

        self.__directory = LetsEncryptAcmeDirectory(**response.json())

    def account(self, contact: str) -> str:
        body = LetsEncryptAcmeAccountPostBody(
            terms_of_service_agreed=True,
            contact=[contact]
        )

        response = self.__do_signed_post(
            endpoint=self.__directory.new_account,
            identification={"jwk": self.__public_jwk},
            body=body.model_dump(by_alias=True)
        )

        return response.headers.get("location")

    def update_account(self, contact: str, account_uri: str) -> None:
        pass

    def request_certificate(self, domain: str, account_uri: str) -> None:
        body = LetsEncryptAcmeCertificatePostBody(
            identifiers=[
                LetsEncryptAcmeCertificateIdentifier(
                    type="dns",
                    value=domain
                )
            ]
        )

        order_response = self.__do_signed_post(
            endpoint=self.__directory.new_order,
            identification={"kid": account_uri},
            body=body.model_dump(by_alias=True)
        )

        response = self.__do_signed_post(
            endpoint=order_response.json()["authorizations"][0],
            identification={"kid": account_uri}
        )

        challenge = [challenge for challenge in response.json()["challenges"] if challenge["type"] == "dns-01"][0]
        
        txt_record_value = f"{challenge['token']}.{self.__thumbprint}"
        txt_record = f"_acme-challenge.{domain}"

        print(txt_record)
        print(txt_record_value)
        print(response.json())

        response = self.__do_signed_post(
            endpoint=challenge["url"],
            identification={"kid": account_uri},
            body={}
        )

        print(response.json())

