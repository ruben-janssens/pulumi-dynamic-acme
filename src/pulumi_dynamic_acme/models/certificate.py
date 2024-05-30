import base64
from enum import Enum
from pydantic import BaseModel, Field, model_validator

from cryptography.x509 import load_pem_x509_certificates
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates


class AcmeCertificateType(str, Enum):
    PLAIN = "plain"
    PEM_CHAIN = "pem_chain"
    PKSC12_B64 = "pksc12_b64"


class AcmeCertificate(BaseModel):
    certificate: str
    certificate_signing_key_pem: str | None = Field(default=None)
    type: AcmeCertificateType | None = Field(default=None)

    @model_validator(mode="after")
    def convert_certificate_to_correct_type(self) -> 'AcmeCertificate':
        match self.type:
            case AcmeCertificateType.PLAIN:
                return self
            case AcmeCertificateType.PEM_CHAIN:
                self.__convert_to_pem_chain()
                return self
            case AcmeCertificateType.PKSC12_B64:
                self.__convert_to_pksc12_b64()
                return self
            case _:
                return self

    def __convert_to_pem_chain(self) -> None:
        private_bytes = load_pem_private_key(
            data=self.certificate_signing_key_pem.encode("utf-8"),
            password=None
        ).private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ).decode("utf-8")
        self.certificate = private_bytes + "\n" + self.certificate

    def __convert_to_pksc12_b64(self) -> None:
        x509_certificates = load_pem_x509_certificates(self.certificate.encode("utf-8"))
        self.certificate = base64.b64encode(
            serialize_key_and_certificates(
                name=None,
                key=load_pem_private_key(
                    data=self.certificate_signing_key_pem.encode("utf-8"),
                    password=None
                ),
                cert=x509_certificates[0],
                cas=x509_certificates[1:] if len(x509_certificates) > 1 else None,
                encryption_algorithm=NoEncryption()
            )
        ).decode("utf-8")
