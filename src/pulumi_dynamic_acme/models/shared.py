from typing import Literal, Annotated
from pydantic import BaseModel, Field, AfterValidator
from pydantic import HttpUrl


# Check if string is a valid url
# Could have used HttpUrl but Pulumi might not handle this correctly or give back an Output[AnyHttpUrl] wich is not convenient
HttpUrlString = Annotated[HttpUrl, AfterValidator(str)]


class AcmeIdentifier(BaseModel):
    type: Literal["dns"] = Field(serialization_alias="type", default="dns")
    value: str = Field(serialization_alias="value")
