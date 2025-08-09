from pydantic import BaseModel, Field
from typing import List

class RegisterIn(BaseModel):
    box_pub: str = Field(..., description="public box key (hex)")

class PutIn(BaseModel):
    recipient: str
    expiration_time: int
    cipher_hex: str
    pow: dict  # {"salt": str, "nonce": str}

class GetIn(BaseModel):
    recipient: str

class AckIn(BaseModel):
    ids: List[int]

class DeleteIn(BaseModel):
    ids: List[int]
