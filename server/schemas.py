from pydantic import BaseModel, Field

class RegisterIn(BaseModel):
    box_pub: str = Field(..., description="public box key (hex)")

class PutIn(BaseModel):
    recipient: str
    expiration_time: int
    cipher_hex: str
    pow: dict  # {"salt": str, "nonce": str}
