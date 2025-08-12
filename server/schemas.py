from pydantic import BaseModel, Field, validator
import re, time

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

def _is_hex(s: str) -> bool:
    return bool(s) and HEX_RE.match(s) is not None

class RegisterIn(BaseModel):
    box_pub: str = Field(..., description="public box key (hex)")
    @validator("box_pub")
    def v_box_pub(cls, v):
        if not _is_hex(v):
            raise ValueError("box_pub must be hex")
        if len(v) != 64:
            raise ValueError("box_pub must be 64 hex chars")
        return v

class PutIn(BaseModel):
    recipient: str
    expiration_time: int
    cipher_hex: str
    pow: dict  # {"salt": str, "nonce": str}

    @validator("recipient")
    def v_recipient(cls, v):
        if not _is_hex(v) or len(v) != 64:
            raise ValueError("recipient must be 64 hex chars")
        return v

    @validator("cipher_hex")
    def v_cipher_hex(cls, v):
        if not _is_hex(v):
            raise ValueError("cipher_hex must be hex")
        return v

    @validator("pow")
    def v_pow(cls, v):
        if not isinstance(v, dict): raise ValueError("pow must be object")
        salt = v.get("salt"); nonce = v.get("nonce")
        if not salt or not isinstance(salt, str): raise ValueError("pow.salt required")
        if not nonce or not isinstance(nonce, str) or not _is_hex(nonce): raise ValueError("pow.nonce hex required")
        if len(nonce) < 16 or len(nonce) > 128:
            raise ValueError("pow.nonce length invalid")
        return v

    @validator("expiration_time")
    def v_exp(cls, v):
        if v <= 0: raise ValueError("expiration_time must be > 0")
        return v
