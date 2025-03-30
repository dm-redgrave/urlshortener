from pydantic import BaseModel, EmailStr
from datetime import datetime

class RegisterRequest(BaseModel):
    email: EmailStr

class ShortenRequest(BaseModel):
    url: str
    custom_alias: str | None = None
    expires_at: datetime | None = None

class LinkInfo(BaseModel):
    original_url: str
    created_at: datetime
    last_accessed_at: datetime | None
    click_count: int
    expires_at: datetime | None
