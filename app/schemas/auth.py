from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    personnel_id: str = Field(
        ...,
        min_length=1,
        max_length=20
    )

    password: str = Field(
        ...,
        min_length=8,
        max_length=128
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
