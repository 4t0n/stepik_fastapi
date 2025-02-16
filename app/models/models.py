from pydantic import BaseModel, EmailStr, Field
from typing import Annotated


class Feedback(BaseModel):
    name: str
    message: str


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    age: Annotated[int, Field(gt=1, lt=140)] | None = None
    is_subscribed: bool | None = None


class UserReturn(UserCreate):
    id: int | None = None


class Product(BaseModel):
    product_id: int
    name: str
    category: str
    price: float


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class BaseUser(BaseModel):
    user_name: str
    password: str


class User(BaseModel):
    username: str
    full_name: str
    email: EmailStr
    password: str
    disabled: bool
    roles: list[str]


class ErrorResponseModel(BaseModel):
    status_code: int
    message: str
    error_detail: str
