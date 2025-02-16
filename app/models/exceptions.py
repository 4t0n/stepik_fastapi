from pydantic import BaseModel


class CustomExceptionModelA(BaseModel):
    status_code: int
    er_message: str
    er_details: str


class CustomExceptionModelB(BaseModel):
    status_code: int
    er_message: str
    er_details: str
    er_log: str
