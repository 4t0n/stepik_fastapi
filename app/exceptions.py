from fastapi import HTTPException


class CustomExceptionA(HTTPException):
    def __init__(self, detail: str, message: str, status_code: int = 400):
        super().__init__(status_code=status_code, detail=detail)
        self.message = message


class CustomExceptionB(HTTPException):
    def __init__(
        self,
        detail: str,
        message: str,
        log: str,
        status_code: int = 400,
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.message = message
        self.log = log
