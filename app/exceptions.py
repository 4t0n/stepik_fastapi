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


class UserNotFoundException(HTTPException):
    def __init__(
        self, detail: str, message: str, status_code: int = 404
    ):
        super().__init__(
            status_code=status_code, detail=detail
        )
        self.message = message


class InvalidUserDataException(HTTPException):
    def __init__(
        self, detail: str, message: str, status_code: int = 422
    ):
        super().__init__(
            status_code=status_code, detail=detail
        )
        self.message = message
