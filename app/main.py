import re
import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import (
    Depends,
    HTTPException,
    Request,
    status,
    Header,
    BackgroundTasks,
    Cookie,
    FastAPI,
    Response,
)
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from models.models import (
    BaseUser,
    Feedback,
    Product,
    Token,
    TokenData,
    User,
    UserCreate,
    UserReturn,
)
from fastapi.encoders import jsonable_encoder
from models.exceptions import (
    CustomExceptionModelA,
    CustomExceptionModelB,
    ErrorResponseModel,
)
from fake_data.data import sample_products
from datetime import datetime, timedelta, timezone
from typing import Annotated
from functools import wraps
from databases import Database
from exceptions import CustomExceptionA, CustomExceptionB


SECRET_KEY = "0eb5ad9cb42cffd87faad1aa050810d2eaf77cc91cee5f2c43b2fbda057738fa"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "postgresql://postgres:postgres@localhost/postgres"


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()


def is_valid_accept_language(header: str) -> bool:
    """
    Проверяет, соответствует ли заголовок Accept-Language корректному формату.
    :param header: строка заголовка Accept-Language
    :return: True, если заголовок корректен, иначе False
    """
    pattern = re.compile(
        r'^(?:[a-zA-Z]{1,8}(?:-[a-zA-Z]{1,8})?(?:;q=0(\.\d{0,3})?|1(\.0{0,3})?)?(?:,\s*)?)+$'
    )
    return bool(pattern.fullmatch(header))


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return User(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if user.password != password:
        return False
    return user


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


class PermissionChecker:

    def __init__(self, roles: list[str]):
        self.roles = roles

    def __call__(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get("current_user")
            if not any(role in user.roles for role in self.roles):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect permission",
                )
            return await func(*args, **kwargs)

        return wrapper


feedbacks = []


fake_users = {
    1: {"username": "john_doe", "email": "john@example.com"},
    2: {"username": "jane_smith", "email": "jane@example.com"},
}
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "password": "password",
        "disabled": False,
        "roles": [
            "user",
        ],
    }
}


@app.get("/")
async def root(response: Response):
    now = datetime.now().strftime("%d/%m/%Y, %H:%M:%S")
    response.set_cookie(key="last_visit", value=now)
    return {"message": "куки установлены"}


# @app.get("/{user_id}")
# async def search_by_id(user_id: int):
#     return {"вы просили найти юзера с id": user_id}


# @app.get("/users/{user_id}")
# async def read_user(user_id: int):
#     if user_id in fake_users:
#         return fake_users[user_id]
#     return {"error": "User not found"}


@app.post("/feedback/")
async def post_feedback(feedback: Feedback):
    feedbacks.append({"name": feedback.name, "message": feedback.message})
    return {"message": feedback.message}


@app.get("/feedback/")
async def get_feedbacks():
    return feedbacks


# @app.post("/create_user")
# async def create_user(user: UserCreate) -> UserCreate:
#     return user


@app.get("/product/{product_id}")
async def get_product(product_id: int) -> Product | dict:
    product = list(
        filter(lambda x: x["product_id"] == product_id, sample_products)
    )
    if product:
        return product[0]
    return {"message": "Product not found"}


@app.get("/products/search")
async def search_product(
    keyword: str, category: str | None = None, limit: int | None = 10
) -> list[Product]:
    return list(
        filter(
            lambda x: keyword.lower() in x["name"].lower()
            and (category is None or x["category"] == category),
            sample_products,
        )
    )[:limit]


def write_notification(email: str, message=""):
    with open("log.txt", mode="w") as email_file:
        content = f"notification for {email}: {message}"
        email_file.write(content)


@app.post("/send-notification/{email}")
async def send_notification(email: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(
        write_notification, email, message="some notification"
    )
    return {"message": "Notification sent in the background"}


@app.get("/items/")
async def read_items(x_token: Annotated[list[str] | None, Header()] = None):
    return {"X-Token values": x_token}


@app.get("/headers/")
async def get_headers(request: Request):
    ua = request.headers.get("User-Agent")
    al = request.headers.get("Accept-Language")
    if ua is None or al is None:
        raise HTTPException(status_code=400, detail="Отсутствуют заголовки.")
    if not is_valid_accept_language(al):
        raise HTTPException(
            status_code=400, detail="Неправильный формат Accept-Language."
        )
    if ua and al:
        return {
            "User-Agent": ua,
            "Accept-Language": al,
        }


@app.post("/login")
async def login_for_token(user: BaseUser) -> Token:
    user = authenticate_user(fake_users_db, user.user_name, user.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/admin")
@PermissionChecker(["admin"])
async def get_admin(
    current_user: User = Depends(get_current_user),
) -> dict:
    user = get_user(fake_users_db, current_user.username)
    if user:
        return {"Message": "Success!"}
    return {"Message": "Not success!"}


@app.get("/user_me")
@PermissionChecker(["admin", "user"])
async def get_user_me(
    current_user: User = Depends(get_current_user),
) -> dict:
    user = get_user(fake_users_db, current_user.username)
    if user:
        return {"Message": "Success!"}
    return {"Message": "Not success!"}


@app.get("/protected_resource")
@PermissionChecker(["admin", "user"])
async def get_protected_resource(
    current_user: User = Depends(get_current_user),
) -> dict:
    return {"message": "Access success!"}


@app.post(
    "/users/",
    response_model=UserReturn,
    responses={
        status.HTTP_200_OK: {"model": UserReturn},
        status.HTTP_500_INTERNAL_SERVER_ERROR: {"model": ErrorResponseModel},
    },
)
async def create_user(user: UserCreate):
    query = "INSERT INTO users (username, email) VALUES (:username, :email) RETURNING id"
    values = {"username": user.username, "email": user.email}
    async with Database(DATABASE_URL) as db:
        try:
            user_id = await db.execute(query=query, values=values)
            return {**user.model_dump(), "id": user_id}
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Failed to create user. Error: {e}"
            )


@app.get("/users/{user_id}", response_model=UserReturn)
async def get_one_user_(user_id: int):
    query = "SELECT * FROM users WHERE id = :user_id"
    values = {"user_id": user_id}
    async with Database(DATABASE_URL) as db:
        try:
            result = await db.fetch_one(query=query, values=values)
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Failed to create user. Error: {e}"
            )
        if result:
            return UserReturn(
                username=result["username"],
                email=result["email"],
                id=result["id"],
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )


@app.put("/users/{user_id}", response_model=UserReturn)
async def update_user_(user_id: int, user: UserCreate):
    query = "UPDATE users SET username = :username, email = :email, age = :age, is_subscribed = :is_subscribed WHERE id = :user_id RETURNING *"
    values = {
        "user_id": user_id,
        "username": user.username,
        "email": user.email,
        "age": user.age,
        "is_subscribed": user.is_subscribed,
    }
    async with Database(DATABASE_URL) as db:
        try:
            result = await db.fetch_one(query=query, values=values)
            if not result:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found.",
                )
            return UserReturn(**result)
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Failed to create user. Error: {e}"
            )


@app.delete("/users/{user_id}", response_model=dict)
async def delete_user_(user_id: int):
    query = "DELETE FROM users WHERE id = :user_id RETURNING id"
    values = {"user_id": user_id}
    async with Database(DATABASE_URL) as db:
        try:
            result = await db.execute(query=query, values=values)
        except Exception as e:
            raise HTTPException(
                status_code=500, detail=f"Failed to create user. Error: {e}"
            )
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )
        if result:
            return {"message": "User deleted successfully"}


@app.exception_handler(CustomExceptionA)
async def custom_exception_a_handler(request: Request, exc: CustomExceptionA):
    error = jsonable_encoder(
        CustomExceptionModelA(
            status_code=exc.status_code,
            er_message=exc.message,
            er_details=exc.detail,
        )
    )
    return JSONResponse(status_code=exc.status_code, content=error)


@app.exception_handler(CustomExceptionB)
async def custom_exception_b_handler(request: Request, exc: CustomExceptionB):
    error = jsonable_encoder(
        CustomExceptionModelB(
            status_code=exc.status_code,
            er_message=exc.message,
            er_details=exc.detail,
            er_log=exc.log,
        )
    )
    return JSONResponse(status_code=exc.status_code, content=error)


# добавили модель ответа
@app.get(
    "/items/{item_id}/",
    responses={
        status.HTTP_403_FORBIDDEN: {"model": CustomExceptionModelA},
        status.HTTP_404_NOT_FOUND: {"model": CustomExceptionModelB},
    },
)
async def read_item(item_id: int):
    if item_id == 42:
        raise CustomExceptionA(
            detail="Item not found",
            status_code=403,
            message="You're trying to get an item that doesn't exist. Try entering a different item_id.",
        )
    if item_id == 43:
        raise CustomExceptionB(
            detail="Item not found",
            status_code=404,
            message="You're trying to get an item that doesn't exist.",
            log="loglog",
        )
    return {"id": item_id}
