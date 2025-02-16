import sqlalchemy
from sqlalchemy import Column

metadata = sqlalchemy.MetaData()


users_table = sqlalchemy.Table(
    "users",
    metadata,
    Column("id", sqlalchemy.Integer, primary_key=True),
    Column("username", sqlalchemy.String(100), unique=True, nullable=False),
    Column("email", sqlalchemy.String(40), unique=True, nullable=False),
    Column("age", sqlalchemy.Integer),
    Column("is_subscribed", sqlalchemy.Boolean(), default=False)
)
