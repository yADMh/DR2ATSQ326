from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi.security import OAuth2PasswordBearer, HTTPBearer
from jose import jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="auth/login",
    scopes={
        "read:consultas": "Ler consultas autorizadas",
        "write:consultas": "Criar e alterar consultas autorizadas",
        "role:admin": "Privilégios administrativos",
        "m2m_scope": "Consultar horários disponíveis via integração M2M",
    },
)

# Esquema Bearer usado pelo Swagger para permitir a colagem manual do JWT.
# O token continua sendo emitido pelo endpoint /auth/login e validado normalmente.
bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BearerAuth",
    description="Cole aqui o JWT obtido em /auth/login. Não inclua a palavra Bearer.",
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta
        if expires_delta
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
