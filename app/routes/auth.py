from fastapi import APIRouter, Depends, HTTPException, Request, Form, status
from sqlmodel import Session, select
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database.session import get_session
from app.models.domain import Usuario
from app.core.config import settings
from app.core.security import verify_password, create_access_token

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

# Os scopes são definidos pelo servidor de acordo com o papel.
ROLE_SCOPES = {
    "admin": ["read:consultas", "write:consultas", "role:admin"],
    "medico": ["read:consultas", "write:consultas"],
    "paciente": ["read:consultas", "write:consultas"],
}


@router.post("/login")
@limiter.limit("5/minute")
def login(
    request: Request,
    grant_type: str = Form(default="password"),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    username: str = Form(None),
    password: str = Form(None),
    scope: str = Form(""),  # mantido por compatibilidade com OAuth2; não é confiável
    session: Session = Depends(get_session),
):
    if grant_type == "client_credentials":
        if (
            client_id == settings.M2M_CLIENT_ID
            and client_secret == settings.M2M_CLIENT_SECRET
        ):
            return {
                "access_token": create_access_token(
                    {
                        "sub": client_id,
                        "principal_type": "m2m",
                        "role": "lab",
                        "scopes": ["m2m_scope"],
                    }
                ),
                "token_type": "bearer",
            }

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais de cliente inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if grant_type != "password":
        raise HTTPException(status_code=400, detail="Grant type não suportado")

    if not username or not password:
        raise HTTPException(
            status_code=400,
            detail="Username and password required for password grant",
        )

    usuario = session.exec(
        select(Usuario).where(Usuario.username == username)
    ).first()

    if not usuario or not verify_password(password, usuario.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if usuario.role == "admin":
        mfa_code = request.headers.get("X-MFA-Code")
        if mfa_code != "123456":
            raise HTTPException(status_code=401, detail="MFA required")

    # O cliente NÃO pode escolher os próprios privilégios.
    authorized_scopes = ROLE_SCOPES.get(usuario.role, [])

    return {
        "access_token": create_access_token(
            data={
                "sub": usuario.username,
                "id": usuario.id,
                "role": usuario.role,
                "principal_type": "user",
                "scopes": authorized_scopes,
            }
        ),
        "token_type": "bearer",
    }
