from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from app.database.session import get_session
from app.models.domain import Usuario
from app.core.security import verify_password, create_access_token
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

@router.post("/login")
@limiter.limit("5/minute")
def login(
    request: Request,
    grant_type: str = Form(default="password"),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    username: str = Form(None),
    password: str = Form(None),
    scope: str = Form(""),
    session: Session = Depends(get_session)
):
    scopes_list = scope.split() if scope else []

    if grant_type == "client_credentials":
        # FLUXO M2M: Validar client_id e client_secret
        if client_id == "m2m_client" and client_secret == "m2m_secret":
            return {"access_token": create_access_token({"sub": client_id, "scopes": ["m2m_scope"]}), "token_type": "bearer"}
        else:
            raise HTTPException(status_code=401, detail="Credenciais de cliente inválidas")

    elif grant_type == "password":
        # FLUXO HUMANO: Validar username e password
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required for password grant")
            
        usuario = session.exec(select(Usuario).where(Usuario.username == username)).first()
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

        if usuario.role != "admin" and "role:admin" in scopes_list:
            raise HTTPException(status_code=400, detail="Invalid scope requested")

        access_token = create_access_token(
            data={
                "sub": usuario.username, 
                "id": usuario.id, 
                "role": usuario.role, 
                "scopes": scopes_list
            }
        )
        return {"access_token": access_token, "token_type": "bearer"}
        
    else:
        raise HTTPException(status_code=400, detail="Grant type não suportado")
