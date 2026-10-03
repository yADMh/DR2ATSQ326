from fastapi import APIRouter, Depends, HTTPException, status, Security
from sqlmodel import Session
from app.database.session import get_session
from app.models.domain import Consulta
from app.models.schemas import ConsultaCreate, ConsultaResponse
from fastapi.security import SecurityScopes
from app.core.security import oauth2_scheme
from jose import jwt, JWTError
from app.core.config import settings

router = APIRouter()

def get_current_user(security_scopes: SecurityScopes, token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        user_id: int = payload.get("id")
        token_scopes = payload.get("scopes", [])
        if username is None:
            raise HTTPException(status_code=401)
        
        for scope in security_scopes.scopes:
            if scope not in token_scopes:
                raise HTTPException(status_code=403, detail="Permissoes insuficientes para este escopo")
                
        return {"username": username, "role": role, "id": user_id, "scopes": token_scopes}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalido ou expirado")

def check_consulta_ownership(consulta, current_user):
    if current_user["role"] in ["admin", "lab"]:
        return

    if (
        consulta.paciente_id != current_user["id"]
        and consulta.medico_id != current_user["id"]
    ):
        raise HTTPException(
            status_code=403,
            detail="Acesso a prontuario de terceiros bloqueado"
        )

@router.post("/", response_model=ConsultaResponse)
def criar_consulta(consulta_in: ConsultaCreate, session: Session = Depends(get_session), current_user: dict = Security(get_current_user, scopes=["write:consultas"])):
    nova_consulta = Consulta(**consulta_in.model_dump(), paciente_id=current_user["id"])
    session.add(nova_consulta)
    session.commit()
    session.refresh(nova_consulta)
    return nova_consulta

@router.get("/{consulta_id}", response_model=ConsultaResponse)
def ler_consulta(consulta_id: int, session: Session = Depends(get_session), current_user: dict = Security(get_current_user, scopes=["read:consultas"])):
    consulta = session.get(Consulta, consulta_id)
    if not consulta:
        raise HTTPException(status_code=404, detail="Consulta nao encontrada")
    
    check_consulta_ownership(consulta, current_user)
    return consulta
