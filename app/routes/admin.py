from fastapi import APIRouter, Depends, HTTPException, Security
from sqlmodel import Session, select

from app.database.session import get_session
from app.models.domain import Usuario
from app.routes.consultas import get_current_user

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/usuarios")
def listar_usuarios(
    session: Session = Depends(get_session),
    current_user: dict = Security(get_current_user),
):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acesso restrito a administradores")

    usuarios = session.exec(select(Usuario)).all()
    return [
        {
            "id": usuario.id,
            "username": usuario.username,
            "role": usuario.role,
        }
        for usuario in usuarios
    ]
