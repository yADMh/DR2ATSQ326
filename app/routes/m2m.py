from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Security
from sqlmodel import Session, select

from app.database.session import get_session
from app.models.domain import Consulta
from app.routes.consultas import get_current_user

router = APIRouter(prefix="/m2m", tags=["M2M"])


@router.get("/agenda/disponibilidade")
def consultar_disponibilidade(
    session: Session = Depends(get_session),
    current_user: dict = Security(get_current_user, scopes=["m2m_scope"]),
):
    if current_user["principal_type"] != "m2m":
        raise HTTPException(status_code=403, detail="Endpoint exclusivo para cliente M2M")

    # Endpoint exclusivo da integração. O token M2M não acessa prontuários
    # nem usa ownership de usuários humanos.
    consultas = session.exec(
        select(Consulta).where(
            Consulta.data_horario >= datetime.now(timezone.utc).replace(tzinfo=None)
        )
    ).all()

    # Como o modelo não possui tabela de "slots", consideramos horários
    # ocupados e retornamos somente a agenda mínima para integração.
    return {
        "ocupados": [
            {
                "data_horario": consulta.data_horario,
                "especialidade": consulta.especialidade,
            }
            for consulta in consultas
        ]
    }
