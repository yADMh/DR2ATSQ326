from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import SecurityScopes
from jose import JWTError, jwt
from sqlmodel import Session, select

from app.core.config import settings
from app.core.security import bearer_scheme
from app.database.session import get_session
from app.models.domain import Consulta, Usuario
from app.models.schemas import ConsultaCreate, ConsultaResponse, ConsultaUpdate

router = APIRouter()


def get_current_user(
    security_scopes: SecurityScopes,
    bearer_credentials = Depends(bearer_scheme),
):
    authenticate_value = "Bearer"

    if not bearer_credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": authenticate_value},
        )

    token = bearer_credentials.credentials
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido ou expirado",
            headers={"WWW-Authenticate": authenticate_value},
        )

    username = payload.get("sub")
    role = payload.get("role")
    user_id = payload.get("id")
    principal_type = payload.get("principal_type", "user")
    token_scopes = payload.get("scopes", [])

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": authenticate_value},
        )

    for required_scope in security_scopes.scopes:
        if required_scope not in token_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissoes insuficientes para este escopo",
            )

    return {
        "username": username,
        "role": role,
        "id": user_id,
        "principal_type": principal_type,
        "scopes": token_scopes,
    }


def get_consulta_or_404(consulta_id: int, session: Session) -> Consulta:
    consulta = session.get(Consulta, consulta_id)
    if not consulta:
        raise HTTPException(status_code=404, detail="Consulta nao encontrada")
    return consulta


def check_consulta_ownership(consulta: Consulta, current_user: dict):
    # Apenas usuários humanos relacionados à consulta ou admin podem acessá-la.
    # M2M possui endpoint próprio e nunca passa por este bypass.
    if current_user["principal_type"] == "m2m":
        raise HTTPException(
            status_code=403,
            detail="Cliente M2M deve usar o endpoint de integração",
        )

    if current_user["role"] == "admin":
        return

    if (
        consulta.paciente_id != current_user["id"]
        and consulta.medico_id != current_user["id"]
    ):
        raise HTTPException(
            status_code=403,
            detail="Acesso a prontuario de terceiros bloqueado",
        )


def get_user(session: Session, user_id: int | None) -> Usuario:
    if not user_id:
        raise HTTPException(status_code=422, detail="ID de usuário obrigatório")
    usuario = session.get(Usuario, user_id)
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return usuario


@router.post("/", response_model=ConsultaResponse)
def criar_consulta(
    consulta_in: ConsultaCreate,
    session: Session = Depends(get_session),
    current_user: dict = Security(
        get_current_user,
        scopes=["write:consultas"],
    ),
):
    if current_user["role"] == "medico":
        paciente_id = consulta_in.paciente_id
        medico_id = current_user["id"]
    elif current_user["role"] == "paciente":
        paciente_id = current_user["id"]
        medico_id = consulta_in.medico_id
    elif current_user["role"] == "admin":
        paciente_id = consulta_in.paciente_id
        medico_id = consulta_in.medico_id
    else:
        raise HTTPException(status_code=403, detail="Perfil não autorizado")

    get_user(session, paciente_id)
    get_user(session, medico_id)

    nova_consulta = Consulta(
        paciente_id=paciente_id,
        medico_id=medico_id,
        especialidade=consulta_in.especialidade,
        data_horario=consulta_in.data_horario,
        observacoes=consulta_in.observacoes,
    )
    session.add(nova_consulta)
    session.commit()
    session.refresh(nova_consulta)
    return nova_consulta


@router.get("/", response_model=list[ConsultaResponse])
def listar_consultas(
    session: Session = Depends(get_session),
    current_user: dict = Security(
        get_current_user,
        scopes=["read:consultas"],
    ),
):
    statement = select(Consulta)

    if current_user["role"] != "admin":
        statement = statement.where(
            (Consulta.paciente_id == current_user["id"])
            | (Consulta.medico_id == current_user["id"])
        )

    return session.exec(statement).all()


@router.get("/{consulta_id}", response_model=ConsultaResponse)
def ler_consulta(
    consulta_id: int,
    session: Session = Depends(get_session),
    current_user: dict = Security(
        get_current_user,
        scopes=["read:consultas"],
    ),
):
    consulta = get_consulta_or_404(consulta_id, session)
    check_consulta_ownership(consulta, current_user)
    return consulta


@router.put("/{consulta_id}", response_model=ConsultaResponse)
def atualizar_consulta(
    consulta_id: int,
    consulta_in: ConsultaUpdate,
    session: Session = Depends(get_session),
    current_user: dict = Security(
        get_current_user,
        scopes=["write:consultas"],
    ),
):
    consulta = get_consulta_or_404(consulta_id, session)
    check_consulta_ownership(consulta, current_user)

    if current_user["role"] == "medico":
        # Médico não pode transferir a consulta para outro médico.
        if consulta_in.medico_id is not None and consulta_in.medico_id != current_user["id"]:
            raise HTTPException(status_code=403, detail="Médico não pode alterar o responsável")
        consulta.medico_id = current_user["id"]

    if consulta_in.paciente_id is not None:
        get_user(session, consulta_in.paciente_id)
        consulta.paciente_id = consulta_in.paciente_id

    if consulta_in.medico_id is not None:
        get_user(session, consulta_in.medico_id)
        consulta.medico_id = consulta_in.medico_id

    if consulta_in.especialidade is not None:
        consulta.especialidade = consulta_in.especialidade
    if consulta_in.data_horario is not None:
        consulta.data_horario = consulta_in.data_horario
    if consulta_in.observacoes is not None:
        consulta.observacoes = consulta_in.observacoes

    session.add(consulta)
    session.commit()
    session.refresh(consulta)
    return consulta


@router.delete("/{consulta_id}", status_code=204)
def excluir_consulta(
    consulta_id: int,
    session: Session = Depends(get_session),
    current_user: dict = Security(
        get_current_user,
        scopes=["write:consultas"],
    ),
):
    consulta = get_consulta_or_404(consulta_id, session)
    check_consulta_ownership(consulta, current_user)

    session.delete(consulta)
    session.commit()
