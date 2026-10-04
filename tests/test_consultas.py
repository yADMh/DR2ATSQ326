from datetime import datetime

from app.core.security import create_access_token
from app.main import app
from app.models.domain import Consulta
from app.routes.consultas import get_current_user


def token(user_id, username, role, scopes):
    return create_access_token(
        data={
            "sub": username,
            "id": user_id,
            "role": role,
            "principal_type": "user",
            "scopes": scopes,
        }
    )


def test_stored_xss_mitigation(client, mock_db_session):
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "admin",
        "role": "admin",
        "id": 1,
        "principal_type": "user",
        "scopes": ["read:consultas", "write:consultas", "role:admin"],
    }

    payload_xss = "<script>alert('Stored XSS')</script>"
    mock_db_session.get.return_value = Consulta(
        id=1,
        paciente_id=1,
        medico_id=1,
        especialidade="Cardiologia",
        data_horario=datetime.fromisoformat("2026-10-10T10:00:00"),
        observacoes=payload_xss,
    )
    response = client.get("/agenda")

    assert response.status_code == 200
    assert "&lt;script&gt;alert(&#39;Stored XSS&#39;)&lt;/script&gt;" in response.text
    assert payload_xss not in response.text
    app.dependency_overrides.clear()


def test_200_com_ownership(client, mock_db_session):
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "med1",
        "role": "medico",
        "id": 1,
        "principal_type": "user",
        "scopes": ["read:consultas"],
    }

    mock_consulta = Consulta(
        id=1,
        paciente_id=2,
        medico_id=1,
        especialidade="Cardiologia",
        data_horario=datetime.now(),
    )
    mock_db_session.get.return_value = mock_consulta

    response = client.get("/consultas/1")
    assert response.status_code == 200
    assert response.json()["medico_id"] == 1
    app.dependency_overrides.clear()


def test_403_sem_ownership_bola(client, mock_db_session):
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "pac3",
        "role": "paciente",
        "id": 3,
        "principal_type": "user",
        "scopes": ["read:consultas"],
    }

    mock_consulta = Consulta(
        id=1,
        paciente_id=2,
        medico_id=1,
        especialidade="Cardiologia",
        data_horario=datetime.now(),
    )
    mock_db_session.get.return_value = mock_consulta

    response = client.get("/consultas/1")
    assert response.status_code == 403
    app.dependency_overrides.clear()


def test_m2m_nao_bypassa_ownership(client, mock_db_session):
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "m2m_client",
        "role": "lab",
        "id": None,
        "principal_type": "m2m",
        "scopes": ["read:consultas"],
    }

    mock_db_session.get.return_value = Consulta(
        id=1,
        paciente_id=2,
        medico_id=1,
        especialidade="Cardiologia",
        data_horario=datetime.now(),
    )

    response = client.get("/consultas/1")
    assert response.status_code == 403
    app.dependency_overrides.clear()


def test_crud_list_update_delete_routes_exist(client, mock_db_session):
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "admin",
        "role": "admin",
        "id": 1,
        "principal_type": "user",
        "scopes": ["read:consultas", "write:consultas", "role:admin"],
    }

    consulta = Consulta(
        id=1,
        paciente_id=2,
        medico_id=1,
        especialidade="Cardiologia",
        data_horario=datetime.now(),
    )
    mock_db_session.exec.return_value.all.return_value = [consulta]
    mock_db_session.get.return_value = consulta

    assert client.get("/consultas/").status_code == 200
    assert client.put(
        "/consultas/1",
        json={"observacoes": "Atualizada"},
    ).status_code == 200
    assert client.delete("/consultas/1").status_code == 204
    app.dependency_overrides.clear()


def test_422_payload_invalido_extra_forbid(client, mock_db_session):
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "med1",
        "role": "medico",
        "id": 1,
        "principal_type": "user",
        "scopes": ["read:consultas", "write:consultas"],
    }

    payload = {
        "paciente_id": 2,
        "medico_id": 1,
        "especialidade": "Cardiologia",
        "data_horario": "2026-10-10T10:00:00",
        "is_admin": True,
    }

    response = client.post("/consultas/", json=payload)
    assert response.status_code == 422
    app.dependency_overrides.clear()
