from app.core.security import create_access_token
from app.main import app
from app.routes.consultas import get_current_user


def test_401_sem_token(client):
    response = client.get("/consultas/1")
    assert response.status_code == 401


def test_usuario_nao_admin_recebe_403_na_rota_admin(client):
    app.dependency_overrides[get_current_user] = lambda: {
        "username": "medico1",
        "role": "medico",
        "id": 2,
        "principal_type": "user",
        "scopes": ["read:consultas", "write:consultas"],
    }

    response = client.get("/admin/usuarios")
    assert response.status_code == 403
    app.dependency_overrides.clear()


def test_agenda_exige_autenticacao(client):
    response = client.get("/agenda")
    assert response.status_code == 401


def test_scopes_nao_podem_ser_escolhidos_pelo_cliente(client, mock_db_session):
    from app.models.domain import Usuario
    from app.core.security import get_password_hash

    mock_db_session.exec.return_value.first.return_value = Usuario(
        id=2,
        username="paciente1",
        hashed_password=get_password_hash("123"),
        role="paciente",
    )

    response = client.post(
        "/auth/login",
        data={
            "username": "paciente1",
            "password": "123",
            "scope": "role:admin",
        },
    )

    assert response.status_code == 200
    token = response.json()["access_token"]

    from jose import jwt
    from app.core.config import settings
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

    assert "role:admin" not in payload["scopes"]


def test_rate_limiting(client, mock_db_session):
    mock_db_session.exec.return_value.first.return_value = None

    for _ in range(5):
        client.post("/auth/login", data={"username": "hacker", "password": "123"})

    response = client.post("/auth/login", data={"username": "hacker", "password": "123"})
    assert response.status_code == 429
