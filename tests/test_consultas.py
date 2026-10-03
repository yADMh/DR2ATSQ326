from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from datetime import datetime
from app.main import app
from app.models.domain import Consulta
from app.routes.consultas import get_current_user
from app.core.security import create_access_token

def test_stored_xss_mitigation(client, mock_db_session):
    token_valido = create_access_token(data={"sub": "admin", "role": "admin", "id": 1, "scopes": ["read:consultas", "write:consultas"]})
    payload_xss = "<script>alert('Stored XSS')</script>"
    
    # Simulate DB persistence: When post is called, insert object. When get is called, return object.
    from app.models.domain import Consulta
    mock_consulta = Consulta(id=1, paciente_id=1, medico_id=1, especialidade="Cardiologia", data_horario="2026-10-10T10:00:00", observacoes=payload_xss)
    
    # 1. Inserir o payload via POST
    response_post = client.post(
        "/consultas/",
        json={
            "medico_id": 1, 
            "especialidade": "Cardiologia", 
            "data_horario": "2026-10-10T10:00:00",
            "observacoes": payload_xss
        },
        headers={"Authorization": f"Bearer {token_valido}"}
    )
    assert response_post.status_code == 200
    
    # Setup mock to return the created consulta
    mock_db_session.exec.return_value.all.return_value = [mock_consulta]
    
    # 2. Resgatar as consultas via GET na view da agenda
    response_get = client.get("/agenda")
    
    # 3. Validar Jinja2 autoescape
    assert "&lt;script&gt;alert(&#39;Stored XSS&#39;)&lt;/script&gt;" in response_get.text or "&lt;script&gt;alert('Stored XSS')&lt;/script&gt;" in response_get.text
    assert payload_xss not in response_get.text

def test_200_com_ownership(client, mock_db_session):
    app.dependency_overrides[get_current_user] = lambda: {"username": "med1", "role": "medico", "id": 1, "scopes": ["read:consultas"]}
    
    mock_consulta = Consulta(id=1, paciente_id=2, medico_id=1, especialidade="Cardiologia", data_horario=datetime.now())
    mock_db_session.get.return_value = mock_consulta
    
    response = client.get("/consultas/1")
    assert response.status_code == 200
    assert response.json()["medico_id"] == 1
    app.dependency_overrides.clear()

def test_403_sem_ownership_bola(client, mock_db_session):
    app.dependency_overrides[get_current_user] = lambda: {"username": "pac3", "role": "paciente", "id": 3, "scopes": ["read:consultas"]}
    
    mock_consulta = Consulta(id=1, paciente_id=2, medico_id=1, especialidade="Cardiologia", data_horario=datetime.now())
    mock_db_session.get.return_value = mock_consulta
    
    response = client.get("/consultas/1")
    assert response.status_code == 403
    assert "Acesso a prontuario de terceiros bloqueado" in response.text
    app.dependency_overrides.clear()

def test_403_scope_insuficiente(client, mock_db_session):
    token = create_access_token(data={"sub": "lab1", "role": "lab", "id": 3, "scopes": ["read:consultas"]})
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"medico_id": 1, "especialidade": "Cardiologia", "data_horario": "2026-10-10T10:00:00"}
    
    response = client.post("/consultas/", json=payload, headers=headers)
    assert response.status_code == 403
    assert "Permissoes insuficientes para este escopo" in response.text

def test_422_payload_invalido_extra_forbid(client, mock_db_session):
    token = create_access_token(data={"sub": "med1", "role": "medico", "id": 1, "scopes": ["read:consultas", "write:consultas"]})
    headers = {"Authorization": f"Bearer {token}"}
    
    payload = {
        "medico_id": 1,
        "especialidade": "Cardiologia",
        "data_horario": "2026-10-10T10:00:00",
        "is_admin": True 
    }
    
    response = client.post("/consultas/", json=payload, headers=headers)
    assert response.status_code == 422
    assert "Extra inputs are not permitted" in response.text
