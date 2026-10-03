from fastapi.testclient import TestClient
from app.main import app

def test_401_sem_token(client):
    response = client.get("/consultas/1")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}

def test_rate_limiting(client, mock_db_session):
    # Simula brute force falho no login
    mock_db_session.exec.return_value.first.return_value = None
    for _ in range(5):
        client.post("/auth/login", data={"username": "hacker", "password": "123"})
    
    # 6a requisicao deve retornar 429
    response = client.post("/auth/login", data={"username": "hacker", "password": "123"})
    assert response.status_code == 429
