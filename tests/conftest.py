import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from app.main import app
from app.database.session import get_session

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def mock_db_session():
    session = MagicMock()
    app.dependency_overrides[get_session] = lambda: session
    yield session
    app.dependency_overrides.clear()
