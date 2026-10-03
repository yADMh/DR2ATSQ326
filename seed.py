from sqlmodel import Session
from app.database.session import engine
from app.models.domain import Usuario, Consulta
from app.core.security import get_password_hash
from datetime import datetime

def seed_db():
    with Session(engine) as session:
        # Create a test admin user
        admin = Usuario(username="admin", hashed_password=get_password_hash("123"), role="admin")
        medico1 = Usuario(username="medico1", hashed_password=get_password_hash("123"), role="medico")
        paciente1 = Usuario(username="paciente1", hashed_password=get_password_hash("123"), role="paciente")
        lab1 = Usuario(username="m2m_client", hashed_password=get_password_hash("m2m_secret"), role="lab")
        
        session.add(admin)
        session.add(medico1)
        session.add(paciente1)
        session.add(lab1)
        session.commit()
        print("Database seeded with test users!")

if __name__ == "__main__":
    seed_db()
