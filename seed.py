from datetime import datetime

from sqlmodel import Session, select

from app.core.security import get_password_hash
from app.database.session import engine
from app.models.domain import Consulta, Usuario


def get_or_create_user(session, username, password, role):
    user = session.exec(
        select(Usuario).where(Usuario.username == username)
    ).first()

    if user:
        # Garante que a senha e a role estejam corretas
        user.hashed_password = get_password_hash(password)
        user.role = role
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    user = Usuario(
        username=username,
        hashed_password=get_password_hash(password),
        role=role,
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


def seed_db():
    with Session(engine) as session:

        # =========================
        # USUÁRIOS
        # =========================

        admin = get_or_create_user(
            session,
            "admin",
            "123",
            "admin",
        )

        medico1 = get_or_create_user(
            session,
            "medico1",
            "123",
            "medico",
        )

        medico2 = get_or_create_user(
            session,
            "medico2",
            "123",
            "medico",
        )

        paciente1 = get_or_create_user(
            session,
            "paciente1",
            "123",
            "paciente",
        )

        paciente2 = get_or_create_user(
            session,
            "paciente2",
            "123",
            "paciente",
        )

        # =========================
        # CONSULTAS
        # =========================

        consultas_existentes = session.exec(
            select(Consulta)
        ).all()

        if not consultas_existentes:

            consulta1 = Consulta(
                paciente_id=paciente1.id,
                medico_id=medico1.id,
                especialidade="Cardiologia",
                data_hora=datetime(2026, 10, 10, 10, 0),
            )

            consulta2 = Consulta(
                paciente_id=paciente2.id,
                medico_id=medico2.id,
                especialidade="Neurologia",
                data_hora=datetime(2026, 10, 11, 14, 30),
            )

            consulta3 = Consulta(
                paciente_id=paciente1.id,
                medico_id=medico2.id,
                especialidade="Dermatologia",
                data_hora=datetime(2026, 10, 12, 9, 0),
            )

            session.add(consulta1)
            session.add(consulta2)
            session.add(consulta3)

            session.commit()

            print("Consultas criadas.")

        else:
            print("Consultas já existem. Nenhuma nova consulta foi criada.")

        # =========================
        # RESULTADO
        # =========================

        print("\n=== DATABASE SEEDED ===")
        print(f"admin     -> ID {admin.id} | senha: 123 | role: admin")
        print(f"medico1   -> ID {medico1.id} | senha: 123 | role: medico")
        print(f"medico2   -> ID {medico2.id} | senha: 123 | role: medico")
        print(f"paciente1 -> ID {paciente1.id} | senha: 123 | role: paciente")
        print(f"paciente2 -> ID {paciente2.id} | senha: 123 | role: paciente")

        print("\nM2M:")
        print("As credenciais M2M continuam sendo lidas somente do .env.")


if __name__ == "__main__":
    seed_db()