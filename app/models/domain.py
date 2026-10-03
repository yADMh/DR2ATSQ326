from sqlmodel import SQLModel, Field
from typing import Optional
from datetime import datetime

class Usuario(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    role: str

class Consulta(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    paciente_id: int = Field(foreign_key="usuario.id")
    medico_id: int = Field(foreign_key="usuario.id")
    especialidade: str
    data_horario: datetime
    observacoes: Optional[str] = None
