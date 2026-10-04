from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ConsultaCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    paciente_id: Optional[int] = None
    medico_id: Optional[int] = None
    especialidade: str = Field(
        ...,
        pattern="^(Cardiologia|Ortopedia|Clinica Geral)$",
    )
    data_horario: datetime
    observacoes: Optional[str] = Field(None, max_length=500)


class ConsultaUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    paciente_id: Optional[int] = None
    medico_id: Optional[int] = None
    especialidade: Optional[str] = Field(
        None,
        pattern="^(Cardiologia|Ortopedia|Clinica Geral)$",
    )
    data_horario: Optional[datetime] = None
    observacoes: Optional[str] = Field(None, max_length=500)


class ConsultaResponse(BaseModel):
    id: int
    paciente_id: int
    medico_id: int
    especialidade: str
    data_horario: datetime
    observacoes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
