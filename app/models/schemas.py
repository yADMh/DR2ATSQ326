from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Optional

class ConsultaCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    medico_id: int
    especialidade: str = Field(..., pattern="^(Cardiologia|Ortopedia|Clinica Geral)$")
    data_horario: datetime
    observacoes: Optional[str] = Field(None, max_length=500)

class ConsultaResponse(BaseModel):
    id: int
    paciente_id: int
    medico_id: int
    especialidade: str
    data_horario: datetime
    
    model_config = ConfigDict(from_attributes=True)
