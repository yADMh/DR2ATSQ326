from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.routes import auth, consultas
from app.database.session import engine
from sqlmodel import SQLModel
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.routes.auth import limiter
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

SQLModel.metadata.create_all(engine)

app = FastAPI(title="Agendamento API - HealthTech Segura")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://frontend-clinica.com", "https://lab-parceiro.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(consultas.router, prefix="/consultas", tags=["Consultas"])

templates = Jinja2Templates(directory="app/templates")

from sqlmodel import Session, select
from app.database.session import get_session
from fastapi import Depends
from app.models.domain import Consulta

@app.get("/agenda", response_class=HTMLResponse)
def read_agenda(request: Request, session: Session = Depends(get_session)):
    consultas = session.exec(select(Consulta)).all()
    return templates.TemplateResponse("agenda.html", {"request": request, "consultas": consultas})
