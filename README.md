# API de Agendamento Médico - HealthTech Segura

API RESTful construída com FastAPI para agendamento de consultas médicas. O projeto aplica os princípios de *Security by Design* com foco em mitigação do OWASP Top 10, englobando autenticação JWT, controle de autorização RBAC + Ownership (Prevenção de BOLA), Rate Limiting contra ataques de força bruta, e validações estritas de entrada/saída.

## Tecnologias e Segurança
- **Framework**: FastAPI (Python 3.11+)
- **ORM & Banco de Dados**: SQLModel / SQLite (com injeção parametrizada para prevenir SQLi)
- **Validação**: Pydantic (`extra='forbid'`, whitelisting e regex)
- **Autenticação**: OAuth2PasswordBearer com tokens JWT assinados via `python-jose` e senhas cifradas com `bcrypt`.
- **Prevenção contra XSS**: Templates HTML renderizados com Auto-escape nativo do `Jinja2`.
- **Proteção de Camada (Rede)**: Middleware para limitação de taxa (`slowapi`), *Security Headers* (HSTS, Anti-clickjacking) e `CORS Allowlist`.
- **DevSecOps**: Workflow no GitHub Actions com SAST (`Bandit`), SCA (`Safety`) e DAST (`OWASP ZAP`), suportado por suíte de testes em `pytest`.

---

## Pré-requisitos
- **Python 3.11** ou superior
- Instalação global do pacote `virtualenv` (recomendado)

---

## Como Executar a Aplicação Localmente

**1. Clone o projeto e crie o ambiente virtual**
```bash
py -3.11 -m venv venv
```

**2. Ative o ambiente virtual**
- No Linux/MacOS:
```bash
source venv/bin/activate
```
- No Windows (PowerShell):
```powershell
.\venv\Scripts\activate
```

**3. Instale as dependências**
```bash
pip install -r requirements.txt
```
> *Nota de Compatibilidade (Passlib & Bcrypt):* Caso utilize versões muito recentes do ecossistema bcrypt, se ocorrer incompatibilidade ao gerar o hash das senhas, certifique-se de instalar o pacote limitando a versão: `pip install "bcrypt<4.0.0"`.

**4. Configure as variáveis de ambiente**
Faça uma cópia do arquivo `.env.example` renomeando-o para `.env` na raiz do projeto:
- No Linux/MacOS: `cp .env.example .env`
- No Windows: `copy .env.example .env`

**5. Suba o servidor de desenvolvimento**
```bash
uvicorn app.main:app --reload
```

**6. (Opcional) Popule o banco com dados de teste (Seeding)**
Para criar usuários iniciais (`medico1`, `admin`, `paciente1`) e testar via Swagger, você pode criar um script de seeding usando `session.exec(select(Usuario))` e rodar:
```bash
python seed.py
```


A API estará rodando em `http://localhost:8000`. O banco de dados SQLite (`agendamento.db`) será gerado automaticamente na primeira execução.

---

## Como Acessar a Documentação e Testar Manualmente

- **Swagger UI Interativo**: Acesse [http://localhost:8000/docs](http://localhost:8000/docs). Lá você pode testar o endpoint de autenticação `/auth/login` e o CRUD restrito de `/consultas`.
- **ReDocs**: Acesse [http://localhost:8000/redoc](http://localhost:8000/redoc).
- **Endpoint Renderizado com Jinja2**: Teste a mitigação de XSS através do navegador acessando [http://localhost:8000/agenda?paciente_nome=Teste](http://localhost:8000/agenda?paciente_nome=Teste).

---

## Como Executar a Suíte de Testes (Segurança/pytest)

O projeto possui uma série de testes unitários focados nas políticas de segurança (Mocking, BOLA, XSS, Autenticação, Extra Forbid Payload).

Para executar os testes automatizados, certifique-se de que o ambiente virtual está ativo e digite:
```bash
python -m pytest -v
```

Los resultados exibirão a cobertura de segurança mapeada contra o *Threat Model* (vide `RELATORIO_TECNICO.md`).


### Autenticação no Swagger

O Swagger usa o esquema `BearerAuth` para facilitar os testes manuais. Faça login em `POST /auth/login` com MFA quando necessário, copie o `access_token`, clique em **Authorize** e cole somente o JWT. O servidor continua validando assinatura, expiração, papel, escopos e ownership; o uso do Bearer no Swagger não concede privilégios adicionais.
