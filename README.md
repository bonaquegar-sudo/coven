# Coven

Equipo de agentes de IA que audita tu repositorio local con una interfaz tipo Slack/Discord. BYOK: usa tu API key o directamente tu suscripción de Claude, ChatGPT o Gemini (sin API key).

| Agente | Canal | Qué hace |
|---|---|---|
| TechLead | #general | Reparte el trabajo y resume |
| CodeScout | #arquitectura | Mapa técnico, dependencias (OSV.dev), secretos, rutas API |
| Reviewer | #auditoria | SAST (semgrep o reglas nativas) y revisión manual OWASP |
| QARunner | #tests | Tests del proyecto y pruebas DAST **solo contra localhost** |
| Fixer | #parches | Parches para los hallazgos confirmados |

Cada hallazgo (`COVEN-NNN`) pasa por DETECTED → CONFIRMED_BY_QA → PATCHED → VERIFIED (o FALSE_POSITIVE). Los secretos se muestran siempre enmascarados.

## Arrancar

```bash
# backend (Python 3.11+)
cd backend
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # Linux/macOS: .venv/bin/pip
.venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# frontend
cd frontend
npm install && npm run dev   # http://localhost:5173
```

Proveedores: `openrouter`, `anthropic`, `openai`, `gemini`, `ollama` con API key, o por suscripción a través de los CLI oficiales ya logueados: Claude Code (`claude`), Codex CLI (`codex`) o Antigravity (`agy`).

## Tests

```bash
cd backend
.venv/Scripts/python test_appsec.py      # escáneres + registro de hallazgos (consulta OSV en vivo)
.venv/Scripts/python test_smoke.py       # grafo de agentes con un LLM simulado
COVEN_LIVE_SUBS=1 .venv/Scripts/python test_subscriptions.py   # suscripciones reales
```

Probado de punta a punta contra [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) en local.

> Las pruebas DAST mandan GET/HEAD/OPTIONS/POST a tu app local: un POST puede crear datos (por ejemplo, usuarios de prueba). Úsalo contra entornos de desarrollo, nunca contra producción.

## Capturas (auditoría de Juice Shop con la suscripción de Claude)

| | |
|---|---|
| ![Proveedor por suscripción](docs/screenshots/01-suscripcion.png) | ![Inicio](docs/screenshots/02-inicio.png) |
| ![Resumen del TechLead](docs/screenshots/04-general.png) | ![Auditoría](docs/screenshots/06-auditoria.png) |
| ![Mapa técnico](docs/screenshots/05-arquitectura.png) | ![QA y consola DAST](docs/screenshots/07-tests-consola.png) |
