# SIEM AI

SIEM AI is a local development app with a React/Vite frontend and a FastAPI backend.

## Requirements

- Python 3.12
- Node.js and npm
- Windows PowerShell for the included one-command development launcher

## First-time setup (Windows)

From the repository root, run:

```powershell
python -m venv backend\venv
backend\venv\Scripts\python.exe -m pip install --upgrade pip
backend\venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Copy-Item backend\.env.example backend\.env
Copy-Item frontend\.env.example frontend\.env.local
Set-Location frontend
npm ci
```

The local launcher uses `frontend\siem-dev.sqlite3`, created automatically on the first API start. It does not require a local PostgreSQL or Redis service.

## Configure sign-in providers

Google and GitHub OAuth credentials are optional for starting the app. To enable a provider, put its client ID and secret in `backend\.env` and register the callback URL shown there with that provider. Never commit `.env` files or paste their secret values into source files.

OAuth callback processing needs outbound HTTPS access from the backend to the selected provider. If the network or endpoint security policy blocks that connection, provider sign-in cannot complete until that policy permits it.

## Run the app

From the `frontend` directory:

```powershell
npm run dev:stack
```

Open <http://127.0.0.1:5174>. The API is at <http://127.0.0.1:8000>; API logs are written under the Windows temporary directory in `siem-ai-dev-logs`.

To stop the stack, close the PowerShell terminal that started it or stop its frontend and API processes.
