$ErrorActionPreference = 'Stop'

$frontendRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path (Split-Path -Parent $frontendRoot) 'backend'
$python = Join-Path $backendRoot 'venv\Scripts\python.exe'
$databasePath = Join-Path $frontendRoot 'siem-dev.sqlite3'
$apiUrl = 'http://127.0.0.1:8000'

try {
  $response = Invoke-WebRequest -Uri "$apiUrl/openapi.json" -UseBasicParsing -TimeoutSec 2
  $document = $response.Content | ConvertFrom-Json
  if ($response.StatusCode -eq 200 -and $document.info.title -eq 'Next-Gen SIEM API') {
    Write-Output "SIEM API is already running: $apiUrl"
    exit 0
  }
}
catch { }

$netstat = Join-Path $env:SystemRoot 'System32\netstat.exe'
$apiListener = $null
foreach ($line in (& $netstat -ano -p tcp)) {
  if ($line -match '^\s*TCP\s+\S+:8000\s+\S+\s+LISTENING\s+(\d+)\s*$') {
    $apiListener = [int]$Matches[1]
    break
  }
}
if ($apiListener) {
  throw "Port 8000 is already occupied by process $apiListener. Stop that process or use the existing SIEM API; do not start another Uvicorn server."
}

if (-not (Test-Path -LiteralPath $python)) {
  throw "Backend Python environment not found at $python"
}

$databaseUrl = 'sqlite:///' + ($databasePath -replace '\\', '/')
$env:DATABASE_URL = $databaseUrl
# Do not expose development verification codes. Phone OTP must use the
# configured Twilio provider; requests fail clearly if provider config is missing.
$env:AUTH_OTP_DEV_MODE = 'false'
# Password reset can return a one-time link in the local UI if SMTP is blocked.
$env:PASSWORD_RESET_LOCAL_LINK_ENABLED = 'true'
# The local OAuth callback is documented for the GitHub OAuth App. Keep an
# explicitly supplied value, but fill the missing .env value for local runs.
if ([string]::IsNullOrWhiteSpace($env:OAUTH_GITHUB_REDIRECT_URI)) {
  $env:OAUTH_GITHUB_REDIRECT_URI = 'http://127.0.0.1:8000/api/v1/auth/oauth/github/callback'
}

Push-Location $backendRoot
try {
  & $python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}
finally {
  Pop-Location
}
