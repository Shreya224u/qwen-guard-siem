$ErrorActionPreference = 'Stop'

$startupMutex = [System.Threading.Mutex]::new($false, 'Local\SIEMAI-DevStack-Startup')
if (-not $startupMutex.WaitOne([TimeSpan]::FromSeconds(60))) {
  throw 'Another SIEM AI startup is still in progress. Wait a moment and run npm.cmd run dev:stack again.'
}

try {
$frontendRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path (Split-Path -Parent $frontendRoot) 'backend'
$apiPython = Join-Path $backendRoot 'venv\Scripts\python.exe'
$runtimeLogRoot = Join-Path $env:TEMP 'siem-ai-dev-logs'
$frontendUrl = 'http://127.0.0.1:5174'
$apiUrl = 'http://127.0.0.1:8000'
$apiMarkerPath = Join-Path $runtimeLogRoot 'api-process.json'

function Test-Service([string] $url) {
  try {
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
    return $response.StatusCode -eq 200
  }
  catch {
    return $false
  }
}

function Test-SiemApi {
  try {
    $response = Invoke-WebRequest -Uri "$apiUrl/openapi.json" -UseBasicParsing -TimeoutSec 2
    $document = $response.Content | ConvertFrom-Json
    return $response.StatusCode -eq 200 -and $document.info.title -eq 'Next-Gen SIEM API'
  }
  catch {
    return $false
  }
}

function Get-ListeningProcess([int] $port) {
  $netstat = Join-Path $env:SystemRoot 'System32\netstat.exe'
  foreach ($line in (& $netstat -ano -p tcp)) {
    if ($line -match "^\s*TCP\s+\S+:$port\s+\S+\s+LISTENING\s+(\d+)\s*$") {
      return Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue
    }
  }
  return $null
}

function Test-PortInUse([int] $port) {
  return [bool](Get-ListeningProcess $port)
}

function Start-LoggedProcess([string] $name, [string] $filePath, [string[]] $arguments, [string] $workingDirectory) {
  $stdout = Join-Path $runtimeLogRoot "$name-out.log"
  $stderr = Join-Path $runtimeLogRoot "$name-error.log"
  return Start-Process -FilePath $filePath -ArgumentList $arguments -WorkingDirectory $workingDirectory `
    -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
}

New-Item -ItemType Directory -Path $runtimeLogRoot -Force | Out-Null

if (-not (Test-Service "$frontendUrl/src/main.jsx")) {
  if (Test-PortInUse 5174) {
    throw "Port 5174 is occupied by a process that is not serving this Vite app. Stop that process, then run npm.cmd run dev:stack again."
  }
  $node = (Get-Command node.exe -ErrorAction Stop).Source
  Start-LoggedProcess 'frontend' $node @('node_modules/vite/bin/vite.js', '--host', '127.0.0.1') $frontendRoot | Out-Null
}

if (Test-Service "$apiUrl/openapi.json") {
  $apiProcess = Get-ListeningProcess 8000
  $managedApi = $false
  if ($apiProcess -and (Test-Path -LiteralPath $apiMarkerPath)) {
    try {
      $marker = Get-Content -LiteralPath $apiMarkerPath -Raw | ConvertFrom-Json
      $managedApi = [int]$marker.processId -eq $apiProcess.Id -and
        [long]$marker.startTimeTicks -eq $apiProcess.StartTime.ToUniversalTime().Ticks
    }
    catch {
      $managedApi = $false
    }
  }
  if ($apiProcess -and -not $managedApi) {
    if (-not (Test-SiemApi)) {
      throw 'Port 8000 is serving another application. Stop it manually before starting the SIEM API.'
    }
    Write-Output 'Restarting the existing SIEM API through the project launcher.'
    Stop-Process -Id $apiProcess.Id -Force
    $stopDeadline = (Get-Date).AddSeconds(10)
    while ((Get-ListeningProcess 8000) -and (Get-Date) -lt $stopDeadline) {
      Start-Sleep -Milliseconds 250
    }
  }
}

if (-not (Test-Service "$apiUrl/openapi.json")) {
  if (Test-PortInUse 8000) {
    throw "Port 8000 is occupied by a process that is not serving this SIEM API. Stop that process, then run npm.cmd run dev:stack again."
  }
  if (-not (Test-Path -LiteralPath $apiPython)) {
    throw "Backend Python environment not found at $apiPython. Create it and install backend\requirements.txt first."
  }
  $databasePath = Join-Path $frontendRoot 'siem-dev.sqlite3'
  $env:DATABASE_URL = 'sqlite:///' + ($databasePath -replace '\\', '/')
  $env:AUTH_OTP_DEV_MODE = 'false'
  $env:PASSWORD_RESET_LOCAL_LINK_ENABLED = 'true'
  if ([string]::IsNullOrWhiteSpace($env:OAUTH_GITHUB_REDIRECT_URI)) {
    $env:OAUTH_GITHUB_REDIRECT_URI = 'http://127.0.0.1:8000/api/v1/auth/oauth/github/callback'
  }
  $apiProcess = Start-LoggedProcess 'api' $apiPython @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000') $backendRoot
}

$deadline = (Get-Date).AddSeconds(45)
do {
  $frontendReady = Test-Service "$frontendUrl/src/main.jsx"
  $apiReady = Test-Service "$apiUrl/openapi.json"
  if ($frontendReady -and $apiReady) { break }
  Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)

if (-not $frontendReady -or -not $apiReady) {
  $logFiles = @((Join-Path $runtimeLogRoot 'frontend-error.log'), (Join-Path $runtimeLogRoot 'api-error.log'))
  foreach ($logFile in $logFiles) {
    if (Test-Path -LiteralPath $logFile) {
      Write-Error "Startup log ($logFile):`n$((Get-Content -LiteralPath $logFile -Tail 40) -join "`n")" -ErrorAction Continue
    }
  }
  throw 'The frontend and API did not both become ready within 45 seconds.'
}

$apiProcess = Get-ListeningProcess 8000
if ($apiProcess) {
  @{ processId = $apiProcess.Id; startTimeTicks = $apiProcess.StartTime.ToUniversalTime().Ticks } |
    ConvertTo-Json | Set-Content -LiteralPath $apiMarkerPath -Encoding utf8
}

Write-Output "Frontend ready: $frontendUrl"
Write-Output "API ready: $apiUrl"
Write-Output "Logs: $runtimeLogRoot"
}
finally {
  $startupMutex.ReleaseMutex()
  $startupMutex.Dispose()
}
