$ErrorActionPreference = 'Stop'

$startupMutex = [System.Threading.Mutex]::new($false, 'Local\SIEMAI-DevStack-Startup')
if (-not $startupMutex.WaitOne([TimeSpan]::FromSeconds(60))) {
  throw 'Another SIEM AI startup is still in progress. Wait a moment and run npm.cmd run dev:stack again.'
}

try {
$frontendRoot = Split-Path -Parent $PSScriptRoot
$apiScript = Join-Path $PSScriptRoot 'start-api.ps1'
$runtimeLogRoot = Join-Path $env:TEMP 'siem-ai-dev-logs'
$frontendUrl = 'http://127.0.0.1:5174'
$apiUrl = 'http://127.0.0.1:8000'

function Test-Service([string] $url) {
  try {
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
    return $response.StatusCode -eq 200
  }
  catch {
    return $false
  }
}

function Test-PortInUse([int] $port) {
  return [bool](Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1)
}

function Start-LoggedProcess([string] $name, [string] $filePath, [string[]] $arguments, [string] $workingDirectory) {
  $stdout = Join-Path $runtimeLogRoot "$name-out.log"
  $stderr = Join-Path $runtimeLogRoot "$name-error.log"
  Start-Process -FilePath $filePath -ArgumentList $arguments -WorkingDirectory $workingDirectory `
    -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr | Out-Null
}

New-Item -ItemType Directory -Path $runtimeLogRoot -Force | Out-Null

if (-not (Test-Service "$frontendUrl/src/main.jsx")) {
  if (Test-PortInUse 5174) {
    throw "Port 5174 is occupied by a process that is not serving this Vite app. Stop that process, then run npm.cmd run dev:stack again."
  }
  $node = (Get-Command node.exe -ErrorAction Stop).Source
  Start-LoggedProcess 'frontend' $node @('node_modules/vite/bin/vite.js', '--host', '127.0.0.1') $frontendRoot
}

if (-not (Test-Service "$apiUrl/openapi.json")) {
  if (Test-PortInUse 8000) {
    throw "Port 8000 is occupied by a process that is not serving this SIEM API. Stop that process, then run npm.cmd run dev:stack again."
  }
  Start-LoggedProcess 'api' 'powershell.exe' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $apiScript) $frontendRoot
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

Write-Output "Frontend ready: $frontendUrl"
Write-Output "API ready: $apiUrl"
Write-Output "Logs: $runtimeLogRoot"
}
finally {
  $startupMutex.ReleaseMutex()
  $startupMutex.Dispose()
}
