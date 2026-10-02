param([string]$NodePath = '')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $NodePath) {
  $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
  if ($nodeCommand) { $NodePath = $nodeCommand.Source }
  else {
    $bundledNode = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe'
    if (Test-Path -LiteralPath $bundledNode) { $NodePath = $bundledNode }
  }
}
if (-not $NodePath -or -not (Test-Path -LiteralPath $NodePath)) { throw 'Install Node.js or pass -NodePath.' }
$vite = Join-Path $projectRoot 'web/node_modules/vite/bin/vite.js'
if (-not (Test-Path -LiteralPath $vite)) { throw 'Run pnpm install in web first.' }
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'web/dist/index.html')) -or
    -not (Test-Path -LiteralPath (Join-Path $projectRoot 'web/dist/docs/index.html'))) {
  throw 'Run pnpm build:all in web once to prepare embedded assets.'
}
if (Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue) {
  throw 'Port 8080 is already in use. Stop the previous development server before starting another.'
}
Push-Location $projectRoot
try {
  # Reuse the installed database and secrets; never remove volumes or reset accounts.
  $postgresId = & docker compose ps --all --quiet postgres
  if ($LASTEXITCODE -ne 0 -or -not $postgresId) { throw 'Initialize the regular Docker installation first (see CONTRIBUTING.md).' }
  & docker start $postgresId
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the existing PostgreSQL container.' }
  $devComposeArgs = @('compose', '-f', 'compose.yaml', '-f', 'compose.dev.yaml')
  $localSources = Join-Path $projectRoot 'lab/.runtime/live/compose.yaml'
  if (Test-Path -LiteralPath $localSources) {
    & (Join-Path $projectRoot 'lab/.runtime/live/start.ps1')
    $devComposeArgs += @('-f', $localSources)
    & docker @devComposeArgs up -d --no-deps --no-build local-gateway
    if ($LASTEXITCODE -ne 0) { throw 'Could not start the local source gateway.' }
  }
  & docker @devComposeArgs up -d --no-deps --no-build app
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the development backend.' }
  Write-Host 'Starting backend; first compilation may take a few minutes...'
  $ready = $false
  for ($attempt = 0; $attempt -lt 180; $attempt++) {
    try {
      $response = Invoke-WebRequest 'http://127.0.0.1:8082/readyz' -UseBasicParsing -TimeoutSec 2
      if ($response.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
    Start-Sleep -Seconds 2
  }
  if (-not $ready) { throw 'Backend did not become ready. Inspect: docker compose logs app' }
  if (Test-Path -LiteralPath $localSources) {
    $maintenance = Join-Path $projectRoot 'lab/.runtime/live/maintenance.ps1'
    $powerShellExe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $powerShellExe -WindowStyle Hidden -ArgumentList @('-NoProfile', '-File', ('"{0}"' -f $maintenance))
  }
  Write-Host 'Grantline development: http://127.0.0.1:8080 (Ctrl+C stops the frontend)'
  Set-Location (Join-Path $projectRoot 'web')
  & $NodePath $vite
} finally { Pop-Location }
