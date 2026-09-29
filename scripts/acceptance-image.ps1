param([string]$Image='grantline:candidate',[string]$Platform='linux/arm64',[int]$Port=8085,[string]$ComposeFile='')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
if(-not $ComposeFile){$ComposeFile=Join-Path $root 'compose.yaml'}
$docker='C:\Program Files\Docker\Docker\resources\bin\docker.exe'
$project='grantline-image-'+[guid]::NewGuid().ToString('N').Substring(0,10)
$override=Join-Path $root "bin/$project.yaml"
$previous=@{GRANTLINE_IMAGE=$env:GRANTLINE_IMAGE;GRANTLINE_PORT=$env:GRANTLINE_PORT;GRANTLINE_PUBLIC_URL=$env:GRANTLINE_PUBLIC_URL}
try {
  if($Platform -notin @('linux/amd64','linux/arm64')){throw 'Unsupported platform'}
  "services:`n  init:`n    platform: $Platform`n  migrate:`n    platform: $Platform`n  app:`n    platform: $Platform" | Set-Content -LiteralPath $override
  $env:GRANTLINE_IMAGE=$Image
  $env:GRANTLINE_PORT="$Port"
  $env:GRANTLINE_PUBLIC_URL="http://127.0.0.1:$Port"
  & $docker compose -p $project -f $ComposeFile -f $override up -d --wait --wait-timeout 180
  if($LASTEXITCODE -ne 0){throw 'Image clean installation failed'}
  $result=Invoke-RestMethod "$env:GRANTLINE_PUBLIC_URL/api/v1/status"
  if(-not $result.setup_required){throw 'Clean installation did not require Owner setup'}
  & $docker compose -p $project -f $ComposeFile -f $override exec -T app grantline version
  if($LASTEXITCODE -ne 0){throw 'Runtime version check failed'}
  "PASS: $Platform init, migration, server readiness and first Owner setup state."
} finally {
  # This project and its volumes were created only for this acceptance run.
  & $docker compose -p $project -f $ComposeFile -f $override down --volumes 2>$null | Out-Null
  Remove-Item -LiteralPath $override -Force -ErrorAction SilentlyContinue
  $env:GRANTLINE_IMAGE=$previous.GRANTLINE_IMAGE
  $env:GRANTLINE_PORT=$previous.GRANTLINE_PORT
  $env:GRANTLINE_PUBLIC_URL=$previous.GRANTLINE_PUBLIC_URL
}
