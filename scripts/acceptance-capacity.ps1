$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$docker='C:\Program Files\Docker\Docker\resources\bin\docker.exe'
$suffix=[guid]::NewGuid().ToString('N').Substring(0,10)
$name="grantline-capacity-$suffix"
$network="grantline-capacity-net-$suffix"
$password=[guid]::NewGuid().ToString('N')
try {
  & $docker network create --internal $network | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Cannot create isolated capacity network'}
  & $docker run -d --name $name --network $network --cpus=2 --memory=2g --memory-swap=2g --env POSTGRES_USER=grantline --env POSTGRES_DB=grantline --env "POSTGRES_PASSWORD=$password" postgres:17-alpine | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Cannot start disposable database'}
  for($i=0;$i -lt 30;$i++){& $docker exec $name pg_isready -U grantline -d grantline 2>$null | Out-Null; if($LASTEXITCODE -eq 0){break}; Start-Sleep -Seconds 1}
  if($LASTEXITCODE -ne 0){throw 'Database not ready'}
  'Reference resource caps: application 2 CPU / 6 GiB; PostgreSQL 2 CPU / 2 GiB; total 4 CPU / 8 GiB. Shared Windows Docker Desktop host.'
  & $docker run --rm --network $network --cpus=2 --memory=6g --memory-swap=6g --mount "type=bind,source=$root\bin,target=/tests,readonly" --env "GRANTLINE_TEST_DATABASE_URL=postgres://grantline:${password}@${name}:5432/grantline?sslmode=disable" --env GRANTLINE_TEST_CAPACITY=1 --entrypoint /tests/platform.test grantline:development '-test.run=^TestDatabaseCapacityAndReportRoundTrip$' '-test.v'
  if($LASTEXITCODE -ne 0){throw 'Capacity acceptance failed'}
} finally {
  # Only disposable resources created by this invocation.
  & $docker rm -f -v $name 2>$null | Out-Null
  & $docker network rm $network 2>$null | Out-Null
}
