param([ValidateSet('Compose','Kubernetes')][string]$Deployment='Compose')
$ErrorActionPreference='Stop'
if($PSVersionTable.PSVersion -lt [version]'7.4'){throw 'PowerShell 7.4+ is required for binary-safe native redirection'}
$root=Split-Path -Parent $PSScriptRoot
$docker='C:\Program Files\Docker\Docker\resources\bin\docker.exe'
$kubectl='C:\Program Files\Docker\Docker\resources\bin\kubectl.exe'
$suffix=[guid]::NewGuid().ToString('N').Substring(0,10)
$seed="grantline-backup-seed-$suffix"
$restore="grantline-backup-restore-$suffix"
$network="grantline-backup-$suffix"
$dir=Join-Path $root "bin/backup-$suffix"
New-Item -ItemType Directory $dir | Out-Null
$fixture=Join-Path $dir 'fixture.json'
$dump=Join-Path $dir 'fixture.dump'
$schema=''
function CheckNative { if($LASTEXITCODE -ne 0){throw "Acceptance command failed: $LASTEXITCODE"} }
try {
  if($Deployment -eq 'Compose'){
    & $docker run --name $seed --network grantline_default --mount "type=bind,source=$root\bin,target=/tests,readonly" --mount type=volume,source=grantline_app-secrets,target=/source-secrets,readonly --env GRANTLINE_TEST_DATABASE_URL_FILE=/source-secrets/database-url --env GRANTLINE_TEST_BACKUP_DIR=/tmp --entrypoint /tests/platform.test grantline:development '-test.run=^TestDatabaseBackupSeed$' '-test.v'
    CheckNative
    & $docker cp "${seed}:/tmp/fixture.json" $fixture
    CheckNative
  } else {
    $pod=(& $kubectl --kubeconfig "$root/bin/acceptance.kubeconfig" -n grantline get pods -l app.kubernetes.io/name=grantline -o jsonpath='{.items[0].metadata.name}')
    CheckNative
    & $kubectl --kubeconfig "$root/bin/acceptance.kubeconfig" -n grantline cp ./bin/platform.test "${pod}:/tmp/platform.test" -c app
    CheckNative
    & $kubectl --kubeconfig "$root/bin/acceptance.kubeconfig" -n grantline exec $pod -c app -- chmod 700 /tmp/platform.test
    CheckNative
    & $kubectl --kubeconfig "$root/bin/acceptance.kubeconfig" -n grantline exec $pod -c app -- env GRANTLINE_TEST_DATABASE_URL_FILE=/run/grantline/database-url GRANTLINE_TEST_BACKUP_DIR=/tmp /tmp/platform.test '-test.run=^TestDatabaseBackupSeed$' '-test.v'
    CheckNative
    & $kubectl --kubeconfig "$root/bin/acceptance.kubeconfig" -n grantline exec $pod -c app -- cat /tmp/fixture.json > $fixture
    CheckNative
  }
  $schema=(Get-Content -LiteralPath $fixture -Raw | ConvertFrom-Json).Schema
  if($schema -notmatch '^acceptance_[a-f0-9]{16}$'){throw 'Invalid acceptance schema'}
  if($Deployment -eq 'Compose'){
    & $docker exec grantline-postgres-1 pg_dump -U grantline -d grantline -n $schema -Fc > $dump
    CheckNative
  } else {
    & $kubectl --kubeconfig "$root/bin/acceptance.kubeconfig" -n grantline exec grantline-grantline-postgres-0 -- pg_dump -U grantline -d grantline -n $schema -Fc > $dump
    CheckNative
  }
  & $docker network create --internal $network | Out-Null
  CheckNative
  $password=[guid]::NewGuid().ToString('N')
  & $docker run -d --name $restore --network $network --env POSTGRES_DB=grantline --env POSTGRES_USER=grantline --env "POSTGRES_PASSWORD=$password" postgres:17-alpine | Out-Null
  CheckNative
  for($attempt=0;$attempt -lt 30;$attempt++){
    & $docker exec $restore pg_isready -U grantline -d grantline 2>$null | Out-Null
    if($LASTEXITCODE -eq 0){break}
    Start-Sleep -Seconds 1
  }
  CheckNative
  & $docker cp $dump "${restore}:/tmp/fixture.dump"
  CheckNative
  & $docker exec $restore pg_restore -U grantline -d grantline --no-owner --exit-on-error /tmp/fixture.dump
  CheckNative
  & $docker run --rm --network $network --mount "type=bind,source=$root\bin,target=/tests,readonly" --mount "type=bind,source=$dir,target=/fixture,readonly" --env "GRANTLINE_TEST_DATABASE_URL=postgres://grantline:${password}@${restore}:5432/grantline?sslmode=disable" --env GRANTLINE_TEST_BACKUP_DIR=/fixture --entrypoint /tests/platform.test grantline:development '-test.run=^TestDatabaseBackupRestored$' '-test.v'
  CheckNative
  "$Deployment backup/restore acceptance passed."
} finally {
  if($Deployment -eq 'Kubernetes' -and $pod){ & $kubectl --kubeconfig "$root/bin/acceptance.kubeconfig" -n grantline exec $pod -c app -- rm -f /tmp/platform.test /tmp/fixture.json }
  if($schema -match '^acceptance_[a-f0-9]{16}$'){
    $sql="DROP SCHEMA $schema CASCADE"
    if($Deployment -eq 'Compose'){ & $docker exec grantline-postgres-1 psql -U grantline -d grantline -c $sql | Out-Null }
    else { & $kubectl --kubeconfig "$root/bin/acceptance.kubeconfig" -n grantline exec grantline-grantline-postgres-0 -- psql -U grantline -d grantline -c $sql | Out-Null }
  }
  # Only resources created with this invocation's random suffix are removed.
  & $docker rm -f -v $restore $seed 2>$null | Out-Null
  & $docker network rm $network 2>$null | Out-Null
  # Keep the synthetic dump for review; the independently held test key is temporary.
  if(Test-Path -LiteralPath $fixture){Remove-Item -LiteralPath $fixture}
}
