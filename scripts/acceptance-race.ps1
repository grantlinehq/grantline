$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$docker='C:\Program Files\Docker\Docker\resources\bin\docker.exe'
$suffix=[guid]::NewGuid().ToString('N').Substring(0,10)
$database="grantline-race-$suffix"
$network="grantline-race-net-$suffix"
$password=[guid]::NewGuid().ToString('N')
try {
  & $docker network create $network | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Cannot create disposable test network'}
  & $docker run -d --name $database --network $network --env POSTGRES_USER=grantline --env POSTGRES_DB=grantline --env "POSTGRES_PASSWORD=$password" postgres:17-alpine | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Cannot start disposable database'}
  for($i=0;$i -lt 30;$i++){& $docker exec $database pg_isready -U grantline -d grantline 2>$null | Out-Null; if($LASTEXITCODE -eq 0){break}; Start-Sleep -Seconds 1}
  if($LASTEXITCODE -ne 0){throw 'Database not ready'}
  # Compile an isolated source copy on the container filesystem. This excludes
  # private bin/ helpers and avoids mmap failures on Windows/OneDrive bind mounts.
  # Build web/dist (including docs) before invoking this script.
  $testScript = @'
mkdir -p /work/web
cp -R /src/cmd /src/internal /src/scripts /src/schema /src/testdata /src/go.mod /src/go.sum /work/
cp -R /src/web/assets.go /src/web/dist /work/web/
cd /work
go test -race -count=1 ./...
go vet ./...
'@
  & $docker run --rm --network $network --mount "type=bind,source=$root,target=/src,readonly" --mount type=volume,source=grantline-test-gomod,target=/go/pkg/mod --mount type=volume,source=grantline-test-gocache,target=/root/.cache/go-build -e CGO_ENABLED=1 --env "GRANTLINE_TEST_DATABASE_URL=postgres://grantline:${password}@${database}:5432/grantline?sslmode=disable" golang:1.27.1 sh -ec $testScript
  if($LASTEXITCODE -ne 0){throw 'Race or database acceptance failed'}
} finally {
  & $docker rm -f -v $database 2>$null | Out-Null
  & $docker network rm $network 2>$null | Out-Null
}
