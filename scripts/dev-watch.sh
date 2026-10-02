#!/bin/sh
# Run inside the Go development container. The source mount is read-only.
set -eu
server_pid=''
stop_server() {
  if [ -n "$server_pid" ]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=''
  fi
}
trap 'stop_server; exit 0' INT TERM
fingerprint() {
  # Include embedded assets; frontend source itself is handled by Vite HMR.
  find cmd internal web/dist web/assets.go go.mod go.sum \
    -type f ! -name '*_test.go' -printf '%p %s %T@\n' | sort | sha256sum
}
previous=''
while :; do
  current=$(fingerprint)
  if [ "$current" != "$previous" ]; then
    previous=$current
    echo '[dev] Source changed; compiling backend...'
    if go build -o /tmp/grantline-dev-next ./cmd/grantline; then
      stop_server
      mv /tmp/grantline-dev-next /tmp/grantline-dev
      if /tmp/grantline-dev migrate; then
        /tmp/grantline-dev server --listen 0.0.0.0:8080 &
        server_pid=$!
        echo '[dev] Backend started; browser URL: http://127.0.0.1:8080'
      else
        echo '[dev] Migration failed. Fix the source/configuration and restart.' >&2
        exit 1
      fi
    else
      echo '[dev] Compilation failed; retaining the last working backend. Save a fix to retry.' >&2
    fi
  fi
  if [ -n "$server_pid" ] && ! kill -0 "$server_pid" 2>/dev/null; then
    echo '[dev] Backend exited unexpectedly; restarting development container.' >&2
    exit 1
  fi
  sleep 1 &
  wait $! || true
done
