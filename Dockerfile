# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS web
ARG BUILDKIT_SBOM_SCAN_STAGE=true
WORKDIR /src/web
RUN corepack enable && corepack prepare pnpm@11.19.0 --activate
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
COPY docs/.vitepress/ /src/docs/.vitepress/
COPY docs/guide/ /src/docs/guide/
RUN pnpm build:all

FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=v0.1.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ internal/
COPY cmd/ cmd/
COPY web/assets.go web/assets.go
COPY --from=web /src/web/dist web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X github.com/grantlinehq/grantline/internal/command.Version=$VERSION" -o /out/grantline ./cmd/grantline

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 65532 grantline && adduser -D -H -u 65532 -G grantline grantline && \
    mkdir -p /var/lib/grantline/secrets /var/lib/grantline/database-secrets && \
    chown -R 65532:65532 /var/lib/grantline && \
    chmod 700 /var/lib/grantline/secrets
COPY --from=build /out/grantline /usr/local/bin/grantline
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/grantline/
COPY third_party/licenses/ /usr/share/doc/grantline/licenses/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["grantline"]
CMD ["server", "--listen", "0.0.0.0:8080"]
