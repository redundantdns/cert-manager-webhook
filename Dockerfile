# syntax=docker/dockerfile:1
# The webhook image: a static binary on distroless, running as non-root.
# Base images are pinned by digest (multi-arch index); bump the Go one with
# go.mod's go directive.

FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
# While go-client is private: GOPRIVATE=github.com/redundantdns/* and a
# build secret "netrc" (a read-only token) let go fetch it from git.
ARG GOPRIVATE=""
ENV GOPRIVATE=${GOPRIVATE}
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=secret,id=netrc,target=/root/.netrc,required=false \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X github.com/redundantdns/cert-manager-webhook/internal/solver.Version=${VERSION}" \
    -o /out/webhook .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/webhook /webhook
COPY LICENSE NOTICE /licenses/
# 65532 is the distroless "nonroot" user; numeric so runAsNonRoot can
# verify it.
USER 65532:65532
ENTRYPOINT ["/webhook"]
