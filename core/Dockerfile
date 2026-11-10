FROM golang:1.25-alpine AS builder
ARG VERSION=extended-v5
WORKDIR /src
COPY go.mod go.sum ./
COPY replace/ replace/
RUN go mod download
COPY . .
# Direct go build with an explicit -checklinkname=0 (required by common/badtls
# //go:linkname into crypto/tls); does not depend on release/LDFLAGS or .git,
# both excluded by .dockerignore. //H
RUN apk add --no-cache git build-base && \
    export GOTOOLCHAIN=local && \
    go build -v -trimpath \
      -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_tailscale,with_ccm,with_ocm,with_cloudflared,badlinkname,tfogo_checklinkname0,with_grpc,with_awg,with_xdp" \
      -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=${VERSION}' -X internal/godebug.defaultGODEBUG=multipathtcp=0 -checklinkname=0 -s -w -buildid=" \
      -o /src/sing-box ./cmd/sing-box

FROM alpine
RUN apk add --no-cache bash tzdata ca-certificates nftables
COPY --from=builder /src/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["sing-box"]
