# wdtt-relay shim — static build, no CGO, no TUN (pure UDP relay).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/wdtt-relay .

FROM alpine:3.22
RUN adduser -D -H wdtt
COPY --from=build /out/wdtt-relay /usr/local/bin/wdtt-relay
ENTRYPOINT ["/usr/local/bin/wdtt-relay"]
