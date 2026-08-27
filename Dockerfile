# Ladon in a container.
#
# The image carries the engine and the bundled presets; everything else —
# the sets, the firewall rules that route what lands in them, and the resolver
# whose answers ladon reads — stays on the host. See release/docker/README.md.
#
# Build:  docker build -t ladon:local --build-arg VERSION=$(git describe --tags) .

FROM golang:1.26-alpine AS build
WORKDIR /src

# Dependencies first, so a source-only change keeps the module cache warm.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/ladon ./cmd/ladon

FROM alpine:3.21

# ipset: the engine shells out to it to program the sets.
# ca-certificates: the probe verifies a server's chain to tell a real block
#   from a substituted certificate, which needs the trust store.
# tzdata: so timestamps in logs match the operator's clock.
RUN apk add --no-cache ipset ca-certificates tzdata

# Mirrors the layout the systemd unit uses, so paths in the docs read the same
# whether ladon runs on the host or in here.
WORKDIR /opt/ladon
COPY --from=build /out/ladon /opt/ladon/ladon
COPY release/extensions/ /opt/ladon/extensions/

# state: the SQLite database. /etc/ladon: config and the manual lists.
VOLUME ["/opt/ladon/state", "/etc/ladon"]

ENTRYPOINT ["/opt/ladon/ladon"]
CMD ["-config", "/etc/ladon/config.yaml", "run", "/var/log/dnsmasq.log"]
