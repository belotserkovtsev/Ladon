# Ladon in a container.
#
# The image carries the engine, the resolver and the bundled presets, because a
# network namespace of its own is only useful if traffic passes through it — and
# traffic only passes through something that answers its DNS and forwards its
# packets. Sets are per-namespace, so deciding and enforcing have to share one.
#
# See release/docker/README.md for what the host still has to do.
#
#   docker build -t ladon:local --build-arg VERSION=$(git describe --tags) .

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

# dnsmasq answers for the clients and fills the sets while it answers;
# ipset/iptables/iproute2 are the split itself; ca-certificates lets the probe
# tell a real block from a substituted certificate; tzdata keeps log timestamps
# matching the operator's clock.
RUN apk add --no-cache dnsmasq ipset iptables ip6tables iproute2 ca-certificates tzdata

# Mirrors the layout the systemd unit uses, so paths read the same either way.
WORKDIR /opt/ladon
COPY --from=build /out/ladon /opt/ladon/ladon
COPY release/extensions/ /opt/ladon/extensions/
COPY release/docker/entrypoint.sh /opt/ladon/entrypoint.sh
RUN chmod +x /opt/ladon/entrypoint.sh

# state: the SQLite database. /etc/ladon: config and the manual lists.
VOLUME ["/opt/ladon/state", "/etc/ladon"]

EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/opt/ladon/entrypoint.sh"]
