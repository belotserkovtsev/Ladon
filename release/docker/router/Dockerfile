# Ladon as a router in its own network namespace.
#
# Unlike the plain image, this one carries the resolver too, because a namespace
# of its own is only useful if the traffic passes through it — and traffic only
# passes through something that answers its DNS and forwards its packets.
#
#   docker build -f release/docker/router/Dockerfile -t ladon-router:local .

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/ladon ./cmd/ladon

FROM alpine:3.21

# dnsmasq answers for the clients and fills the sets while it answers;
# ipset/iptables/iproute2 are the split itself; ca-certificates lets the probe
# tell a real block from a substituted certificate.
RUN apk add --no-cache dnsmasq ipset iptables ip6tables iproute2 ca-certificates tzdata

WORKDIR /opt/ladon
COPY --from=build /out/ladon /opt/ladon/ladon
COPY release/extensions/ /opt/ladon/extensions/
COPY release/docker/router/entrypoint.sh /opt/ladon/entrypoint.sh
RUN chmod +x /opt/ladon/entrypoint.sh

VOLUME ["/opt/ladon/state", "/etc/ladon"]

EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/opt/ladon/entrypoint.sh"]
