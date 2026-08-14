# pkgwatch in a container, for the hub.
#
# Built for the machine that already runs its other services with compose. The
# agent is deliberately NOT the intended tenant here: it exists to see what is
# installed on a host and to sit in front of that host's package managers, and
# a container gives it a view of its own filesystem instead. Run the agent on
# the host; run the hub here if that is how the box is organised.
#
# The build stage does reach the network. vendor/ is deliberately NOT committed
# here — `go mod vendor` weighs 134 MB, almost all of it machine-generated
# modernc.org/{libc,sqlite} per GOOS/GOARCH — so modules are fetched at build
# time. What makes that acceptable is go.sum: every module is pinned by hash and
# the toolchain refuses anything that does not match, which is the same property
# committing vendor/ would have bought. See the note in .gitignore.

FROM golang:1.26-alpine AS build
WORKDIR /src

# Manifests first so the module download is its own layer and survives edits to
# the source underneath it.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags="-s -w -X github.com/myselfvivek17/pkgwatch/internal/buildinfo.Version=docker" \
        -o /out/pkgwatch ./cmd/pkgwatch

# Certificates come from the builder rather than being trusted from a base
# image nobody looks at. The hub serves its own self-signed certificate and
# needs none of these to do that, but fetching advisory bundles over the
# internet does.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/pkgwatch /pkgwatch

# Everything the hub keeps lives under one directory so a single volume covers
# it: hub.db, the TLS keypair it generates on first run, and any advisory
# bundles it relays. HOME is what the data-dir resolver reads on Linux
# (~/.local/share/pkgwatch), and scratch has no /etc/passwd to answer for it.
ENV HOME=/data
VOLUME /data
WORKDIR /data

# Note for anyone reading timestamps in the dashboard: scratch carries no
# timezone database, so local time in the container is UTC. The trend charts
# bucket by local day, which means days break at UTC midnight here.

EXPOSE 4876
ENTRYPOINT ["/pkgwatch"]
CMD ["hub"]
