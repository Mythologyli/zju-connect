# get modules, if they don't change the cache can be used for faster builds
FROM golang:1.19@sha256:7ffa70183b7596e6bc1b78c132dbba9a6e05a26cd30eaa9832fecad64b83f029 AS base
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
# ENV GOARCH=amd64
WORKDIR /src
COPY go.* .
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# build th application
FROM base AS build
# temp mount all files instead of loading into image with COPY
# temp mount module cache
# temp mount go build cache
RUN --mount=target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    # go build -ldflags="-w -s" -o /app/main ./cmd/openwrt-wan-reconnect/*.go
    go build -v -o /app/zju-connect -trimpath -ldflags "-s -w -buildid=" .

# Import the binary from build stage
FROM gcr.io/distroless/static:nonroot@sha256:ed05c7a5d67d6beebeba19c6b9082a5513d5f9c3e22a883b9dc73ec39ba41c04 as prd
WORKDIR /home/nonroot
COPY --from=build /app/zju-connect /home/nonroot
# this is the numeric version of user nonroot:nonroot to check runAsNonRoot in kubernetes
USER 65532:65532
ENTRYPOINT ["/home/nonroot/zju-connect" ,"-config", "/home/nonroot/config.toml"]