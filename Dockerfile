# get modules, if they don't change the cache can be used for faster builds
FROM golang:1.22 AS base
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64
ARG build_tag=full
# RUN go env -w GOPROXY=https://goproxy.cn,direct

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
    go build -tags ${build_tag} -v -o /app/zju-connect -trimpath -ldflags "-s -w -buildid=" .

# Import the binary from build stage
# use root container, but still use /home/nonroot to keep backward support
FROM gcr.io/distroless/static as prd
WORKDIR /home/nonroot
COPY --from=build /app/zju-connect /home/nonroot
ENTRYPOINT ["/home/nonroot/zju-connect" ,"-config", "/home/nonroot/config.toml"]
