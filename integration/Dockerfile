FROM golang:1.25.12-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/franztls-integration ./cmd/franztls-integration

FROM debian:12-slim

RUN groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot \
    && install -d -o 65532 -g 65532 -m 0700 /etc/certs
COPY --from=build /out/franztls-integration /usr/local/bin/franztls-integration
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/franztls-integration"]
