# syntax=docker/dockerfile:1

# One image, two entrypoints: the scanner (default) and the throwaway mock
# service used by the compose demo. Both share the same Go build stage, so the
# demo needs no images beyond the official alpine/golang bases.

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY scope ./scope
COPY probe ./probe
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/netinv ./cmd/netinv \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mock ./cmd/mock

FROM alpine:3.20
RUN adduser -D -H -u 10001 scan \
 && mkdir -p /work /work/out \
 && chown -R scan:scan /work
COPY --from=build /out/netinv /usr/local/bin/netinv
COPY --from=build /out/mock /usr/local/bin/mock
WORKDIR /work
USER scan
ENTRYPOINT ["/usr/local/bin/netinv"]
CMD ["-scope", "/work/scope.json", "-out", "/work/out/report.json"]
