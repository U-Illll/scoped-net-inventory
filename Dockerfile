# syntax=docker/dockerfile:1

# One image, several entrypoints: the scanner, the throwaway mock service, and
# the lab C2 pair. Everything shares the same Go build stage, so nothing here
# pulls an image beyond the official alpine/golang bases.

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY scope ./scope
COPY probe ./probe
COPY c2 ./c2
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/netinv ./cmd/netinv \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mock ./cmd/mock \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/c2server ./cmd/c2server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/c2implant ./cmd/c2implant

FROM alpine:3.20
RUN adduser -D -H -u 10001 scan \
 && mkdir -p /work /work/out /work/c2 \
 && chown -R scan:scan /work
COPY --from=build /out/netinv /usr/local/bin/netinv
COPY --from=build /out/mock /usr/local/bin/mock
COPY --from=build /out/c2server /usr/local/bin/c2server
COPY --from=build /out/c2implant /usr/local/bin/c2implant
COPY DISCLAIMER.md /work/DISCLAIMER.md
WORKDIR /work
USER scan
ENTRYPOINT ["/usr/local/bin/netinv"]
CMD ["-scope", "/work/scope.json", "-out", "/work/out/report.json"]
