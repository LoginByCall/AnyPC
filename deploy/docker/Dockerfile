# syntax=docker/dockerfile:1
# Образ anypc-server (хаб + веб-клиент; ретранслятор — отдельный контейнер coturn, см. compose.yml).
# Сборка из корня репозитория: docker build -f deploy/docker/Dockerfile .
# Кросс-компиляция на платформе сборщика — amd64 и arm64 без эмуляции.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
ENV GOFLAGS="-trimpath -buildvcs=false"
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CPace веб-клиента — тот же Go в WebAssembly (как в build.sh); в git его нет
RUN GOOS=js GOARCH=wasm go build -ldflags='-s -w' -o ui/pake.wasm ./wasm \
 && cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ui/ \
 && CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w -X main.version=$VERSION" -o /anypc-server ./server

FROM scratch
# корневые сертификаты — для Let's Encrypt (ACME по HTTPS)
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /anypc-server /anypc-server
# /data: сертификаты (certs/) и ключи хостов (hosts.json)
VOLUME /data
# ponytail: от root — порты 80/443 в сети хоста; non-root — с setcap, если понадобится
ENTRYPOINT ["/anypc-server", "-certs", "/data/certs"]
