FROM golang:1.27.1 AS build

WORKDIR /govpn

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ./bin/govpn ./cmd/govpn

FROM alpine:3.24.2
WORKDIR /govpn
COPY --from=build /govpn/bin/govpn ./bin/govpn
COPY --chmod=755 docker/entrypoint.sh ./docker/entrypoint.sh
ENTRYPOINT ["/govpn/docker/entrypoint.sh"]
