FROM golang:1.27.1

WORKDIR /govpn

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ./bin/govpn ./cmd/govpn

CMD ["./bin/govpn"]
