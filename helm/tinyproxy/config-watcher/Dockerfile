FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum main.go ./
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /config-watcher main.go

FROM alpine:3.18
COPY --from=builder /config-watcher /usr/local/bin/config-watcher
ENTRYPOINT ["/usr/local/bin/config-watcher"]
