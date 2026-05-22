FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /lokilens-mcp ./cmd/lokilens-mcp

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /lokilens-mcp /lokilens-mcp
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
