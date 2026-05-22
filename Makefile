.PHONY: build test clean tidy mcp

build:
	go build -o bin/lokilens-mcp ./cmd/lokilens-mcp

test:
	go test ./... -v

tidy:
	go mod tidy

clean:
	rm -rf bin/

mcp:
	go run ./cmd/lokilens-mcp
