BINARY      := possession
PKG         := github.com/bugsyhewitt/possession
CMD         := ./cmd/possession

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint cover clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

test:
	go test ./... -race

lint:
	go vet ./...

cover:
	go test ./... -race -coverprofile=coverage.out
	go tool cover -func=coverage.out

clean:
	rm -f $(BINARY) coverage.out
	rm -rf dist
