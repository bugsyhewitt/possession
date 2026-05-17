BINARY      := possession
PKG         := github.com/bugsyhewitt/possession
CMD         := ./cmd/possession

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint cover clean release

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

# release: cross-compile v1.0 binaries for the five supported platforms,
# package each as a tar.gz (zip for Windows), and emit a SHA256SUMS
# file. Does NOT publish — the human publishes the GitHub Release from
# the dist/ artifacts.
RELEASE_VERSION := $(VERSION)
RELEASE_TARGETS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

release: clean
	@mkdir -p dist
	@for target in $(RELEASE_TARGETS); do \
		os=$${target%/*}; arch=$${target#*/}; \
		bin=$(BINARY); \
		if [ "$$os" = "windows" ]; then bin=$(BINARY).exe; fi; \
		stage=dist/$(BINARY)-$(RELEASE_VERSION)-$$os-$$arch; \
		mkdir -p $$stage; \
		echo "==> building $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			go build -trimpath -ldflags "$(LDFLAGS)" \
			-o $$stage/$$bin $(CMD); \
		cp README.md LICENSE CHANGELOG.md $$stage/; \
		if [ "$$os" = "windows" ]; then \
			(cd dist && zip -qr $(BINARY)-$(RELEASE_VERSION)-$$os-$$arch.zip $(BINARY)-$(RELEASE_VERSION)-$$os-$$arch); \
		else \
			(cd dist && tar -czf $(BINARY)-$(RELEASE_VERSION)-$$os-$$arch.tar.gz $(BINARY)-$(RELEASE_VERSION)-$$os-$$arch); \
		fi; \
		rm -rf $$stage; \
	done
	@cd dist && sha256sum *.tar.gz *.zip 2>/dev/null > SHA256SUMS
	@echo
	@echo "==> dist artifacts:"
	@ls -la dist/
