BINARY_NAME=aipostex
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-s -w -X github.com/professor-moody/aipostex/internal/config.Version=$(VERSION) -X github.com/professor-moody/aipostex/internal/config.BuildTime=$(BUILD_TIME)"

.PHONY: all build clean test lint fmt vet

all: clean build

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/aipostex/

build-all: clean
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/aipostex/
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/aipostex/
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/aipostex/
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/aipostex/
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/aipostex/

clean:
	rm -rf bin/

test:
	go test -v -race ./...

test-short:
	go test -short ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w cmd internal pkg

vet:
	go vet ./...

# Run against local test lab
test-lab:
	go run ./cmd/aipostex/ discover network --target 127.0.0.1 --ports 11434,8000,6333,8888

# Count templates
count-templates:
	@find pkg/vulncheck/templates -name '*.yaml' | wc -l
	@echo "templates loaded"
