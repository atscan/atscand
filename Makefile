.PHONY: all build install test clean fmt lint help

# Binary name
BINARY_NAME=atscand
INSTALL_PATH=$(GOPATH)/bin

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOINSTALL=$(GOCMD) install
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOFMT=$(GOCMD) fmt
GOMOD=$(GOCMD) mod
GORUN=$(GOCMD) run

# Default target
all: build

# Build the CLI tool
build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) -o $(BINARY_NAME) ./cmd/atscand

# Install the CLI tool globally
install:
	@echo "Installing $(BINARY_NAME)..."
	$(GOINSTALL) ./cmd/atscand

run:
	$(GORUN) cmd/atscand/main.go -verbose

update-plcbundle:
	GOPROXY=direct go get -u tangled.org/atscan.net/plcbundle@latest

# Show help
help:
	@echo "Available targets:"
	@echo "  make build          - Build the binary"
	@echo "  make install        - Install binary globally"
	@echo "  make run            - Run app"