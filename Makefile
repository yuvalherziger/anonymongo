BINARY_NAME=anonymongo
DIST_DIR=./dist
SRC_DIR=./src
PKG=$(SRC_DIR)/...
GO=go
DOCKER=docker

.PHONY: all build test clean fmt vet docker-build

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build -o $(DIST_DIR)/$(BINARY_NAME) $(SRC_DIR)

test:
	@echo "Running tests..."
	$(GO) test $(PKG)

fmt:
	@echo "Formatting code..."
	$(GO) fmt $(PKG)

vet:
	@echo "Running go vet..."
	$(GO) vet $(PKG)

clean:
	@echo "Cleaning up..."
	rm -rf $(DIST_DIR)

run: build
	@echo "Running $(BINARY_NAME)..."
	$(DIST_DIR)/$(BINARY_NAME)

docker-build:
	@echo "Building Docker image..."
	$(DOCKER) build -t $(BINARY_NAME) .
