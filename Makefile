GOBIN     := $(shell go env GOPATH)/bin
PROTO_DIR := api/proto
GEN_DIR   := internal/genproto
LDFLAGS   := -s -w
VERSION   ?= 0.1.0

.PHONY: help build build-agent stage package-deb package-rpm generate test test-integration lint tidy clean

help:
	@grep -E '^[a-zA-Z-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  %-18s %s\n", $$1, $$2}'

build: ## Builds the control plane and the agent for the host
	go build -ldflags '$(LDFLAGS)' -o bin/flotestro-control-plane ./cmd/control-plane
	go build -ldflags '$(LDFLAGS)' -o bin/flotestro-agent ./cmd/agent

build-agent: ## Builds a static agent for linux/amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o bin/flotestro-agent-linux-amd64 ./cmd/agent

COMPONENT ?= agent

stage: ## Builds the binaries into the bin directory (COMPONENT=agent|control-plane)
	@mkdir -p bin
ifeq ($(COMPONENT),agent)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o bin/flotestro-agent ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o bin/flotestro-agent-helper ./cmd/agent-helper
else
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o bin/flotestro-control-plane ./cmd/control-plane
endif

package-deb: stage ## Builds the .deb package (COMPONENT=agent|control-plane, requires dpkg-deb)
	@mkdir -p dist
	packaging/build-deb.sh $(COMPONENT) bin $(VERSION) amd64 dist

package-rpm: stage ## Builds the .rpm package (COMPONENT=agent|control-plane, requires rpmbuild)
	@mkdir -p dist
	packaging/build-rpm.sh $(COMPONENT) bin $(VERSION) x86_64 dist

generate: ## Generates the code from the protobuf contract
	PATH="$(PATH):$(GOBIN)" protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=module=github.com/ultherego/flotestro/$(GEN_DIR) \
		--connect-go_out=$(GEN_DIR) --connect-go_opt=module=github.com/ultherego/flotestro/$(GEN_DIR) \
		$(PROTO_DIR)/flotestro/agent/v1/agent.proto \
		$(PROTO_DIR)/flotestro/helper/v1/helper.proto

test: ## Unit tests
	go test ./...

test-integration: ## Integration tests against the test fleet
	go test -tags=integration -count=1 -v ./tests/integration/...

lint: ## gofmt and go vet
	@test -z "$$(gofmt -l cmd internal db)" || (gofmt -l cmd internal db && exit 1)
	go vet ./...

tidy: ## Tidies the dependencies
	go mod tidy

clean: ## Deletes the build artefacts
	rm -rf bin
