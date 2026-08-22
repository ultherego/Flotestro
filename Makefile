GOBIN     := $(shell go env GOPATH)/bin
PROTO_DIR := api/proto
GEN_DIR   := internal/genproto
LDFLAGS   := -s -w

.PHONY: help build build-agent generate test test-integration lint tidy clean

help:
	@grep -E '^[a-zA-Z-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  %-18s %s\n", $$1, $$2}'

build: ## Buduje control plane i agenta dla hosta
	go build -ldflags '$(LDFLAGS)' -o bin/flotestro-control-plane ./cmd/control-plane
	go build -ldflags '$(LDFLAGS)' -o bin/flotestro-agent ./cmd/agent

build-agent: ## Buduje statycznego agenta dla linux/amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o bin/flotestro-agent-linux-amd64 ./cmd/agent

generate: ## Generuje kod z kontraktu protobuf
	PATH="$(PATH):$(GOBIN)" protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=module=github.com/ultherego/flotestro/$(GEN_DIR) \
		--connect-go_out=$(GEN_DIR) --connect-go_opt=module=github.com/ultherego/flotestro/$(GEN_DIR) \
		$(PROTO_DIR)/flotestro/agent/v1/agent.proto

test: ## Testy jednostkowe
	go test ./...

test-integration: ## Testy integracyjne wobec floty testowej
	go test -tags=integration -count=1 -v ./tests/integration/...

lint: ## gofmt i go vet
	@test -z "$$(gofmt -l cmd internal db)" || (gofmt -l cmd internal db && exit 1)
	go vet ./...

tidy: ## Porzadkuje zaleznosci
	go mod tidy

clean: ## Kasuje artefakty budowania
	rm -rf bin
