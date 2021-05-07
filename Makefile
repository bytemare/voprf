PACKAGES    := $(shell go list ./...)
COMMIT      := $(shell git rev-parse HEAD)

.PHONY: lint
lint:
	@echo "Linting and security ..."
	@go vet ./...
	@golangci-lint run --fix --config=./.github/.golangci.yml ./...

.PHONY: get-module
get-module:
	@echo "Getting submodule ..."
	@git pull --recurse-submodules
	@cd test/draft-irtf-cfrg-voprf && git fetch --all && git checkout 866a54cc1021390359e67d8a1b773e2d70f19067

.PHONY: test
test: get-module
	@echo "Testing ..."
	@go test -v ./...

.PHONY: test-vectors
vectors: get-module
	@echo "Testing ..."
	@go test -v ./...

.PHONY: cover
cover: get-module
	@echo "Coverage ..."
	@go test -v -race -covermode=atomic \
		    -coverpkg=./... ./...
