PACKAGES    := $(shell go list ./...)
COMMIT      := $(shell git rev-parse HEAD)

.PHONY: lint
lint:
	@echo "Linting and security ..."
	@go vet ./...
	@golangci-lint run --fix --config=./.github/.golangci.yml ./...

.PHONY: test
test:
	@echo "Testing ..."
	@go test -v ./...

.PHONY: cover
cover:
	@echo "Coverage ..."
	@go test -v -race -covermode=atomic \
		    -coverpkg=./... ./...
