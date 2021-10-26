PACKAGES    := $(shell go list ./...)
COMMIT      := $(shell git rev-parse HEAD)

.PHONY: lint
lint:
	@echo "Linting ..."
	@gofumports -w -local github.com/bytemare/voprf .
	@golangci-lint run --config=./.github/.golangci.yml ./...

.PHONY: test
test:
	@echo "Testing ..."
	@go test -v ./...

.PHONY: cover
cover:
	@echo "Coverage ..."
	@go test -v -race -covermode=atomic \
		    -coverpkg=./... ./...
