PACKAGES    := $(shell go list ./...)
COMMIT      := $(shell git rev-parse HEAD)

.PHONY: lint
lint:
	@echo "Linting ..."
	@gofumports -w -local github.com/bytemare/voprf .
	@if golangci-lint run --config=./.github/.golangci.yml ./...; then echo "Linting OK"; else return 1; fi;

.PHONY: license
license:
	@echo "Checking License headers ..."
	@if addlicense -check -v -f .github/licence-header.tmpl *; then echo "License headers OK"; else return 1; fi;

.PHONY: test
test:
	@echo "Testing ..."
	@go test -v ./...

.PHONY: cover
cover:
	@echo "Coverage ..."
	@go test -v -race -covermode=atomic \
		    -coverpkg=./... ./...
