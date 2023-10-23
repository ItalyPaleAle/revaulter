.PHONY: test
test:
	go test -tags unit ./...

.PHONY: test-race
test:
	go test -race -tags unit ./...

.PHONY: lint
lint:
	golangci-lint run
