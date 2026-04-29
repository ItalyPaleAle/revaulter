export GOEXPERIMENT := jsonv2

.PHONY: test
test:
	go test -tags unit ./...

.PHONY: test-race
test-race:
	CGO_ENABLED=1 go test -race -tags unit ./...

.PHONY: lint
lint:
	golangci-lint run -c .golangci.yaml

.PHONY: gen-config
gen-config:
	go run ./tools/gen-config-yaml

# Ensure gen-config ran
.PHONY: check-config-diff
check-config-diff: gen-config
	git diff --exit-code config.sample.yaml

.PHONY: client-format
client-format:
	(cd client/web && pnpm run format)

.PHONY: client-lint
client-lint:
	(cd client/web && pnpm run lint)

.PHONY: test-client
test-client:
	(cd client/web && pnpm run test)

.PHONY: test-e2e
test-e2e:
	(cd client/web && pnpm run e2e)
