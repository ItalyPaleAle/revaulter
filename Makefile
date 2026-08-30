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

.PHONY: gen-db
gen-db:
	go generate ./internal/db/...

# Ensure gen-db ran
.PHONY: check-db-diff
check-db-diff: gen-db
	git diff --exit-code internal/db/backup/tables_gen.go

.PHONY: client-format
client-format:
	(cd client/web && pnpm run format)

.PHONY: client-lint
client-lint:
	(cd client/web && pnpm run lint)

.PHONY: test-client
test-client:
	(cd client/web && pnpm run test)

# Runs against chromium only
# Set E2E_BROWSERS to "all", or to a comma-separated list of chromium, firefox and webkit, to run against other engines
.PHONY: test-e2e
test-e2e:
	(cd client/web && pnpm run e2e)
