# Coding Style Guidelines

## Go

Never define variables inside `if` conditions. Always declare variables on a separate line before the conditional check.

```go
// Wrong
if err := something(); err != nil { ... }

// Wrong
if val, ok := something.(string); ok { ... }

// Right
err := something()
if err != nil { ... }

// Right
val, ok := something.(string)
if ok { ... }
```

If you modify `internal/config.Config` or any struct referenced from it, always run `make gen-config` before finishing the task.

The Go build tag `unit` is meant for files that contain helpers for unit tests. It should never be included in a Go test file (ending in `_test.go`).

## JavaScript, TypeScript, JSX, and TSX

### Package management

The client project uses **pnpm** (NOT `npm`) for all package operations in the `client/` directory.

### Braces

Always use braces `{}` around control flow bodies — no single-line statements.

```js
// Wrong
if (foo) return false

// Right
if (foo) {
    return false
}
```

## Comments (all languages)

- One sentence per line; do not wrap to a max line length
- No trailing period on single-line comments

```go
// Wrong — wrapped mid-sentence
// This function performs the main validation logic. It checks
// the input against the schema and returns an error if the
// input is invalid.

// Wrong — trailing period on single-line comment
// Validate the input.

// Right
// This function performs the main validation logic
// It checks the input against the schema and returns an error if the input is invalid

// Right
// Validate the input
```

## Svelte and UI

All clickable `<button>` elements must expose `cursor: pointer` when enabled.

Prefer the shared button component at `client/src/components/Button.svelte` instead of ad hoc button markup so button behavior and styling stay standardized.

## Running tests

Always pass `-tags unit` when running Go tests — several test helpers are guarded by that build tag, so tests will fail to compile without it.

When compiling or testing code that imports use Go 1.27+.

```sh
go test -tags unit ./...
```

## Running the linter

The linter is pinned to a specific version (included in `.github/workflows/ci.yaml`), which must be installed from the pre-compiled binary: builds from package managers are compiled with an older Go and refuse this module's Go version.

```sh
VERSION="2.x.x" # From .github/workflows/ci.yaml
curl -sSL https://github.com/golangci/golangci-lint/releases/download/v${VERSION}/golangci-lint-${VERSION}-linux-amd64.tar.gz | tar -xz -C /tmp
install /tmp/golangci-lint-${VERSION}-linux-amd64/golangci-lint /usr/local/bin
make lint
```

## Release builds

`scripts/build-binaries.sh <target>` builds every binary for one release target and packages it, so the release pipeline invokes it once per platform. A new binary under `cmd/` must be added to the `BINARIES` list in that script to ship in releases.

## Git

Do not stage or unstage changes unless the user explicitly asks you to.
