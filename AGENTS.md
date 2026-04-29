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

If you modify `pkg/config.Config` or any struct referenced from it, always run `make gen-config` before finishing the task.

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

When compiling or testing code that imports use Go 1.26+ and set `GOEXPERIMENT=jsonv2`.

```sh
go test -tags unit ./...
```
