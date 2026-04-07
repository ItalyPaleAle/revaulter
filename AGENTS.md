# Coding Style Guidelines

## Go

Never define variables inside `if` conditions. Always declare variables on a separate line before the conditional check.

**Incorrect:**

```go
if err := something(); err != nil {
    // ...
}

if err = something(); err != nil {
    // ...
}
```

**Correct:**

```go
err := something()
if err != nil {
    // ...
}
```

## JavaScript, TypeScript, JSX, and TSX

Always use braces `{}` around statements in control flow blocks (`if`, `else`, `while`, `for`, etc.). Single-line statements without braces are not allowed.

**Incorrect:**

```js
if (foo) return false

while (true) sleep()

for (let i = 0; i < 10; i++) process(i)
```

**Correct:**

```js
if (foo) {
    return false
}

while (true) {
    sleep()
}

for (let i = 0; i < 10; i++) {
    process(i)
}
```
