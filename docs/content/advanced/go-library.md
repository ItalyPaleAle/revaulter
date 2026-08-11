---
title: "Using Revaulter as a Go library"
weight: 44
---

Everything `revaulter-cli` does over is also available as a Go package, so applications can submit encrypt, decrypt, sign, and verify requests without shelling out to the CLI.

```bash
go get github.com/italypaleale/revaulter/pkg/revaulter
```

The package documentation is on [pkg.go.dev](https://pkg.go.dev/github.com/italypaleale/revaulter/pkg/revaulter).

> Only `pkg/revaulter` is part of the public API and offers a stable API contract.

## Creating a client

A client needs the address of a Revaulter server and a per-user request key, which is shown in the web UI after registration:

```go
client, err := revaulter.New(revaulter.Options{
    Server:     "https://revaulter.example.com",
    RequestKey: os.Getenv("REVAULTER_REQUEST_KEY"),
})
if err != nil {
    return err
}
```

Clients are safe for concurrent use. Every operation blocks until the user approves the request in the browser, the operation times out, or the context is canceled:

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()
```

## Anchor pinning

Each user owns a hybrid (ES384 + ML-DSA-87) anchor key pair that signs the public keys the server advertises. Clients pin the anchor on first contact (the same Trust On First Use model as SSH host keys) and refuse to proceed if it ever changes. Pins live in the trust store shared with `revaulter-cli`, so a server pinned with `revaulter-cli trust` is already trusted by the library.

Because pinning an anchor is a security decision, keys must explicitly pinned. Applications that can ask interactive user input should implement the callback:

```go
client, err := revaulter.New(revaulter.Options{
    Server:     "https://revaulter.example.com",
    RequestKey: requestKey,
    ConfirmAnchor: func(anchor revaulter.AnchorInfo) (bool, error) {
        fmt.Printf("First contact with %s\nFingerprint:\n%s\n", anchor.Server, anchor.FormatFingerprint(2))
        // Ask the user, and return true to pin the anchor
        return promptUser()
    },
})
```

Non-interactive applications should either pin the anchor ahead of time with `revaulter-cli trust`, or opt into `revaulter.AcceptAnchorOnFirstUse`, which pins whatever the server presents on the first connection.

## Encrypting and decrypting

```go
enc, err := client.Encrypt(ctx, revaulter.EncryptRequest{
    KeyLabel:  "my-secret",
    Algorithm: revaulter.AlgorithmA256GCM,
    Plaintext: []byte("hello world"),
    Note:      "backup credentials",
})
if err != nil {
    return err
}

// enc.Ciphertext, enc.Nonce, and enc.Tag are what you store
dec, err := client.Decrypt(ctx, revaulter.DecryptRequest{
    KeyLabel:   enc.KeyLabel,
    Algorithm:  enc.Algorithm,
    Ciphertext: enc.Ciphertext,
    Nonce:      enc.Nonce,
    Tag:        enc.Tag,
})
if err != nil {
    return err
}

fmt.Println(string(dec.Plaintext))
```

Payloads are limited to `revaulter.MaxPayloadSize` (100 KB), because they are sent to the browser to be processed. Larger data should be encrypted locally with a key that Revaulter wraps, which is what [`revaulter-edit`](/cli/revaulter-edit) does for files.

## Signing and verifying

`Sign` hashes the message as the algorithm requires before sending it, so for `ES256` and `Ed25519ph` only the digest leaves the machine:

```go
res, err := client.Sign(ctx, revaulter.SignRequest{
    KeyLabel:  "release",
    Algorithm: revaulter.AlgorithmES256,
    Message:   manifest,
})
```

`res.Signature` holds the raw 64-byte signature, in the IEEE P1363 `r||s` form for `ES256`.

Verifying does not require the user's approval: it fetches the public signing key published on the server and checks the signature locally.

```go
err = client.Verify(ctx, revaulter.VerifyRequest{
    KeyLabel:  "release",
    Algorithm: revaulter.AlgorithmES256,
    Message:   manifest,
    Signature: res.Signature,
})
if errors.Is(err, revaulter.ErrInvalidSignature) {
    // The signature does not match the message
}
```

Signing keys must be published from the Revaulter web interface: publishing attaches an anchor-signed proof, which the library verifies against the pinned anchor before returning the key. To verify many signatures, fetch the key once and reuse it:

```go
key, err := client.SigningPublicKey(ctx, "release", revaulter.AlgorithmES256)
if err != nil {
    return err
}

err = key.Verify(revaulter.VerifyRequest{Message: manifest, Signature: signature})
```

`key.PublicKey` is a standard `*ecdsa.PublicKey` or `ed25519.PublicKey`, so it can also be handed to any other library.
