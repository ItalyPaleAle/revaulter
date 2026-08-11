/*
Package revaulter is a client library for interacting with a [Revaulter] server.

Revaulter performs cryptographic operations with keys that never leave the user's browser: a client submits a request, the user approves it with a passkey, and the browser performs the operation locally and returns the result encrypted end-to-end.
This package implements the client side of that protocol, exposing the same low-level operations the revaulter-cli command offers: encrypting and decrypting messages, signing them, and verifying signatures.

# Getting started

Create a [Client] with the address of the server and a per-user request key, then invoke one of the operations.
Every operation blocks until the user approves the request in their browser (or the context is canceled):

	client, err := revaulter.New(revaulter.Options{
		Server:     "https://revaulter.example.com",
		RequestKey: os.Getenv("REVAULTER_REQUEST_KEY"),
	})
	if err != nil {
		panic(err)
	}

	res, err := client.Encrypt(ctx, revaulter.EncryptRequest{
		KeyLabel:  "my-secret",
		Algorithm: revaulter.AlgorithmA256GCM,
		Plaintext: []byte("hello world"),
	})

# Anchor pinning

Each user owns a hybrid (ES384 + ML-DSA-87) "anchor" key pair that signs the public keys the server advertises.
Clients pin the anchor on first contact (the same Trust On First Use, or TOFU, model used by SSH for host keys) and refuse to proceed if it ever changes.
Pins are stored in a trust store shared with revaulter-cli, so a server pinned with "revaulter-cli trust" is already trusted by this package.

Because pinning an anchor is a security decision, [Client] fails closed the first time it contacts a server unless [Options.ConfirmAnchor] is set.
Applications that can prompt a human should implement that callback, while non-interactive applications should either pin the anchor ahead of time with revaulter-cli, or opt into [AcceptAnchorOnFirstUse].

[Revaulter]: https://github.com/italypaleale/revaulter
*/
package revaulter
