# Interacting with Revaulter using the CLI

The Revaulter CLI (`revaulter-cli`) offers a simplified method to interact with Revaulter to perform the six cryptographic operations supported by Azure Key Vault: encrypting and decrypting messages, wrapping and unwrapping keys, and computing and verifying digital signatures.

## Flow

Regardless of the operation in use, the regular flow is the same:

1. The application that requires the operation invokes `revaulter-cli` to start the operation. The CLI will automatically wait for the completion.
2. Revaulter receives the request and sends a notification to an admin.
3. An admin visits the Revaulter page, authenticates with Azure AD, and then approves the operation. If the admin denies the operation, or the request expires, Revaulter removes the request from its state and the flow stops.
4. Once the request is approved, Revaulter performs the operation within the Key Vault.
5. Revaulter sends the result to the CLI. The response is sent only once.

Revaulter uses delegated permissions to access Azure Key Vault. It uses the access token the user provides after logging in with Azure AD to make requests to Azure Key Vault, with the access level granted to the user.

> The ["headless" flow](./04-using-rest-api.md#headless-flow), which doesn't require approval from an admin, is only supported using the REST APIs.

## Installing the Revaulter CLI

TODO

## Using Revaulter

TODO

### Encrypt a message

TODO

### Decrypt a message

TODO

### Sign a message

TODO

### Verify a digital signature

TODO

### Wrap a key

TODO

### Unwrap a key

TODO
