# 🔐 Revaulter v1.0-beta.1

Revaulter lets you perform cryptographic operations with keys stored on [Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview), securely after getting consent from an admin. You can use Revaulter for:

- Encrypting and decrypting messages
- Wrapping and unwrapping encryption keys
- Calculating and verifying digital signatures

Revaulter works with Azure Key Vault, where your cryptographic keys (RSA, elliptic curve, and symmetric) are stored safely. You can build applications that interact with Revaulter to perform cryptographic operations that are completed in the key vault, only after a user with sufficient permission authorizes it.

Some example usages:

- Revaulter can be used to provide an encryption key for starting a long-running application, such as [unlocking encrypted drives at boot time](https://withblue.ink/2020/01/19/auto-mounting-encrypted-drives-with-a-remote-key-on-linux.html). This way, your encryption keys can be stored on your server safely in a wrapped (encrypted) format. By requiring explicit consent from an admin, you can be confident that no one can unwrap your encryption keys without your knowledge and permission.
- You can use Revaulter as part of a CI/CD pipeline to digitally sign your binaries.
- Or, you can use Revaulter as a generic tool to encrypt or decrypt (short) messages.

# ⚙️ How it works

Revaulter exposes a few REST endpoints that can be used to perform cryptographic operations, including: encrypting and decrypting arbitrary data, wrapping and unwrapping keys, calculating and verifying digital signatures. These operations are performed on Azure Key Vault, a safe, cloud-based key vault that uses strong keys, including RSA (up to 4096 bits), ECDSA (with NIST curves including P-256, P-384, and P-521), and AES (on Managed HSM Azure Key Vault only).

Revaulter doesn't have standing permission to perform operations on the vault, so every time a request comes in, Revaulter sends a notification to an admin (via a webhook), who can sign into Revaulter via Azure AD and allow (or deny) the operation. Revaulter uses delegated permissions to access the Key Vault, so access is restricted to specific users via Role-Based Access Control on the Azure Key Vault resource.

![Example of a notification sent by Revaulter (to a Discord chat)](/notification-example.png)

Alternatively, Revaulter can be invoked with a bearer token issued by Azure AD, obtained outside of Revaulter, with permission to access the Key Vault. This allows, for example, using the client credentials flow to obtain an access token (i.e. using a client ID and client secret pair).

# 📘 Docs

1. [Set up](./docs/01-set-up.md) and configure Azure resources
2. [Install and configure Revaulter](./docs/02-install-and-configure-revaulter.md)
3. [Using Revaulter](./docs/03-using-revaulter.md)
