---
title: "Authenticating with OIDC tokens"
weight: 27
---

By default, the CLI authenticates the requests it sends you with a static request key. That key never expires, so wherever it's stored (a CI secret, a file on a server) it's a long-lived credential that someone could steal.

If your requests come from a platform that issues OpenID Connect (OIDC) tokens to its workloads, such as GitHub Actions, GitLab CI, Service Account Tokens on Kubernetes, Workload Identity tokens on cloud providers like Azure or Vercel, you can use those tokens instead. They are signed by the platform, identify the exact workload that requested them, and expire within minutes, so there's no long-lived secret to protect.

Approving a request still requires your passkey: OIDC tokens only replace the request key, which decides who can _ask_ you for approval.

## How it works

Each user chooses which authentication methods to enable in the web UI, under **Settings → Request auth**. The two can be enabled at the same time:

- **Request key**: the CLI sends the static request key
- **OIDC tokens**: the CLI sends a JWT from one of your trusted issuers, together with your user ID

When a request carries a JWT, the server:

1. Reads the user ID from the `X-Revaulter-User` header (the CLI's `--user-id` flag), and checks that the user has enabled OIDC tokens.
2. Looks for a trusted issuer of that user whose issuer matches the token's `iss` claim exactly, whose audience is in the token's `aud` claim, and whose subject pattern matches the token's `sub` claim.
3. Verifies the token's signature with the issuer's public keys, which it fetches from the issuer's JWKS. The JWKS URL is found with OpenID Connect discovery, unless you set it explicitly.
4. Checks that the token has an `exp` claim and hasn't expired, and that its `nbf` and `iat` claims, when present, aren't in the future. A clock skew of up to one minute is tolerated.

The response to the new request includes a _result token_, which the CLI uses to wait for your approval. The result token stays valid until the request is completed or expires, so the approval can take longer than the OIDC token's lifetime.

## Setting up

1. Sign in to the web UI, open **Settings → Request auth**, and enable **OIDC tokens**.
2. Select **Add trusted issuer**, and fill in:
    - **Issuer**: the value of the tokens' `iss` claim, such as `https://token.actions.githubusercontent.com`
    - **Audience**: the value your workload requests for the tokens' `aud` claim. It defaults to the address of your Revaulter server, which is the convention most platforms follow
    - **Subject**: a pattern for the tokens' `sub` claim. `*` matches any sequence of characters, including `/` and `:`
    - **JWKS URL**: set it if you need to pass an explicit endpoint, otherwise it is automatically detected using OpenID Connect discovery
3. Copy your **User ID** from the same page, and pass it to the CLI with `--user-id` (or, with `revaulter-edit`, the `REVAULTER_USER_ID` environment variable).

You can trust up to 25 issuers. Add one entry for each workload that should be able to send you requests.

The Revaulter server needs outbound HTTPS access to each issuer, to fetch its discovery document and JWKS. Keys are cached, and refreshed in the background and whenever a token is signed with a key the server hasn't seen yet.

By default, the server only connects to issuers on public addresses, since users choose the URLs it fetches. If your issuer is on a private network, such as a Kubernetes cluster's internal API server, set the [`oidcAllowPrivateAddresses`](/docs/installing-revaulter/) option.

## Choosing the subject

The subject is what restricts _which_ workloads can send you requests.

Some examples for **GitHub Actions**, whose issuer is `https://token.actions.githubusercontent.com`:

| Subject | Matches tokens from |
| --- | --- |
| `repo:my-org/my-app:environment:release` | Jobs that use the `release` environment. Combined with [environment protection rules](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment), this is the most robust option |
| `repo:my-org/my-app:ref:refs/tags/*` | Workflows triggered by any tag |
| `repo:my-org/my-app:ref:refs/heads/main` | Workflows running on the `main` branch |
| `repo:my-org/my-app:*` | Any workflow in the repository, including pull requests |

For **GitLab CI**, the issuer is the address of your GitLab instance (such as `https://gitlab.com`), and subjects look like `project_path:my-group/my-app:ref_type:branch:ref:main`.

## Using the CLI

Pass the token as the request key, and your user ID with `--user-id`:

```bash
revaulter-cli sign \
  --server https://revaulter.example.com \
  --request-key "$OIDC_TOKEN" \
  --user-id "$REVAULTER_USER_ID" \
  --key-label release-signing \
  --algorithm ES256 \
  --input dist/myapp
```

See [Signing a release binary from GitHub Actions](/examples/signing-a-release-binary-from-github-actions/) for a complete workflow.

If the token is in a file that's renewed in place, such as a Kubernetes projected service account token, pass it with `--request-key-file` instead. The CLI reads the file again for every request, so long-running commands like `ssh-agent` keep using a current token.

API users send the token in the `Authorization: Bearer <token>` header, and the user ID in the `X-Revaulter-User` header. See the [REST API reference](/advanced/rest-api-reference/#request-endpoints-v2request). Go applications can use the `OIDCToken` option of the [Go library](/advanced/go-library/).

## Audit log

Requests authenticated with an OIDC token are recorded with the `request_oidc` authentication method. The `request.create` event includes the token's verified issuer, subject, and ID (`jti`), so you can tell which workload sent each request. Changes to the trusted issuers, and enabling or disabling an authentication method, are audited too. See [Audit events](/advanced/audit-events/).
