import { asBuf, base64UrlToBytes, bytesToBase64Url } from './utils'

export function generatePrfSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32))
}

function cloneAndDecodeWebAuthnOptions<T>(input: T, skipBinaryDecoding = false): T {
    if (input === null || input === undefined) {
        return input
    }

    if (Array.isArray(input)) {
        return input.map((v) => cloneAndDecodeWebAuthnOptions(v, skipBinaryDecoding)) as T
    }

    if (typeof input === 'object') {
        const out: Record<string, unknown> = {}
        for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
            if (
                !skipBinaryDecoding &&
                (k === 'challenge' || k === 'id' || k === 'rawId' || k === 'userHandle') &&
                typeof v === 'string'
            ) {
                out[k] = base64UrlToBytes(v)
                continue
            }
            // Propagate skipBinaryDecoding into 'rp' to preserve domain strings like rp.id and rp.name.
            out[k] = cloneAndDecodeWebAuthnOptions(v, skipBinaryDecoding || k === 'rp')
        }
        return out as T
    }

    return input
}

function serializePublicKeyCredential(cred: PublicKeyCredential) {
    const base = {
        id: cred.id,
        rawId: bytesToBase64Url(new Uint8Array(cred.rawId)),
        type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults?.() || undefined,
    }

    if (cred.response instanceof AuthenticatorAttestationResponse) {
        return {
            ...base,
            response: {
                attestationObject: bytesToBase64Url(new Uint8Array(cred.response.attestationObject)),
                clientDataJSON: bytesToBase64Url(new Uint8Array(cred.response.clientDataJSON)),
            },
        }
    }

    if (cred.response instanceof AuthenticatorAssertionResponse) {
        return {
            ...base,
            response: {
                authenticatorData: bytesToBase64Url(new Uint8Array(cred.response.authenticatorData)),
                clientDataJSON: bytesToBase64Url(new Uint8Array(cred.response.clientDataJSON)),
                signature: bytesToBase64Url(new Uint8Array(cred.response.signature)),
                userHandle: cred.response.userHandle
                    ? bytesToBase64Url(new Uint8Array(cred.response.userHandle))
                    : undefined,
            },
        }
    }

    return base
}

export async function webauthnRegister(args: {
    username: string
    displayName: string
    challenge: string
    options?: unknown
}): Promise<{ id: string; publicKey: string; signCount: number; raw?: unknown }> {
    if (!('credentials' in navigator) || typeof PublicKeyCredential === 'undefined') {
        throw new Error('WebAuthn is not available in this browser')
    }

    const userId = crypto.getRandomValues(new Uint8Array(16))
    const creationOptions =
        args.options && typeof args.options === 'object' && 'publicKey' in (args.options as Record<string, unknown>)
            ? (
                  cloneAndDecodeWebAuthnOptions(args.options) as PublicKeyCredentialCreationOptionsJSON & {
                      publicKey: PublicKeyCredentialCreationOptions
                  }
              ).publicKey
            : null
    const cred = (await navigator.credentials.create({
        publicKey: creationOptions ?? {
            challenge: asBuf(base64UrlToBytes(args.challenge)),
            rp: { name: 'Revaulter' },
            user: {
                id: asBuf(userId),
                name: args.username,
                displayName: args.displayName,
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 60_000,
            attestation: 'none',
        },
    })) as PublicKeyCredential | null

    if (!cred) {
        throw new Error('WebAuthn registration was canceled')
    }

    const resp = cred.response as AuthenticatorAttestationResponse
    return {
        id: cred.id,
        // The server verifies the registration response and extracts the credential; this field is ignored in the verified path.
        publicKey: bytesToBase64Url(new Uint8Array(resp.attestationObject)),
        signCount: 0,
        raw: {
            credential: serializePublicKeyCredential(cred),
            clientDataJSON: bytesToBase64Url(new Uint8Array(resp.clientDataJSON)),
        },
    }
}

export async function webauthnLoginWithPrf(args: {
    challenge: string
    prfSalt?: Uint8Array
    options?: unknown
}): Promise<{ id: string; signCount: number; prfSecret?: Uint8Array; raw?: unknown }> {
    const salt = args.prfSalt ?? generatePrfSalt()
    if (!('credentials' in navigator) || typeof PublicKeyCredential === 'undefined') {
        throw new Error('WebAuthn is not available in this browser')
    }

    const reqOptions =
        args.options && typeof args.options === 'object' && 'publicKey' in (args.options as Record<string, unknown>)
            ? (cloneAndDecodeWebAuthnOptions(args.options) as { publicKey: PublicKeyCredentialRequestOptions })
                  .publicKey
            : null
    const effectivePublicKey: PublicKeyCredentialRequestOptions = reqOptions
        ? {
              ...reqOptions,
              challenge: asBuf(base64UrlToBytes(args.challenge)),
              extensions: {
                  ...(reqOptions.extensions || {}),
                  prf: {
                      eval: {
                          first: salt.buffer as ArrayBuffer,
                      },
                  },
              } as AuthenticationExtensionsClientInputs,
          }
        : {
              challenge: asBuf(base64UrlToBytes(args.challenge)),
              timeout: 60_000,
              userVerification: 'preferred',
              extensions: {
                  prf: {
                      eval: {
                          first: salt.buffer as ArrayBuffer,
                      },
                  },
              } as AuthenticationExtensionsClientInputs,
          }

    const assertion = (await navigator.credentials.get({
        publicKey: effectivePublicKey,
    })) as PublicKeyCredential | null

    if (!assertion) {
        throw new Error('WebAuthn authentication was canceled')
    }

    const resp = assertion.response as AuthenticatorAssertionResponse
    const ext = assertion.getClientExtensionResults() as {
        prf?: {
            enabled?: boolean
            results?: { first?: ArrayBuffer }
        }
    }

    const prfBuf = ext?.prf?.results?.first
    if (!prfBuf) {
        throw new Error('Authenticator did not return PRF output')
    }

    return {
        id: assertion.id,
        signCount: 0,
        prfSecret: new Uint8Array(prfBuf),
        raw: {
            credential: serializePublicKeyCredential(assertion),
            authenticatorData: bytesToBase64Url(new Uint8Array(resp.authenticatorData)),
            clientDataJSON: bytesToBase64Url(new Uint8Array(resp.clientDataJSON)),
            signature: bytesToBase64Url(new Uint8Array(resp.signature)),
            userHandle: resp.userHandle ? bytesToBase64Url(new Uint8Array(resp.userHandle)) : undefined,
            prfEnabled: ext?.prf?.enabled,
        },
    }
}
