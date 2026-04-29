import { extractCredentialPublicKeyCose } from '$lib/cose-extract'
import { asBuf, base64UrlToBytes, bytesToBase64Url } from '$lib/utils'

export function generatePrfSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32))
}

// Returns base64url(SHA-256(raw COSE credential public-key bytes)) for a WebAuthn attestation response
// The hash is taken over the exact CBOR bytes the authenticator wrote, which lets the server re-derive it from its stored COSE credential without any per-algorithm logic
// This matches the algorithm the server and works for any WebAuthn key type, including future post-quantum algorithms
export async function credentialPublicKeyHash(response: AuthenticatorAttestationResponse): Promise<string> {
    const cose = extractCredentialPublicKeyCose(response.attestationObject)
    const digest = await crypto.subtle.digest('SHA-256', asBuf(cose))
    return bytesToBase64Url(new Uint8Array(digest))
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
    options: unknown
}): Promise<{ id: string; publicKeyHash: string; signCount: number; raw?: unknown }> {
    if (!('credentials' in navigator) || typeof PublicKeyCredential === 'undefined') {
        throw new Error('WebAuthn is not available in this browser')
    }
    if (
        !args.options ||
        typeof args.options !== 'object' ||
        !('publicKey' in (args.options as Record<string, unknown>))
    ) {
        throw new Error('WebAuthn registration requires server-provided creation options')
    }

    const creationOptions = (
        cloneAndDecodeWebAuthnOptions(args.options) as PublicKeyCredentialCreationOptionsJSON & {
            publicKey: PublicKeyCredentialCreationOptions
        }
    ).publicKey

    const cred = (await navigator.credentials.create({
        publicKey: creationOptions,
    })) as PublicKeyCredential | null

    if (!cred) {
        throw new Error('WebAuthn registration was canceled')
    }

    const resp = cred.response as AuthenticatorAttestationResponse
    const publicKeyHash = await credentialPublicKeyHash(resp)
    return {
        id: cred.id,
        publicKeyHash,
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
    const saltBuffer = salt.slice().buffer as ArrayBuffer
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
                          first: saltBuffer,
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
                          first: saltBuffer,
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
