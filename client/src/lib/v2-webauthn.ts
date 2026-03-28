import { Decode as Base64UrlDecode } from 'arraybuffer-encoding/base64/url'
import { bytesToB64url } from './v2-crypto'

function asBuf(v: Uint8Array | ArrayBuffer): BufferSource {
    return v as unknown as BufferSource
}

function b64urlToBytes(s: string): Uint8Array {
    return new Uint8Array(Base64UrlDecode(s))
}

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
                out[k] = b64urlToBytes(v)
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
        rawId: bytesToB64url(new Uint8Array(cred.rawId)),
        type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults?.() || undefined,
    }

    if (cred.response instanceof AuthenticatorAttestationResponse) {
        return {
            ...base,
            response: {
                attestationObject: bytesToB64url(new Uint8Array(cred.response.attestationObject)),
                clientDataJSON: bytesToB64url(new Uint8Array(cred.response.clientDataJSON)),
            },
        }
    }
    if (cred.response instanceof AuthenticatorAssertionResponse) {
        return {
            ...base,
            response: {
                authenticatorData: bytesToB64url(new Uint8Array(cred.response.authenticatorData)),
                clientDataJSON: bytesToB64url(new Uint8Array(cred.response.clientDataJSON)),
                signature: bytesToB64url(new Uint8Array(cred.response.signature)),
                userHandle: cred.response.userHandle ? bytesToB64url(new Uint8Array(cred.response.userHandle)) : undefined,
            },
        }
    }
    return base
}

function allowPlaceholderWebAuthnFallback(): boolean {
    return import.meta.env.DEV && import.meta.env.VITE_ALLOW_WEBAUTHN_PLACEHOLDER === '1'
}

export async function webauthnRegisterPlaceholder(args: {
    username: string
    displayName: string
    challenge: string
    options?: unknown
}): Promise<{ id: string; publicKey: string; signCount: number; raw?: unknown }> {
    if (!('credentials' in navigator) || typeof PublicKeyCredential === 'undefined') {
        if (!allowPlaceholderWebAuthnFallback()) {
            throw new Error('WebAuthn is not available in this browser')
        }
        // Dev/test-only placeholder fallback.
        return {
            id: crypto.randomUUID(),
            publicKey: JSON.stringify({ mode: 'placeholder', username: args.username }),
            signCount: 0,
            raw: { id: crypto.randomUUID() },
        }
    }

    const userId = crypto.getRandomValues(new Uint8Array(16))
    const creationOptions =
        args.options && typeof args.options === 'object' && 'publicKey' in (args.options as Record<string, unknown>)
            ? (cloneAndDecodeWebAuthnOptions(args.options) as PublicKeyCredentialCreationOptionsJSON & {
                  publicKey: PublicKeyCredentialCreationOptions
              }).publicKey
            : null
    const cred = (await navigator.credentials.create({
        publicKey: creationOptions ?? {
            challenge: asBuf(b64urlToBytes(args.challenge)),
            rp: { name: 'Revaulter v2' },
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
        // Server-side verification is not implemented yet; persist the attestation blob as placeholder credential data.
        publicKey: bytesToB64url(new Uint8Array(resp.attestationObject)),
        signCount: 0,
        raw: {
            credential: serializePublicKeyCredential(cred),
            clientDataJSON: bytesToB64url(new Uint8Array(resp.clientDataJSON)),
        },
    }
}

export async function webauthnLoginWithPrfPlaceholder(args: {
    challenge: string
    allowedCredentialIds?: string[]
    prfSalt?: Uint8Array
    options?: unknown
}): Promise<{ id: string; signCount: number; prfSecret?: Uint8Array; raw?: unknown }> {
    const salt = args.prfSalt ?? generatePrfSalt()
    if (!('credentials' in navigator) || typeof PublicKeyCredential === 'undefined') {
        if (!allowPlaceholderWebAuthnFallback()) {
            throw new Error('WebAuthn is not available in this browser')
        }
        return {
            id: (args.allowedCredentialIds && args.allowedCredentialIds[0]) || crypto.randomUUID(),
            signCount: 0,
            prfSecret: salt,
        }
    }

    const allowCredentials =
        args.allowedCredentialIds?.map((id) => ({
            type: 'public-key' as const,
            id: b64urlToBytes(id),
        })) ?? []

    const reqOptions =
        args.options && typeof args.options === 'object' && 'publicKey' in (args.options as Record<string, unknown>)
            ? (cloneAndDecodeWebAuthnOptions(args.options) as { publicKey: PublicKeyCredentialRequestOptions }).publicKey
            : null
    const effectivePublicKey: PublicKeyCredentialRequestOptions = reqOptions
        ? {
              ...reqOptions,
              challenge: asBuf(b64urlToBytes(args.challenge)),
              allowCredentials:
                  (reqOptions.allowCredentials as PublicKeyCredentialDescriptor[] | undefined)?.map((c) => ({
                      ...c,
                      id: asBuf(c.id as unknown as Uint8Array | ArrayBuffer),
                  })) ?? allowCredentials.map((c) => ({ ...c, id: asBuf(c.id) })),
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
              challenge: asBuf(b64urlToBytes(args.challenge)),
              timeout: 60_000,
              allowCredentials: allowCredentials.map((c) => ({ ...c, id: asBuf(c.id) })),
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
            authenticatorData: bytesToB64url(new Uint8Array(resp.authenticatorData)),
            clientDataJSON: bytesToB64url(new Uint8Array(resp.clientDataJSON)),
            signature: bytesToB64url(new Uint8Array(resp.signature)),
            userHandle: resp.userHandle ? bytesToB64url(new Uint8Array(resp.userHandle)) : undefined,
            prfEnabled: ext?.prf?.enabled,
        },
    }
}
