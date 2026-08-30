import { extractCredentialPublicKeyCose } from '$lib/cose-extract'
import { asBuf, base64UrlToBytes, bytesToBase64Url } from '$lib/utils'

// generatePrfSalt creates a random 32-byte salt for the WebAuthn PRF extension
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

// cloneAndDecodeWebAuthnOptions clones server options and decodes WebAuthn binary fields from base64url
function cloneAndDecodeWebAuthnOptions<T>(input: T, skipBinaryDecoding = false): T {
    if (input === null || input === undefined) {
        return input
    }

    // Arrays can contain nested credential descriptors whose IDs also require decoding
    if (Array.isArray(input)) {
        return input.map((v) => cloneAndDecodeWebAuthnOptions(v, skipBinaryDecoding)) as T
    }

    if (typeof input === 'object') {
        const out: Record<string, unknown> = {}
        for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
            // WebAuthn JSON represents binary request fields as base64url but the Credentials API requires BufferSource values
            if (
                !skipBinaryDecoding &&
                (k === 'challenge' || k === 'id' || k === 'rawId' || k === 'userHandle') &&
                typeof v === 'string'
            ) {
                out[k] = base64UrlToBytes(v)
                continue
            }
            // Propagate skipBinaryDecoding into rp to preserve domain strings like rp.id and rp.name
            out[k] = cloneAndDecodeWebAuthnOptions(v, skipBinaryDecoding || k === 'rp')
        }
        return out as T
    }

    return input
}

export function serializeWebAuthnExtensionResults(input: unknown): unknown {
    return serializeWebAuthnExtensionValue(input, [])
}

// serializeWebAuthnExtensionValue recursively serializes one WebAuthn extension value
// Browsers expose extension output with inconsistent binary representations so each representation is handled explicitly
function serializeWebAuthnExtensionValue(input: unknown, path: string[]): unknown {
    // Use the intrinsic tag because ArrayBuffers created in another window do not pass the local instanceof check
    if (Object.prototype.toString.call(input) === '[object ArrayBuffer]') {
        return bytesToBase64Url(new Uint8Array(input as ArrayBuffer))
    }

    // ArrayBuffer.isView covers typed arrays and DataView values returned by browser implementations
    if (ArrayBuffer.isView(input)) {
        // Copy only the view range because its backing buffer may contain unrelated bytes before or after the value
        const bytes = new Uint8Array(input.byteLength)
        bytes.set(new Uint8Array(input.buffer, input.byteOffset, input.byteLength))
        return bytesToBase64Url(bytes)
    }

    // Some browsers turn PRF buffers into ordinary number arrays while building the credential JSON
    if (Array.isArray(input)) {
        // Restrict this compatibility conversion to PRF result fields so legitimate arrays from other extensions keep their shape
        const isPrfResult =
            path.length === 3 &&
            path[0] === 'prf' &&
            path[1] === 'results' &&
            (path[2] === 'first' || path[2] === 'second')
        if (isPrfResult && input.every((value) => Number.isInteger(value) && value >= 0 && value <= 255)) {
            return bytesToBase64Url(Uint8Array.from(input as number[]))
        }

        // Preserve non-binary arrays and continue recursively in case they contain nested binary values
        return input.map((value, index) => serializeWebAuthnExtensionValue(value, [...path, String(index)]))
    }

    // Extension output is an open-ended dictionary so recurse instead of enumerating known extension names
    if (input !== null && typeof input === 'object') {
        return Object.fromEntries(
            Object.entries(input).map(([key, value]) => [key, serializeWebAuthnExtensionValue(value, [...path, key])])
        )
    }

    return input
}

// serializePublicKeyCredential converts a browser credential to the JSON shape expected by the server
export function serializePublicKeyCredential(cred: PublicKeyCredential) {
    const clientExtensionResults = cred.getClientExtensionResults?.()
    const serializedExtensionResults = clientExtensionResults
        ? serializeWebAuthnExtensionResults(clientExtensionResults)
        : undefined

    // Prefer the browser serializer because it includes response fields added by newer WebAuthn specifications
    const credentialWithToJSON = cred as PublicKeyCredential & { toJSON?: () => unknown }
    if (typeof credentialWithToJSON.toJSON === 'function') {
        const serialized = credentialWithToJSON.toJSON()
        if (serialized !== null && typeof serialized === 'object') {
            return {
                ...(serialized as unknown as Record<string, unknown>),
                // Replace the native extension JSON because some browsers leave PRF output as number arrays or binary objects
                clientExtensionResults: serializedExtensionResults,
            }
        }
    }

    // Older browsers lack toJSON so serialize the stable credential fields manually
    const base = {
        id: cred.id,
        rawId: bytesToBase64Url(new Uint8Array(cred.rawId)),
        type: cred.type,
        clientExtensionResults: serializedExtensionResults,
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

// webauthnRegister creates a passkey and returns its serialized registration data
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

// webauthnLoginWithPrf authenticates with a passkey and derives a secret through the PRF extension
export async function webauthnLoginWithPrf(args: {
    challenge: string
    prfSalt?: Uint8Array
    options?: unknown
}): Promise<{ id: string; signCount: number; prfSecret?: Uint8Array; raw?: unknown }> {
    const salt = args.prfSalt ?? generatePrfSalt()
    // Copy the view into a standalone ArrayBuffer because WebAuthn accepts BufferSource but the PRF type requires ArrayBuffer
    const saltBuffer = salt.slice().buffer as ArrayBuffer
    if (!('credentials' in navigator) || typeof PublicKeyCredential === 'undefined') {
        throw new Error('WebAuthn is not available in this browser')
    }

    // Prefer server-provided request policy but retain the fallback for callers that only provide a challenge
    const reqOptions =
        args.options && typeof args.options === 'object' && 'publicKey' in (args.options as Record<string, unknown>)
            ? (cloneAndDecodeWebAuthnOptions(args.options) as { publicKey: PublicKeyCredentialRequestOptions })
                  .publicKey
            : null

    // Override the challenge and PRF input because these values belong to this login attempt
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
