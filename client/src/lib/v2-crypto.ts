import { Encode as Base64UrlEncode } from 'arraybuffer-encoding/base64/url'
import type { EcP256PublicJwk, V2ResponseEnvelope } from './v2-types'
import { base64UrlToBytes } from './utils'

/** Casts browser binary inputs to the `BufferSource` shape expected by WebCrypto */
function asBuf(v?: Uint8Array | ArrayBuffer): BufferSource | undefined {
    if (v === undefined) {
        return undefined
    }
    return v as unknown as BufferSource
}

/** Returns an owned `ArrayBuffer`, copying when the input is a `Uint8Array` view. */
function toArrayBuffer(bytes: ArrayBuffer | Uint8Array): ArrayBuffer {
    if (bytes instanceof Uint8Array) {
        // Copy typed array views into a standalone buffer before encoding
        const out = new Uint8Array(bytes.byteLength)
        out.set(bytes)
        return out.buffer
    }

    return bytes
}

/** Encodes bytes using unpadded base64url, which is the wire format */
function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
    return Base64UrlEncode(toArrayBuffer(bytes))
}

/**
 * Generates an ephemeral ECDH P-256 key pair for transport encryption and exports
 * the public half as a compact JWK to send over the API.
 */
export async function generateTransportKeyPairJwk(): Promise<{
    privateKey: CryptoKey
    publicKeyJwk: EcP256PublicJwk
}> {
    // Generate an extractable ECDH key pair so the public key can be exported as JWK
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
    const jwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey

    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
        throw new Error('Failed to export transport public key as P-256 JWK')
    }

    return {
        privateKey: keyPair.privateKey,
        publicKeyJwk: {
            kty: 'EC',
            crv: 'P-256',
            x: jwk.x,
            y: jwk.y,
        },
    }
}

/**
 * Derives the symmetric AES transport key shared between the requester and the
 * browser approver. The request `state` is mixed into HKDF so the transport key
 * is scoped to a single pending request.
 */
async function deriveTransportAesKey(
    state: string,
    privateKey: CryptoKey,
    peerPublicJwk: EcP256PublicJwk
): Promise<CryptoKey> {
    // Import the peer ECDH key
    const peerKey = await crypto.subtle.importKey(
        'jwk',
        peerPublicJwk as JsonWebKey,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    )

    // Derive the raw ECDH shared secret from the local private key and peer public key
    const sharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, privateKey, 256)

    // Re-import the shared secret so HKDF can expand it into a symmetric AES key
    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey'])

    // Bind the transport key to the request state
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(),
            info: new TextEncoder().encode(`revaulter/v2/transport/${state}`),
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )
}

/**
 * Encrypts the browser response envelope that is sent back to the original CLI/client.
 * A fresh ephemeral ECDH key is generated for each response and included in the envelope.
 */
export async function encryptTransportEnvelope(
    state: string,
    clientTransportKey: EcP256PublicJwk,
    plaintext: Uint8Array,
    aad?: Uint8Array
): Promise<V2ResponseEnvelope> {
    // Generate a one-off browser transport key pair for this response
    const eph = await generateTransportKeyPairJwk()
    const aesKey = await deriveTransportAesKey(state, eph.privateKey, clientTransportKey)
    const nonce = crypto.getRandomValues(new Uint8Array(12))

    // Encrypt the payload and optionally bind caller-provided AAD into the AES-GCM tag
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: asBuf(nonce),
            additionalData: asBuf(aad),
        },
        aesKey,
        asBuf(plaintext) as BufferSource
    )

    // Return the encrypted response in the API envelope format expected by clients
    return {
        transportAlg: 'ecdh-p256+a256gcm',
        browserEphemeralPublicKey: eph.publicKeyJwk,
        nonce: bytesToBase64Url(nonce),
        ciphertext: bytesToBase64Url(ciphertext),
        aad: aad && aad.length > 0 ? bytesToBase64Url(aad) : undefined,
        resultType: 'bytes',
    }
}

/**
 * Decrypts a transport envelope using the requester's private transport key.
 * The same request `state` must be supplied so HKDF derives the matching AES key.
 */
export async function decryptTransportEnvelope(
    state: string,
    privateKey: CryptoKey,
    env: V2ResponseEnvelope
): Promise<Uint8Array> {
    // Re-derive the symmetric key from the local private key and browser ephemeral public key
    const aesKey = await deriveTransportAesKey(state, privateKey, env.browserEphemeralPublicKey)

    // Decode the envelope fields and verify the AES-GCM tag during decryption
    const plain = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: asBuf(base64UrlToBytes(env.nonce)) as BufferSource,
            additionalData: asBuf(env.aad ? base64UrlToBytes(env.aad) : undefined),
        },
        aesKey,
        asBuf(base64UrlToBytes(env.ciphertext)) as BufferSource
    )

    return new Uint8Array(plain)
}

/**
 * Computes the PRF salt used during WebAuthn PRF evaluation. When a password is
 * present, it is mixed in with HMAC so the effective salt changes per password.
 */
export async function computePrfSalt(basePrfSalt: Uint8Array, password?: string): Promise<Uint8Array> {
    if (!password) {
        return basePrfSalt
    }

    // Use the server-provided base salt as the HMAC key and the password as the message
    const key = await crypto.subtle.importKey(
        'raw',
        asBuf(basePrfSalt) as BufferSource,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    )

    const sig = await crypto.subtle.sign('HMAC', key, asBuf(new TextEncoder().encode(password)) as BufferSource)
    return new Uint8Array(sig)
}

/**
 * Derives the logical operation key bytes used for application crypto such as
 * AES-GCM encryption/decryption. The derived key is bound to the target user,
 * key label, algorithm, and optionally the password.
 */
export async function deriveOperationKeyBytes(params: {
    targetUser: string
    keyLabel: string
    algorithm: string
    prfSecret: Uint8Array
    password?: string
}): Promise<Uint8Array> {
    // Import the WebAuthn PRF output as the HKDF input keying material
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.prfSecret) as BufferSource, 'HKDF', false, [
        'deriveBits',
    ])

    // If a password is present, mix it in as HKDF salt so the derived key depends on both factors
    const salt = params.password ? new TextEncoder().encode(params.password) : new Uint8Array()
    const infoObj = {
        v: 1,
        targetUser: params.targetUser,
        keyLabel: params.keyLabel,
        algorithm: params.algorithm,
    }

    // Bind the key to the logical key identity so encrypt/decrypt requests derive the same bytes
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: asBuf(salt) as BufferSource,
            info: new TextEncoder().encode(JSON.stringify(infoObj)),
        },
        ikm,
        256
    )
    return new Uint8Array(bits)
}

/** Derives the AES key used to encrypt and verify the password canary value. */
async function deriveCanaryKey(password: string): Promise<CryptoKey> {
    // Treat the password as HKDF input keying material to get a stable canary key
    const ikm = await crypto.subtle.importKey(
        'raw',
        asBuf(new TextEncoder().encode(password)) as BufferSource,
        'HKDF',
        false,
        ['deriveKey']
    )

    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(),
            info: new TextEncoder().encode('revaulter/v2/password-canary'),
        },
        ikm,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )
}

/** Encrypts a fixed canary string so the client can later verify a password locally. */
export async function encryptPasswordCanary(password: string): Promise<string> {
    const key = await deriveCanaryKey(password)
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode('revaulter-password-ok')

    // AES-GCM output already contains the authentication tag appended to the ciphertext
    const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: asBuf(nonce) as BufferSource },
        key,
        asBuf(plaintext) as BufferSource
    )

    // Persist the canary as `nonce.ciphertext`, both encoded as base64url
    return `${bytesToBase64Url(nonce)}.${bytesToBase64Url(ct)}`
}

/** Verifies that a password can decrypt the stored canary without authentication failure. */
export async function verifyPasswordCanary(password: string, canary: string): Promise<boolean> {
    const parts = canary.split('.')
    if (parts.length !== 2) {
        return false
    }
    try {
        // Split the serialized canary back into nonce and combined ciphertext+tag
        const nonce = base64UrlToBytes(parts[0])
        const ct = base64UrlToBytes(parts[1])
        const key = await deriveCanaryKey(password)

        // We do not need to inspect the plaintext here: AES-GCM auth failure is enough to reject the password
        await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: asBuf(nonce) as BufferSource },
            key,
            asBuf(ct) as BufferSource
        )
        return true
    } catch {
        return false
    }
}

/**
 * Performs the requested AES-GCM operation with the derived key bytes. For decrypt,
 * callers may pass the authentication tag separately and it will be recombined into
 * the format expected by WebCrypto.
 */
export async function performAesGcmOperation(params: {
    mode: 'encrypt' | 'decrypt'
    keyBytes: Uint8Array
    value: Uint8Array
    nonce?: Uint8Array
    aad?: Uint8Array
    tag?: Uint8Array
}): Promise<Uint8Array> {
    // Import the raw operation key bytes as an AES-GCM CryptoKey
    const key = await crypto.subtle.importKey(
        'raw',
        asBuf(params.keyBytes) as BufferSource,
        { name: 'AES-GCM' },
        false,
        [params.mode === 'encrypt' ? 'encrypt' : 'decrypt']
    )

    // Use the supplied nonce when present, otherwise generate one for encryption callers
    const iv = params.nonce ?? crypto.getRandomValues(new Uint8Array(12))

    if (params.mode === 'encrypt') {
        // Encrypt the plaintext and bind any additional authenticated data into the tag
        const res = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: asBuf(iv) as BufferSource, additionalData: asBuf(params.aad) },
            key,
            asBuf(params.value) as BufferSource
        )
        return new Uint8Array(res)
    }

    // WebCrypto expects ciphertext and tag in a single buffer, so rebuild that shape when needed
    const combined =
        params.tag && params.tag.length > 0
            ? (() => {
                  const out = new Uint8Array(params.value.length + params.tag.length)
                  out.set(params.value, 0)
                  out.set(params.tag, params.value.length)
                  return out
              })()
            : params.value

    try {
        // Decrypt and authenticate the combined ciphertext in one WebCrypto call
        const res = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: asBuf(iv) as BufferSource, additionalData: asBuf(params.aad) },
            key,
            asBuf(combined) as BufferSource
        )
        return new Uint8Array(res)
    } catch {
        throw new Error(
            'Decryption failed. This normally means that the the ciphertext could not be authenticated. Check that the key label, target user, password, nonce, tag, and additional data match the original encryption request.'
        )
    }
}

/** Splits WebCrypto's combined AES-GCM output into ciphertext and tag segments. */
export function splitAesGcmCiphertextAndTag(ciphertextWithTag: Uint8Array, tagLen = 16) {
    if (ciphertextWithTag.length < tagLen) {
        throw new Error('Ciphertext is too short')
    }

    // AES-GCM appends the authentication tag to the end of the ciphertext
    return {
        data: ciphertextWithTag.slice(0, ciphertextWithTag.length - tagLen),
        tag: ciphertextWithTag.slice(ciphertextWithTag.length - tagLen),
    }
}

/** Convenience wrapper that treats missing values as an empty byte array. */
export function b64urlToBytes(s?: string): Uint8Array {
    return s ? base64UrlToBytes(s) : new Uint8Array()
}

/** Convenience wrapper for base64url-encoding `Uint8Array` values. */
export function bytesToB64url(v: Uint8Array): string {
    return bytesToBase64Url(v)
}
