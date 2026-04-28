import { argon2id } from '@awasm/noble'
import { mapHashToField } from '@noble/curves/abstract/modular.js'
import { p256 } from '@noble/curves/nist.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

import { deriveEcdhSharedSecret, ecP256ScalarToPublicJwk, generateTransportKeyPairJwk } from '$lib/crypto-ecdh'
import { normalizeAeadAlgorithm } from '$lib/crypto-symmetric'
import { asBuf, base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import type {
    Argon2idCost,
    EcP256PublicJwk,
    V2RequestPayloadInner,
    V2ResponseEnvelope,
    V2SigningJwk,
} from '$lib/v2-types'

/**
 * Derives the hybrid ECDH + ML-KEM shared secret, then expands it via HKDF into an AES-256-GCM key
 * Handles both the encapsulate (encrypt) and decapsulate (decrypt) sides of ML-KEM so callers don't touch ML-KEM directly
 * The request `state` is mixed into HKDF so the key is scoped to a single pending request
 */
async function deriveTransportAesKeyForEncrypt(
    state: string,
    ecdhScalar: Uint8Array,
    peerEcdhPublicJwk: EcP256PublicJwk,
    peerMlkemKeyB64: string
): Promise<{ aesKey: CryptoKey; mlkemCiphertext: Uint8Array }> {
    // ECDH shared secret
    const ecdhShared = deriveEcdhSharedSecret(ecdhScalar, peerEcdhPublicJwk)

    // ML-KEM encapsulation
    const mlkemPubBytes = base64UrlToBytes(peerMlkemKeyB64)
    const { cipherText: mlkemCT, sharedSecret: mlkemShared } = ml_kem768.encapsulate(mlkemPubBytes)

    const aesKey = await deriveHybridAesKey(ecdhShared, mlkemShared, `revaulter/v2/transport/${state}`)
    return { aesKey, mlkemCiphertext: mlkemCT }
}

async function deriveTransportAesKeyForDecrypt(
    state: string,
    ecdhScalar: Uint8Array,
    peerEcdhPublicJwk: EcP256PublicJwk,
    mlkemSecretKey: Uint8Array,
    mlkemCiphertext: Uint8Array
): Promise<CryptoKey> {
    // ECDH shared secret
    const ecdhShared = deriveEcdhSharedSecret(ecdhScalar, peerEcdhPublicJwk)

    // ML-KEM decapsulation
    const mlkemShared = ml_kem768.decapsulate(mlkemCiphertext, mlkemSecretKey)

    return deriveHybridAesKey(ecdhShared, mlkemShared, `revaulter/v2/transport/${state}`)
}

/** Combines ECDH + ML-KEM shared secrets and derives an AES-256-GCM key via HKDF-SHA256 */
async function deriveHybridAesKey(
    ecdhShared: Uint8Array,
    mlkemShared: Uint8Array,
    hkdfInfo: string
): Promise<CryptoKey> {
    const combined = new Uint8Array(ecdhShared.length + mlkemShared.length)
    combined.set(ecdhShared, 0)
    combined.set(mlkemShared, ecdhShared.length)

    const hkdfKey = await crypto.subtle.importKey('raw', combined, 'HKDF', false, ['deriveKey'])
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(),
            info: new TextEncoder().encode(hkdfInfo),
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )
}

/**
 * Encrypts the browser response envelope that is sent back to the original CLI/client.
 * Uses hybrid ECDH + ML-KEM key exchange: a fresh ephemeral ECDH key is generated, and ML-KEM encapsulation is performed against the CLI's transport ML-KEM public key.
 */
export async function encryptTransportEnvelope(
    state: string,
    clientTransportEcdhKey: EcP256PublicJwk,
    clientTransportMlkemKey: string,
    plaintext: Uint8Array,
    aad?: Uint8Array
): Promise<V2ResponseEnvelope> {
    const eph = generateTransportKeyPairJwk()
    const { aesKey, mlkemCiphertext } = await deriveTransportAesKeyForEncrypt(
        state,
        eph.scalar,
        clientTransportEcdhKey,
        clientTransportMlkemKey
    )
    const nonce = crypto.getRandomValues(new Uint8Array(12))

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: asBuf(nonce),
            additionalData: asBuf(aad),
        },
        aesKey,
        asBuf(plaintext) as BufferSource
    )

    return {
        transportAlg: 'ecdh-p256+mlkem768+a256gcm',
        browserEphemeralPublicKey: eph.publicKeyJwk,
        mlkemCiphertext: bytesToBase64Url(mlkemCiphertext),
        nonce: bytesToBase64Url(nonce),
        ciphertext: bytesToBase64Url(ciphertext),
        resultType: 'bytes',
    }
}

/**
 * Decrypts a transport envelope using hybrid ECDH + ML-KEM
 * The same request `state` must be supplied so HKDF derives the matching AES key
 *
 * `ecdhScalar` is the raw 32-byte P-256 private scalar of the local transport key (the same shape `generateTransportKeyPairJwk` returns)
 */
export async function decryptTransportEnvelope(
    state: string,
    ecdhScalar: Uint8Array,
    mlkemSecretKey: Uint8Array,
    env: V2ResponseEnvelope,
    aad?: Uint8Array
): Promise<Uint8Array> {
    const mlkemCT = base64UrlToBytes(env.mlkemCiphertext)
    const aesKey = await deriveTransportAesKeyForDecrypt(
        state,
        ecdhScalar,
        env.browserEphemeralPublicKey,
        mlkemSecretKey,
        mlkemCT
    )

    const plain = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: asBuf(base64UrlToBytes(env.nonce)) as BufferSource,
            additionalData: aad ? asBuf(aad) : undefined,
        },
        aesKey,
        asBuf(base64UrlToBytes(env.ciphertext))
    )

    return new Uint8Array(plain)
}

/**
 * Generates a random 256-bit primary key
 * This key is the root of all key derivation and is wrapped (encrypted) before storage
 */
export async function generatePrimaryKey(): Promise<Uint8Array> {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
    return new Uint8Array(await crypto.subtle.exportKey('raw', key))
}

/**
 * Wrapped primary key envelope format
 * Serialized as compact JSON then base64url-encoded for storage
 */
export type WrappedPrimaryKeyEnvelope = {
    v: 1
    passwordRequired: boolean
    argon2id?: {
        m: number
        t: number
        p: number
        salt: string // base64url
    }
    nonce: string // base64url
    ciphertext: string // base64url (AES-GCM ciphertext + tag)
}

/**
 * Derives the wrapping key used to wrap/unwrap the primary key
 * When a password is set, it is stretched via Argon2id before being used as HKDF salt
 * The Argon2id cost MUST be supplied by the caller: use the build-time `argon2idCost` constant for fresh wraps, or the cost stored inside the envelope being unwrapped
 */
export async function deriveWrappingKey(params: {
    prfSecret: Uint8Array
    userId: string
    password?: string
    argon2idSalt?: Uint8Array
    argon2idCost?: Argon2idCost
}): Promise<{
    wrappingKeyBytes: Uint8Array
    stretched?: Uint8Array
    argon2idSalt?: Uint8Array
    argon2idCost?: Argon2idCost
}> {
    let hkdfSalt: BufferSource = new Uint8Array()
    let stretched: Uint8Array | undefined
    let usedArgon2idSalt: Uint8Array | undefined
    let usedArgon2idCost: Argon2idCost | undefined

    if (params.password) {
        if (!params.argon2idCost) {
            throw new Error('argon2idCost is required when a password is provided')
        }

        usedArgon2idSalt = params.argon2idSalt ?? crypto.getRandomValues(new Uint8Array(16))
        usedArgon2idCost = params.argon2idCost
        stretched = await argon2id.async(params.password, usedArgon2idSalt, {
            t: usedArgon2idCost.t,
            m: usedArgon2idCost.m,
            p: usedArgon2idCost.p,
            dkLen: 32,
        })
        hkdfSalt = asBuf(stretched)
    }

    const ikm = await crypto.subtle.importKey('raw', asBuf(params.prfSecret), 'HKDF', false, ['deriveBits'])
    const info = new TextEncoder().encode(`revaulter/v2/primaryKeyWrap\nuserId=${params.userId}\nv=1`)

    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: hkdfSalt,
            info: asBuf(info),
        },
        ikm,
        256
    )

    return {
        wrappingKeyBytes: new Uint8Array(bits),
        stretched,
        argon2idSalt: usedArgon2idSalt,
        argon2idCost: usedArgon2idCost,
    }
}

/**
 * Wraps (encrypts) the primary key using AES-256-GCM and returns a base64url-encoded JSON envelope
 */
export async function wrapPrimaryKey(params: {
    primaryKey: Uint8Array
    wrappingKeyBytes: Uint8Array
    userId: string
    passwordRequired: boolean
    argon2idSalt?: Uint8Array
    argon2idCost?: Argon2idCost
}): Promise<string> {
    const wrappingKey = await crypto.subtle.importKey(
        'raw',
        asBuf(params.wrappingKeyBytes),
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    )
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const aad = new TextEncoder().encode(`revaulter/v2/wrapped-primary-key\nuserId=${params.userId}\nv=1`)

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: asBuf(nonce), additionalData: asBuf(aad) },
        wrappingKey,
        asBuf(params.primaryKey)
    )

    const envelope: WrappedPrimaryKeyEnvelope = {
        v: 1,
        passwordRequired: params.passwordRequired,
        nonce: bytesToBase64Url(nonce),
        ciphertext: bytesToBase64Url(ciphertext),
    }

    if (params.passwordRequired) {
        if (!params.argon2idSalt || !params.argon2idCost) {
            throw new Error('argon2idSalt and argon2idCost are required when passwordRequired is true')
        }

        envelope.argon2id = {
            m: params.argon2idCost.m,
            t: params.argon2idCost.t,
            p: params.argon2idCost.p,
            salt: bytesToBase64Url(params.argon2idSalt),
        }
    }

    const json = JSON.stringify(envelope)
    return bytesToBase64Url(new TextEncoder().encode(json))
}

/**
 * Parses and validates a wrapped primary key envelope from its base64url-encoded form
 */
export function parseWrappedPrimaryKeyEnvelope(wrapped: string): WrappedPrimaryKeyEnvelope {
    const json = new TextDecoder().decode(base64UrlToBytes(wrapped))
    const envelope = JSON.parse(json) as WrappedPrimaryKeyEnvelope

    if (envelope.v !== 1) {
        throw new Error(`Unsupported wrapped key version: ${envelope.v}`)
    }
    if (typeof envelope.passwordRequired !== 'boolean') {
        throw new Error('Invalid wrapped key envelope: missing passwordRequired')
    }
    if (!envelope.nonce || !envelope.ciphertext) {
        throw new Error('Invalid wrapped key envelope: missing nonce or ciphertext')
    }

    if (envelope.passwordRequired) {
        if (
            !envelope.argon2id ||
            typeof envelope.argon2id.m !== 'number' ||
            typeof envelope.argon2id.t !== 'number' ||
            typeof envelope.argon2id.p !== 'number' ||
            !envelope.argon2id.salt
        ) {
            throw new Error('Invalid wrapped key envelope: password required but argon2id params missing')
        }
    }

    return envelope
}

/**
 * Unwraps (decrypts) the primary key from a wrapped envelope
 * Throws on authentication failure (wrong password or corrupted data)
 */
export async function unwrapPrimaryKey(params: {
    wrapped: string
    wrappingKeyBytes: Uint8Array
    userId: string
}): Promise<Uint8Array> {
    const envelope = parseWrappedPrimaryKeyEnvelope(params.wrapped)

    const wrappingKey = await crypto.subtle.importKey(
        'raw',
        asBuf(params.wrappingKeyBytes),
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    )
    const nonce = base64UrlToBytes(envelope.nonce)
    const ciphertext = base64UrlToBytes(envelope.ciphertext)
    const aad = new TextEncoder().encode(`revaulter/v2/wrapped-primary-key\nuserId=${params.userId}\nv=1`)

    try {
        const primaryKey = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: asBuf(nonce), additionalData: asBuf(aad) },
            wrappingKey,
            asBuf(ciphertext)
        )
        return new Uint8Array(primaryKey)
    } catch {
        throw new Error('Failed to unwrap primary key. The password or passkey may be incorrect.')
    }
}

/**
 * Derives the logical operation key bytes used for application crypto such as
 * AES-GCM and ChaCha20-Poly1305 encryption/decryption
 * The derived key is bound to the user ID, key label, and algorithm
 *
 * Known AEAD algorithm names are canonicalized via `normalizeAeadAlgorithm` before binding into HKDF info, so encrypt and decrypt may use different accepted spellings (e.g. `A256GCM` and `aes-256-gcm`) and still produce the same operation key. Unrecognized algorithm strings fall through verbatim.
 */
export async function deriveOperationKeyBytes(params: {
    userId: string
    keyLabel: string
    algorithm: string
    primaryKey: Uint8Array
}): Promise<Uint8Array> {
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.primaryKey), 'HKDF', false, ['deriveBits'])
    const canonical = normalizeAeadAlgorithm(params.algorithm) ?? params.algorithm
    const infoObj = new InfoObj(params.userId, params.keyLabel, canonical)

    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: asBuf(new Uint8Array()),
            info: new TextEncoder().encode(infoObj.serialize()),
        },
        ikm,
        256
    )
    return new Uint8Array(bits)
}

class InfoObj {
    private v = 1
    public userId: string
    public keyLabel: string
    public algorithm: string

    constructor(userId: string, keyLabel: string, algorithm: string) {
        this.userId = userId
        this.keyLabel = keyLabel
        this.algorithm = algorithm
    }

    public serialize(): string {
        // Build a canonical info string that is deterministic across implementations
        // Fields are sorted alphabetically and separated by newlines; no JSON serialization dependency
        return `algorithm=${this.algorithm}\nkeyLabel=${this.keyLabel}\nuserId=${this.userId}\nv=${this.v}`
    }
}

/**
 * Derives a deterministic ECDH P-256 key pair from the primary key for request payload encryption
 * The browser stores this key's public half on the server so the CLI can encrypt request payloads
 *
 * Returns the raw 32-byte private scalar and the corresponding public JWK
 */
export async function deriveRequestEncKeyPair(params: {
    userId: string
    primaryKey: Uint8Array
}): Promise<{ scalar: Uint8Array; publicKeyJwk: EcP256PublicJwk }> {
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.primaryKey), 'HKDF', false, ['deriveBits'])

    const info = new TextEncoder().encode(`revaulter/v2/requestEncKey\nuserId=${params.userId}\nv=1`)

    // Derive 48 bytes (384 bits) so the FIPS 186-5 candidate-reduction in mapHashToField has enough input to keep modular bias negligible
    const rawBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: asBuf(new Uint8Array()), info: asBuf(info) },
        ikm,
        384
    )

    const scalar = mapHashToField(new Uint8Array(rawBits), p256.Point.Fn.ORDER)
    return { scalar, publicKeyJwk: ecP256ScalarToPublicJwk(scalar) }
}

/**
 * Derives a deterministic ML-KEM-768 key pair from the primary key for hybrid request payload encryption
 * The browser stores this key's public half on the server alongside the ECDH public key
 *
 * Returns the CryptoKey decapsulation key and the base64url-encoded raw public encapsulation key (for sending to the server)
 */
export async function deriveRequestEncMlkemKeyPair(params: {
    userId: string
    primaryKey: Uint8Array
}): Promise<{ secretKey: Uint8Array; encapsulationKeyB64: string }> {
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.primaryKey), 'HKDF', false, ['deriveBits'])

    const info = new TextEncoder().encode(`revaulter/v2/requestEncMlkemSeed\nuserId=${params.userId}\nv=1`)

    // Derive 64 bytes (512 bits) as the ML-KEM seed (d || z)
    const seedBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: asBuf(new Uint8Array()), info: asBuf(info) },
        ikm,
        512
    )

    const { secretKey, publicKey } = ml_kem768.keygen(new Uint8Array(seedBits))

    return {
        secretKey,
        encapsulationKeyB64: bytesToBase64Url(publicKey),
    }
}

/**
 * Decrypts an E2EE request payload envelope using hybrid ECDH + ML-KEM
 */
export async function decryptRequestPayload(params: {
    userId: string
    primaryKey: Uint8Array
    cliEphemeralPublicKey: EcP256PublicJwk
    mlkemCiphertext: string
    nonce: string
    ciphertext: string
    aad: Uint8Array
}): Promise<V2RequestPayloadInner> {
    // Derive the static ECDH private scalar
    const { scalar: ecdhScalar } = await deriveRequestEncKeyPair({
        userId: params.userId,
        primaryKey: params.primaryKey,
    })

    // Derive the static ML-KEM decapsulation key
    const { secretKey: mlkemSK } = await deriveRequestEncMlkemKeyPair({
        userId: params.userId,
        primaryKey: params.primaryKey,
    })

    // ECDH shared secret
    const ecdhShared = deriveEcdhSharedSecret(ecdhScalar, params.cliEphemeralPublicKey)

    // ML-KEM decapsulation
    const mlkemCT = base64UrlToBytes(params.mlkemCiphertext)
    const mlkemShared = ml_kem768.decapsulate(mlkemCT, mlkemSK)

    // Derive AES key from combined ECDH + ML-KEM shared secrets
    const aesKey = await deriveHybridAesKey(ecdhShared, mlkemShared, 'revaulter/v2/request-enc')

    // Decrypt
    const nonce = base64UrlToBytes(params.nonce)
    const ct = base64UrlToBytes(params.ciphertext)
    const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: asBuf(nonce), additionalData: asBuf(params.aad) },
        aesKey,
        asBuf(ct)
    )

    return JSON.parse(new TextDecoder().decode(plain)) as V2RequestPayloadInner
}

/**
 * Derives a deterministic ECDSA P-256 signing scalar from the primary key.
 * The derivation is bound to userId, keyLabel, and algorithm, and is domain-separated from request-encryption and symmetric operation keys.
 */
export async function deriveSigningKeyPair(params: {
    userId: string
    keyLabel: string
    algorithm: string
    primaryKey: Uint8Array
}): Promise<{ scalar: Uint8Array; publicJwk: V2SigningJwk }> {
    if (params.algorithm !== 'ES256') {
        throw new Error(`Unsupported signing algorithm: ${params.algorithm}`)
    }

    const ikm = await crypto.subtle.importKey('raw', asBuf(params.primaryKey), 'HKDF', false, ['deriveBits'])
    const info = new TextEncoder().encode(
        `revaulter/v2/signingKey\nalgorithm=${params.algorithm}\nkeyLabel=${params.keyLabel}\nuserId=${params.userId}\nv=1`
    )

    // Derive 384 bits so the FIPS 186-5 candidate-reduction in mapHashToField has enough input to keep modular bias negligible
    const rawBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: asBuf(new Uint8Array()), info: asBuf(info) },
        ikm,
        384
    )
    const scalar = mapHashToField(new Uint8Array(rawBits), p256.Point.Fn.ORDER)

    // Derive the uncompressed public point (0x04 || X(32) || Y(32)) from the scalar and split into JWK x/y
    const pubBytes = p256.getPublicKey(scalar, false)
    if (pubBytes.length !== 65 || pubBytes[0] !== 0x04) {
        throw new Error('Failed to derive uncompressed P-256 public key')
    }
    const x = bytesToBase64Url(pubBytes.subarray(1, 33))
    const y = bytesToBase64Url(pubBytes.subarray(33, 65))

    return {
        scalar,
        publicJwk: { kty: 'EC', crv: 'P-256', x, y },
    }
}

/**
 * Signs a 32-byte digest using an ECDSA P-256 raw private scalar
 * Uses `@noble/curves` with `prehash: false` so the signature is over the supplied digest directly, matching standard ES256 verification semantics
 * Returns the raw r||s concatenation (64 bytes)
 */
export async function signDigestEs256(scalar: Uint8Array, digest: Uint8Array): Promise<Uint8Array> {
    if (digest.length !== 32) {
        throw new Error(`Expected 32-byte digest, got ${digest.length}`)
    }
    const sig = p256.sign(digest, scalar, { prehash: false, format: 'compact' })
    if (sig.length !== 64) {
        throw new Error(`Expected 64-byte compact signature, got ${sig.length}`)
    }
    return sig
}

/**
 * Computes the RFC 7638 JWK thumbprint for an EC P-256 public key and returns it as a base64url-encoded SHA-256 digest.
 * The thumbprint is computed only over the required members (crv, kty, x, y) in lexicographic order.
 */
export async function computeEcP256Thumbprint(jwk: V2SigningJwk): Promise<string> {
    const canonical = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(jwk.kty)},"x":${JSON.stringify(jwk.x)},"y":${JSON.stringify(jwk.y)}}`

    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))

    return bytesToBase64Url(new Uint8Array(hash))
}

/**
 * Converts an EC P-256 public JWK to a PEM-encoded PKIX public key.
 * The returned string is the canonical "-----BEGIN PUBLIC KEY-----" envelope suitable for standard ES256 verification libraries.
 */
export async function ecP256JwkToPem(jwk: V2SigningJwk): Promise<string> {
    // Re-import as an extractable ECDSA public key so we can export SPKI (PKIX DER)
    const pub = await crypto.subtle.importKey(
        'jwk',
        { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true } as JsonWebKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
    )
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pub))

    // Encode DER as base64 and wrap at 64 chars per PEM convention
    let binary = ''
    for (const b of spki) {
        binary += String.fromCharCode(b)
    }
    const b64 = btoa(binary)
    const lines: string[] = []
    for (let i = 0; i < b64.length; i += 64) {
        lines.push(b64.slice(i, i + 64))
    }

    return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`
}
