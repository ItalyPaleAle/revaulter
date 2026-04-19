import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { argon2id } from 'hash-wasm'
import { asBuf, base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import type {
    EcP256PublicJwk,
    V2Operation,
    V2RequestPayloadInner,
    V2ResponseEnvelope,
    V2SigningJwk,
} from '$lib/v2-types'
import { hashToP256Scalar, importP256ScalarAsEcdhKey, importP256ScalarAsEcdsaKey } from './crypto-p256'

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
 * Derives the hybrid ECDH + ML-KEM shared secret, then expands it via HKDF into an AES-256-GCM key.
 * Handles both the encapsulate (encrypt) and decapsulate (decrypt) sides of ML-KEM so callers don't touch ML-KEM directly.
 *
 * The request `state` is mixed into HKDF so the key is scoped to a single pending request.
 */
async function deriveTransportAesKeyForEncrypt(
    state: string,
    ecdhPrivateKey: CryptoKey,
    peerEcdhPublicJwk: EcP256PublicJwk,
    peerMlkemKeyB64: string
): Promise<{ aesKey: CryptoKey; mlkemCiphertext: Uint8Array }> {
    // ECDH shared secret
    const ecdhShared = await deriveEcdhSharedSecret(ecdhPrivateKey, peerEcdhPublicJwk)

    // ML-KEM encapsulation
    const mlkemPubBytes = base64UrlToBytes(peerMlkemKeyB64)
    const { cipherText: mlkemCT, sharedSecret: mlkemShared } = ml_kem768.encapsulate(mlkemPubBytes)

    const aesKey = await deriveHybridAesKey(ecdhShared, mlkemShared, `revaulter/v2/transport/${state}`)
    return { aesKey, mlkemCiphertext: mlkemCT }
}

async function deriveTransportAesKeyForDecrypt(
    state: string,
    ecdhPrivateKey: CryptoKey,
    peerEcdhPublicJwk: EcP256PublicJwk,
    mlkemSecretKey: Uint8Array,
    mlkemCiphertext: Uint8Array
): Promise<CryptoKey> {
    // ECDH shared secret
    const ecdhShared = await deriveEcdhSharedSecret(ecdhPrivateKey, peerEcdhPublicJwk)

    // ML-KEM decapsulation
    const mlkemShared = ml_kem768.decapsulate(mlkemCiphertext, mlkemSecretKey)

    return deriveHybridAesKey(ecdhShared, mlkemShared, `revaulter/v2/transport/${state}`)
}

/** Performs ECDH key agreement and returns the raw 32-byte shared secret */
async function deriveEcdhSharedSecret(privateKey: CryptoKey, peerPublicJwk: EcP256PublicJwk): Promise<Uint8Array> {
    const peerKey = await crypto.subtle.importKey(
        'jwk',
        peerPublicJwk as JsonWebKey,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    )
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, privateKey, 256))
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
    const eph = await generateTransportKeyPairJwk()
    const { aesKey, mlkemCiphertext } = await deriveTransportAesKeyForEncrypt(
        state,
        eph.privateKey,
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
 * Decrypts a transport envelope using hybrid ECDH + ML-KEM.
 * The same request `state` must be supplied so HKDF derives the matching AES key.
 */
export async function decryptTransportEnvelope(
    state: string,
    ecdhPrivateKey: CryptoKey,
    mlkemSecretKey: Uint8Array,
    env: V2ResponseEnvelope,
    aad?: Uint8Array
): Promise<Uint8Array> {
    const mlkemCT = base64UrlToBytes(env.mlkemCiphertext)
    const aesKey = await deriveTransportAesKeyForDecrypt(
        state,
        ecdhPrivateKey,
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
 */
export async function deriveWrappingKey(params: {
    prfSecret: Uint8Array
    userId: string
    password?: string
    argon2idSalt?: Uint8Array
}): Promise<{ wrappingKeyBytes: Uint8Array; stretched?: Uint8Array; argon2idSalt?: Uint8Array }> {
    let hkdfSalt: BufferSource = new Uint8Array()
    let stretched: Uint8Array | undefined
    let usedArgon2idSalt: Uint8Array | undefined

    if (params.password) {
        usedArgon2idSalt = params.argon2idSalt ?? crypto.getRandomValues(new Uint8Array(16))
        // These settings roughly exceed the current OWASP Argon2id guidance as of April 2026 (m=128 MiB, t=4, p=1) and aim for well over 500 ms of work on modern laptops while still being tolerable in-browser
        const stretchedBytes = await argon2id({
            password: params.password,
            salt: usedArgon2idSalt,
            parallelism: 1,
            iterations: 4,
            memorySize: 128 << 10, // 128 MiB
            hashLength: 32,
            outputType: 'binary',
        })
        // Copy into a fresh ArrayBuffer-backed Uint8Array to satisfy
        // BufferSource constraints (hash-wasm returns ArrayBufferLike)
        const copy = new Uint8Array(stretchedBytes.byteLength)
        copy.set(stretchedBytes)
        stretched = copy
        hkdfSalt = copy
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

    return { wrappingKeyBytes: new Uint8Array(bits), stretched, argon2idSalt: usedArgon2idSalt }
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

    if (params.passwordRequired && params.argon2idSalt) {
        envelope.argon2id = {
            m: 128 << 10, // 128 MB
            t: 4,
            p: 1,
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
 * AES-GCM encryption/decryption
 * The derived key is bound to the user ID, key label, and algorithm
 */
export async function deriveOperationKeyBytes(params: {
    userId: string
    keyLabel: string
    algorithm: string
    primaryKey: Uint8Array
}): Promise<Uint8Array> {
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.primaryKey), 'HKDF', false, ['deriveBits'])
    const infoObj = new InfoObj(params.userId, params.keyLabel, params.algorithm)

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

class TransportAADInfo {
    private v = 1
    public state: string
    public operation: V2Operation
    public algorithm: string

    constructor(state: string, operation: V2Operation, algorithm: string) {
        this.state = state
        this.operation = operation
        this.algorithm = algorithm
    }

    public serialize(): string {
        // Keep the transport AAD format deterministic across browser and CLI implementations
        // This avoids relying on JSON field ordering when binding the response envelope
        return `algorithm=${this.algorithm}\noperation=${this.operation}\nstate=${this.state}\nv=${this.v}`
    }
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
 * Builds the canonical AES-GCM additional authenticated data used for transport response envelopes shared between the browser and the CLI
 */
export function buildTransportAAD(state: string, operation: V2Operation, algorithm: string): Uint8Array {
    return new TextEncoder().encode(new TransportAADInfo(state, operation, algorithm).serialize())
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
    const key = await crypto.subtle.importKey('raw', asBuf(params.keyBytes), { name: 'AES-GCM' }, false, [
        params.mode === 'encrypt' ? 'encrypt' : 'decrypt',
    ])

    // Use the supplied nonce when present, otherwise generate one for encryption callers
    const nonce = params.nonce ?? crypto.getRandomValues(new Uint8Array(12))

    if (params.mode === 'encrypt') {
        // Encrypt the plaintext and bind any additional authenticated data into the tag
        const res = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: asBuf(nonce), additionalData: asBuf(params.aad) },
            key,
            asBuf(params.value)
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
            { name: 'AES-GCM', iv: asBuf(nonce), additionalData: asBuf(params.aad) },
            key,
            asBuf(combined)
        )
        return new Uint8Array(res)
    } catch {
        throw new Error(
            'Decryption failed. This normally means that the ciphertext could not be authenticated. Check that the key label, user ID, nonce, tag, and additional data match the original encryption request.'
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

/**
 * Derives a deterministic ECDH P-256 key pair from the primary key for request payload encryption
 * The browser stores this key's public half on the server so the CLI can encrypt request payloads
 */
export async function deriveRequestEncKeyPair(params: {
    userId: string
    primaryKey: Uint8Array
}): Promise<{ privateKey: CryptoKey; publicKeyJwk: EcP256PublicJwk }> {
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.primaryKey), 'HKDF', false, ['deriveBits'])

    const info = new TextEncoder().encode(`revaulter/v2/requestEncKey\nuserId=${params.userId}\nv=1`)

    // Derive 48 bytes (384 bits) so hashToP256Scalar has enough input to keep modular bias negligible
    const rawBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: asBuf(new Uint8Array()), info: asBuf(info) },
        ikm,
        384
    )

    const scalarBytes = hashToP256Scalar(new Uint8Array(rawBits))
    const privateKey = await importP256ScalarAsEcdhKey(scalarBytes)

    // Export the public key as JWK
    const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
        throw new Error('Failed to export request encryption public key as P-256 JWK')
    }

    return {
        privateKey,
        publicKeyJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
    }
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
 * Builds the canonical AAD used when encrypting/decrypting request payloads.
 * This binds the plaintext metadata to the E2EE ciphertext so tampering with
 * keyLabel, algorithm, or operation causes decryption to fail.
 */
export function buildRequestEncAAD(algorithm: string, keyLabel: string, operation: string): Uint8Array {
    return new TextEncoder().encode(`algorithm=${algorithm}\nkeyLabel=${keyLabel}\noperation=${operation}\nv=1`)
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
    // Derive the static ECDH private key
    const { privateKey: ecdhPrivKey } = await deriveRequestEncKeyPair({
        userId: params.userId,
        primaryKey: params.primaryKey,
    })

    // Derive the static ML-KEM decapsulation key
    const { secretKey: mlkemSK } = await deriveRequestEncMlkemKeyPair({
        userId: params.userId,
        primaryKey: params.primaryKey,
    })

    // ECDH shared secret
    const ecdhShared = await deriveEcdhSharedSecret(ecdhPrivKey, params.cliEphemeralPublicKey)

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
 * Derives a deterministic ECDSA P-256 signing key pair from the primary key.
 * The derivation is bound to userId, keyLabel, and algorithm, and is domain-separated from request-encryption and symmetric operation keys.
 */
export async function deriveSigningKeyPair(params: {
    userId: string
    keyLabel: string
    algorithm: string
    primaryKey: Uint8Array
}): Promise<{ privateKey: CryptoKey; publicJwk: V2SigningJwk }> {
    if (params.algorithm !== 'ES256') {
        throw new Error(`Unsupported signing algorithm: ${params.algorithm}`)
    }

    const ikm = await crypto.subtle.importKey('raw', asBuf(params.primaryKey), 'HKDF', false, ['deriveBits'])
    const info = new TextEncoder().encode(
        `revaulter/v2/signingKey\nalgorithm=${params.algorithm}\nkeyLabel=${params.keyLabel}\nuserId=${params.userId}\nv=1`
    )

    // Derive 384 bits so hashToP256Scalar has enough input to keep modular bias negligible
    const rawBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: asBuf(new Uint8Array()), info: asBuf(info) },
        ikm,
        384
    )
    const scalarBytes = hashToP256Scalar(new Uint8Array(rawBits))
    const privateKey = await importP256ScalarAsEcdsaKey(scalarBytes)

    const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
        throw new Error('Failed to export signing public key as P-256 JWK')
    }

    return {
        privateKey,
        publicJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
    }
}

/**
 * Signs a 32-byte digest using an ECDSA P-256 private key. Returns the raw r||s concatenation (64 bytes) produced by WebCrypto
 */
export async function signDigestEs256(privateKey: CryptoKey, digest: Uint8Array): Promise<Uint8Array> {
    if (digest.length !== 32) {
        throw new Error(`Expected 32-byte digest, got ${digest.length}`)
    }
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, asBuf(digest) as BufferSource)
    return new Uint8Array(sig)
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
