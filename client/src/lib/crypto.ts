import { argon2id } from 'hash-wasm'
import mlkem from 'mlkem-wasm'
import { asBuf, base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import type { EcP256PublicJwk, V2RequestPayloadInner, V2ResponseEnvelope } from '$lib/v2-types'
import { hashToP256Scalar, importP256ScalarAsEcdhKey } from './crypto-p256'

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
    const mlkemPubKey = await mlkem.importKey('raw-public', asBuf(mlkemPubBytes) as BufferSource, 'ML-KEM-768', false, [
        'encapsulateBits',
    ])
    const { sharedKey: mlkemSharedBuf, ciphertext: mlkemCTBuf } = await mlkem.encapsulateBits('ML-KEM-768', mlkemPubKey)

    const aesKey = await deriveHybridAesKey(
        ecdhShared,
        new Uint8Array(mlkemSharedBuf),
        `revaulter/v2/transport/${state}`
    )
    return { aesKey, mlkemCiphertext: new Uint8Array(mlkemCTBuf) }
}

async function deriveTransportAesKeyForDecrypt(
    state: string,
    ecdhPrivateKey: CryptoKey,
    peerEcdhPublicJwk: EcP256PublicJwk,
    mlkemDecapsulationKey: CryptoKey,
    mlkemCiphertext: Uint8Array
): Promise<CryptoKey> {
    // ECDH shared secret
    const ecdhShared = await deriveEcdhSharedSecret(ecdhPrivateKey, peerEcdhPublicJwk)

    // ML-KEM decapsulation
    const mlkemSharedBuf = await mlkem.decapsulateBits(
        'ML-KEM-768',
        mlkemDecapsulationKey,
        asBuf(mlkemCiphertext) as BufferSource
    )

    return deriveHybridAesKey(ecdhShared, new Uint8Array(mlkemSharedBuf), `revaulter/v2/transport/${state}`)
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
    mlkemDecapsulationKey: CryptoKey,
    env: V2ResponseEnvelope,
    aad?: Uint8Array
): Promise<Uint8Array> {
    const mlkemCT = base64UrlToBytes(env.mlkemCiphertext)
    const aesKey = await deriveTransportAesKeyForDecrypt(
        state,
        ecdhPrivateKey,
        env.browserEphemeralPublicKey,
        mlkemDecapsulationKey,
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
 * Derives the logical operation key bytes used for application crypto such as
 * AES-GCM encryption/decryption. The derived key is bound to the user ID,
 * key label, algorithm, and optionally the password.
 */
export async function deriveOperationKeyBytes(params: {
    userId: string
    keyLabel: string
    algorithm: string
    prfSecret: Uint8Array
    password?: string
}): Promise<Uint8Array> {
    // Import the WebAuthn PRF output as the HKDF input keying material
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.prfSecret), 'HKDF', false, ['deriveBits'])

    // If a password is present, mix it in as HKDF salt so the derived key depends on both factors
    const salt = params.password ? new TextEncoder().encode(params.password) : new Uint8Array()
    const infoObj = new InfoObj(params.userId, params.keyLabel, params.algorithm)

    // Bind the key to the logical key identity so encrypt/decrypt requests derive the same bytes
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: asBuf(salt),
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
    public operation: 'encrypt' | 'decrypt'
    public algorithm: string

    constructor(state: string, operation: 'encrypt' | 'decrypt', algorithm: string) {
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
export function buildTransportAAD(state: string, operation: 'encrypt' | 'decrypt', algorithm: string): Uint8Array {
    return new TextEncoder().encode(new TransportAADInfo(state, operation, algorithm).serialize())
}

/**
 * Derives the AES key used to encrypt and verify the password canary value.
 *
 * Parameters are intentionally aggressive because the canary is a verifier for the password on the client side, and an attacker who has obtained the canary ciphertext (for example by stealing a passkey) would mount an offline Argon2id search against it.
 * These settings roughly exceed the current OWASP Argon2id guidance as of April 2026 (m=128 MiB, t=4, p=1) and aim for well over 500 ms of work on modern laptops while still being tolerable in-browser.
 */
async function deriveCanaryKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const keyBytes = await argon2id({
        password,
        salt,
        parallelism: 1,
        iterations: 4,
        memorySize: 128 << 10, // 128 MiB
        hashLength: 32,
        outputType: 'binary',
    })

    return crypto.subtle.importKey('raw', asBuf(keyBytes), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

/** Encrypts a fixed canary string so the client can later verify a password locally. */
export async function encryptPasswordCanary(password: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveCanaryKey(password, salt)
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = new TextEncoder().encode('revaulter-password-ok')

    // AES-GCM output already contains the authentication tag appended to the ciphertext
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: asBuf(nonce) }, key, asBuf(plaintext))

    // Persist the canary as `salt.nonce.ciphertext`, all encoded as base64url
    return `${bytesToBase64Url(salt)}.${bytesToBase64Url(nonce)}.${bytesToBase64Url(ct)}`
}

/** Verifies that a password can decrypt the stored canary without authentication failure. */
export async function verifyPasswordCanary(password: string, canary: string): Promise<boolean> {
    const parts = canary.split('.')
    if (parts.length !== 3) {
        return false
    }
    try {
        const salt = base64UrlToBytes(parts[0])
        const nonce = base64UrlToBytes(parts[1])
        const ct = base64UrlToBytes(parts[2])
        const key = await deriveCanaryKey(password, salt)

        // We do not need to inspect the plaintext here: AES-GCM auth failure is enough to reject the password
        await crypto.subtle.decrypt({ name: 'AES-GCM', iv: asBuf(nonce) }, key, asBuf(ct))
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
            'Decryption failed. This normally means that the ciphertext could not be authenticated. Check that the key label, user ID, password, nonce, tag, and additional data match the original encryption request.'
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
 * Derives a deterministic ECDH P-256 key pair from the user's PRF secret
 * (and optional password) for request payload encryption. The browser stores
 * this key's public half on the server so the CLI can encrypt request payloads.
 */
export async function deriveRequestEncKeyPair(params: {
    userId: string
    prfSecret: Uint8Array
    password?: string
}): Promise<{ privateKey: CryptoKey; publicKeyJwk: EcP256PublicJwk }> {
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.prfSecret), 'HKDF', false, ['deriveBits'])

    const salt = params.password ? new TextEncoder().encode(params.password) : new Uint8Array()
    const info = new TextEncoder().encode(`revaulter/v2/requestEncKey\nuserId=${params.userId}\nv=1`)

    // Derive 48 bytes (384 bits) so hashToP256Scalar has enough input to keep modular bias negligible
    const rawBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: asBuf(salt), info: asBuf(info) },
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
 * Derives a deterministic ML-KEM-768 key pair from the user's PRF secret (and optional password) for hybrid request payload encryption.
 * The browser stores this key's public half on the server alongside the ECDH public key.
 *
 * Returns the CryptoKey decapsulation key and the base64url-encoded raw public encapsulation key (for sending to the server).
 */
export async function deriveRequestEncMlkemKeyPair(params: {
    userId: string
    prfSecret: Uint8Array
    password?: string
}): Promise<{ decapsulationKey: CryptoKey; encapsulationKeyB64: string }> {
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.prfSecret), 'HKDF', false, ['deriveBits'])

    const salt = params.password ? new TextEncoder().encode(params.password) : new Uint8Array()
    const info = new TextEncoder().encode(`revaulter/v2/requestEncMlkemSeed\nuserId=${params.userId}\nv=1`)

    // Derive 64 bytes (512 bits) as the ML-KEM seed (d || z)
    const seedBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: asBuf(salt), info: asBuf(info) },
        ikm,
        512
    )

    // Import as ML-KEM-768 decapsulation key from seed
    const dk = await mlkem.importKey('raw-seed', seedBits, 'ML-KEM-768', true, ['decapsulateBits'])

    // Extract the encapsulation (public) key
    const pk = await mlkem.getPublicKey(dk, ['encapsulateBits'])
    const pkRaw = await mlkem.exportKey('raw-public', pk)

    return {
        decapsulationKey: dk,
        encapsulationKeyB64: bytesToBase64Url(pkRaw),
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
    prfSecret: Uint8Array
    password?: string
    cliEphemeralPublicKey: EcP256PublicJwk
    mlkemCiphertext: string
    nonce: string
    ciphertext: string
    aad: Uint8Array
}): Promise<V2RequestPayloadInner> {
    // Derive the static ECDH private key
    const { privateKey: ecdhPrivKey } = await deriveRequestEncKeyPair({
        userId: params.userId,
        prfSecret: params.prfSecret,
        password: params.password,
    })

    // Derive the static ML-KEM decapsulation key
    const { decapsulationKey: mlkemDK } = await deriveRequestEncMlkemKeyPair({
        userId: params.userId,
        prfSecret: params.prfSecret,
        password: params.password,
    })

    // ECDH shared secret
    const ecdhShared = await deriveEcdhSharedSecret(ecdhPrivKey, params.cliEphemeralPublicKey)

    // ML-KEM decapsulation
    const mlkemCT = base64UrlToBytes(params.mlkemCiphertext)
    const mlkemSharedBuf = await mlkem.decapsulateBits('ML-KEM-768', mlkemDK, asBuf(mlkemCT) as BufferSource)

    // Derive AES key from combined ECDH + ML-KEM shared secrets
    const aesKey = await deriveHybridAesKey(ecdhShared, new Uint8Array(mlkemSharedBuf), 'revaulter/v2/request-enc')

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
