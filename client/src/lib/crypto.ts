import { argon2id } from 'hash-wasm'
import type { EcP256PublicJwk, V2ResponseEnvelope } from '$lib/v2-types'
import { asBuf, base64UrlToBytes, bytesToBase64Url } from '$lib/utils'

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

    // Return the encrypted response in the API envelope format expected by clients.
    // AAD is not included — both sides derive it from request metadata independently.
    return {
        transportAlg: 'ecdh-p256+a256gcm',
        browserEphemeralPublicKey: eph.publicKeyJwk,
        nonce: bytesToBase64Url(nonce),
        ciphertext: bytesToBase64Url(ciphertext),
        resultType: 'bytes',
    }
}

/**
 * Decrypts a transport envelope using the requester's private transport key.
 * The same request `state` must be supplied so HKDF derives the matching AES key.
 * AAD must be provided by the caller (derived from request metadata), not from the envelope.
 */
export async function decryptTransportEnvelope(
    state: string,
    privateKey: CryptoKey,
    env: V2ResponseEnvelope,
    aad?: Uint8Array
): Promise<Uint8Array> {
    // Re-derive the symmetric key from the local private key and browser ephemeral public key
    const aesKey = await deriveTransportAesKey(state, privateKey, env.browserEphemeralPublicKey)

    // Decode the envelope fields and verify the AES-GCM tag during decryption
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
 * Computes the PRF salt used during WebAuthn PRF evaluation. When a password is
 * present, it is mixed in with HMAC so the effective salt changes per password.
 */
export async function computePrfSalt(basePrfSalt: Uint8Array, password?: string): Promise<Uint8Array> {
    if (!password) {
        return basePrfSalt
    }

    // Use the server-provided base salt as the HMAC key and the password as the message
    const key = await crypto.subtle.importKey('raw', asBuf(basePrfSalt), { name: 'HMAC', hash: 'SHA-256' }, false, [
        'sign',
    ])

    const sig = await crypto.subtle.sign('HMAC', key, asBuf(new TextEncoder().encode(password)))
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
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.prfSecret), 'HKDF', false, ['deriveBits'])

    // If a password is present, mix it in as HKDF salt so the derived key depends on both factors
    const salt = params.password ? new TextEncoder().encode(params.password) : new Uint8Array()
    const infoObj = new InfoObj(params.targetUser, params.keyLabel, params.algorithm)

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

class InfoObj {
    private v = 1
    public targetUser: string
    public keyLabel: string
    public algorithm: string

    constructor(targetUser: string, keyLabel: string, algorithm: string) {
        this.targetUser = targetUser
        this.keyLabel = keyLabel
        this.algorithm = algorithm
    }

    public serialize(): string {
        // Build a canonical info string that is deterministic across implementations
        // Fields are sorted alphabetically and separated by newlines; no JSON serialization dependency
        return `algorithm=${this.algorithm}\nkeyLabel=${this.keyLabel}\ntargetUser=${this.targetUser}\nv=${this.v}`
    }
}

/** Derives the AES key used to encrypt and verify the password canary value. */
async function deriveCanaryKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const keyBytes = await argon2id({
        password,
        salt,
        parallelism: 1,
        iterations: 3,
        memorySize: 65536, // 64 MiB
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
