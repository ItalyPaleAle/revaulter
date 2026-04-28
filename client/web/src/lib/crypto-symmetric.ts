import { chacha20poly1305 } from '@awasm/noble'

import { asBuf } from '$lib/utils'
import type { V2Operation } from '$lib/v2-types'

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

/**
 * Splits a combined AEAD output (ciphertext || tag) into ciphertext and tag segments
 * Works for both AES-GCM and ChaCha20-Poly1305 since both append a 16-byte tag by default
 */
export function splitAeadCiphertextAndTag(ciphertextWithTag: Uint8Array, tagLen = 16) {
    if (ciphertextWithTag.length < tagLen) {
        throw new Error('Ciphertext is too short')
    }

    return {
        data: ciphertextWithTag.slice(0, ciphertextWithTag.length - tagLen),
        tag: ciphertextWithTag.slice(ciphertextWithTag.length - tagLen),
    }
}

/**
 * Performs the requested ChaCha20-Poly1305 operation with the supplied raw key bytes
 * Mirrors `performAesGcmOperation`'s parameter shape so callers can branch on algorithm and reuse the same input/output framing
 */
export async function performChaCha20Poly1305Operation(params: {
    mode: 'encrypt' | 'decrypt'
    keyBytes: Uint8Array
    value: Uint8Array
    nonce?: Uint8Array
    aad?: Uint8Array
    tag?: Uint8Array
}): Promise<Uint8Array> {
    // ChaCha20-Poly1305 requires a 12-byte nonce; generate one for encryption callers that don't supply one
    const nonce = params.nonce ?? crypto.getRandomValues(new Uint8Array(12))
    const aad = params.aad && params.aad.length > 0 ? params.aad : undefined
    const cipher = chacha20poly1305(params.keyBytes, nonce, aad)

    if (params.mode === 'encrypt') {
        return cipher.encrypt(params.value)
    }

    // The cipher expects ciphertext||tag concatenated, so rebuild that shape when the caller supplied them separately
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
        return cipher.decrypt(combined)
    } catch {
        throw new Error(
            'Decryption failed. This normally means that the ciphertext could not be authenticated. Check that the key label, user ID, nonce, tag, and additional data match the original encryption request.'
        )
    }
}

/**
 * Normalizes an algorithm string to the canonical long-form name used for AEAD dispatch
 * Returns `aes-256-gcm` or `chacha20-poly1305`, or `null` if the algorithm is not supported for encrypt/decrypt
 * The set of accepted spellings matches the server-side `IsSupportedEncryptionAlgorithm`
 */
export function normalizeAeadAlgorithm(algo: string): 'aes-256-gcm' | 'chacha20-poly1305' | null {
    switch (algo.toLowerCase()) {
        case 'a256gcm':
        case 'aes-256-gcm':
        case 'aes256gcm':
            return 'aes-256-gcm'
        case 'c20p':
        case 'chacha20-poly1305':
        case 'chacha20poly1305':
            return 'chacha20-poly1305'
        default:
            return null
    }
}

/** Reports whether an algorithm string is accepted for browser-side encrypt/decrypt operations (case-insensitive) */
export function isSupportedAeadAlgorithm(algo: string): boolean {
    return normalizeAeadAlgorithm(algo) !== null
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
 * Builds the canonical AES-GCM additional authenticated data used for transport response envelopes shared between the browser and the CLI
 */
export function buildTransportAAD(state: string, operation: V2Operation, algorithm: string): Uint8Array {
    return new TextEncoder().encode(new TransportAADInfo(state, operation, algorithm).serialize())
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
