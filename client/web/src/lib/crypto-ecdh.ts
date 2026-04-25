import { p256 } from '@noble/curves/nist.js'

import { base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import type { EcP256PublicJwk } from '$lib/v2-types'

/**
 * Builds a P-256 public JWK (`{ kty, crv, x, y }`) from a raw 32-byte private scalar
 * Uses `@noble/curves` to derive the uncompressed public point and splits it into x/y
 */
export function ecP256ScalarToPublicJwk(scalar: Uint8Array): EcP256PublicJwk {
    const pubBytes = p256.getPublicKey(scalar, false)
    if (pubBytes.length !== 65 || pubBytes[0] !== 0x04) {
        throw new Error('Failed to derive uncompressed P-256 public key')
    }
    return {
        kty: 'EC',
        crv: 'P-256',
        x: bytesToBase64Url(pubBytes.subarray(1, 33)),
        y: bytesToBase64Url(pubBytes.subarray(33, 65)),
    }
}

/**
 * Reconstructs the uncompressed SEC1 public-point bytes (`0x04 || X(32) || Y(32)`) from a P-256 public JWK
 * Used to feed peer keys into `p256.getSharedSecret` without going through `crypto.subtle.importKey`
 */
export function ecP256JwkToPublicBytes(jwk: EcP256PublicJwk): Uint8Array {
    const x = base64UrlToBytes(jwk.x)
    const y = base64UrlToBytes(jwk.y)
    if (x.length !== 32 || y.length !== 32) {
        throw new Error('Invalid P-256 public JWK: x and y must each be 32 bytes')
    }
    const out = new Uint8Array(65)
    out[0] = 0x04
    out.set(x, 1)
    out.set(y, 33)
    return out
}

/**
 * Generates an ephemeral ECDH P-256 key pair for transport encryption
 * Returns the raw 32-byte private scalar and the public half as a compact JWK that the CLI consumes
 */
export function generateTransportKeyPairJwk(): {
    scalar: Uint8Array
    publicKeyJwk: EcP256PublicJwk
} {
    const scalar = p256.utils.randomSecretKey()
    return { scalar, publicKeyJwk: ecP256ScalarToPublicJwk(scalar) }
}

/**
 * Performs ECDH key agreement and returns the raw 32-byte shared secret (the X coordinate of the shared point)
 *
 * `p256.getSharedSecret` returns the compressed shared point (`parity || X`, 33 bytes) by default, so we slice off the parity byte to match the 32-byte X-only output that WebCrypto's `deriveBits(..., 256)` produced
 */
export function deriveEcdhSharedSecret(scalar: Uint8Array, peerPublicJwk: EcP256PublicJwk): Uint8Array {
    const peerPubBytes = ecP256JwkToPublicBytes(peerPublicJwk)
    const compressed = p256.getSharedSecret(scalar, peerPubBytes)
    return compressed.slice(1)
}
