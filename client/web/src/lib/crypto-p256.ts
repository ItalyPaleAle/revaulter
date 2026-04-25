import { asBuf } from '$lib/utils'

/**
 * Reduces arbitrary-length hash output to a valid P-256 private scalar in [1, n-1].
 *
 * Implements the procedure from FIPS 186-5, appendix A.2.1 ("Key Pair Generation by Testing Candidates"): interpret the input as a big-endian integer, compute `(value mod (n-1)) + 1`, and encode the result as a 32-byte big-endian octet string.
 *
 * The caller should supply at least 48 bytes (384 bits) of input so the modular bias is bounded by ~2^-128, which is cryptographically negligible.
 */
export function hashToP256Scalar(hash: Uint8Array): Uint8Array {
    // P-256 curve order
    const P256_ORDER = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')

    let num = BigInt(0)
    for (const b of hash) {
        num = (num << BigInt(8)) | BigInt(b)
    }
    const scalar = (num % (P256_ORDER - BigInt(1))) + BigInt(1)

    const out = new Uint8Array(32)
    let tmp = scalar
    for (let i = 31; i >= 0; i--) {
        out[i] = Number(tmp & BigInt(0xff))
        tmp >>= BigInt(8)
    }
    return out
}

/**
 * Builds a PKCS8 DER envelope for a P-256 private scalar.
 * The same byte layout is used to import the scalar as either ECDH or ECDSA; only the algorithm argument to `crypto.subtle.importKey` changes.
 */
function buildP256Pkcs8(scalar: Uint8Array): Uint8Array {
    if (scalar.length !== 32) {
        throw new Error(`P-256 scalar must be exactly 32 bytes, got ${scalar.length}`)
    }
    // PKCS8 DER envelope: version(0) + AlgorithmIdentifier(EC, P-256) + ECPrivateKey(version=1, scalar)
    // prettier-ignore
    // biome-ignore format: the array should not be formatted
    const PREFIX = new Uint8Array([
        0x30, 0x41,                                                 // SEQUENCE (65 bytes)
        0x02, 0x01, 0x00,                                           //   INTEGER 0 (PKCS8 version)
        0x30, 0x13,                                                 //   SEQUENCE (AlgorithmIdentifier)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,       //     OID 1.2.840.10045.2.1 (ecPublicKey)
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7 (P-256)
        0x04, 0x27,                                                 //   OCTET STRING (39 bytes)
        0x30, 0x25,                                                 //     SEQUENCE (ECPrivateKey)
        0x02, 0x01, 0x01,                                           //       INTEGER 1 (version)
        0x04, 0x20,                                                 //       OCTET STRING (32 bytes) — scalar follows
    ])
    const pkcs8 = new Uint8Array(PREFIX.length + scalar.length)
    pkcs8.set(PREFIX)
    pkcs8.set(scalar, PREFIX.length)
    return pkcs8
}

/**
 * Imports a raw 32-byte P-256 private scalar as an extractable ECDH CryptoKey via PKCS8 DER encoding.
 * PKCS8 import only needs the scalar: the browser derives the public point automatically (unlike JWK which requires x/y).
 */
export async function importP256ScalarAsEcdhKey(scalar: Uint8Array): Promise<CryptoKey> {
    const pkcs8 = buildP256Pkcs8(scalar)
    return crypto.subtle.importKey('pkcs8', asBuf(pkcs8), { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
}
