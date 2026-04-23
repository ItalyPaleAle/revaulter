/**
 * Hybrid anchor crypto: ES384 (P-384 ECDSA with SHA-384) + ML-DSA-87.
 * The anchor is the user's long-lived identity root. Both halves must sign
 * credential attestations and the pubkey bundle; verifiers require both.
 */
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { asBuf, base64UrlToBytes, bytesToBase64Url } from '$lib/utils'

// Domain-separation prefixes — must match pkg/protocolv2/anchor.go exactly.
const CRED_ATTEST_PREFIX = 'revaulter/v2/cred-attest\n'
const PUBKEY_BUNDLE_PREFIX = 'revaulter/v2/pubkey-bundle\n'

// Fixed sizes mirrored from pkg/protocolv2.
const P384_COORD_SIZE = 48
const ES384_SIG_SIZE = 96
const MLDSA87_PUB_SIZE = 2592
const MLDSA87_SIG_SIZE = 4627

export type EcP384PublicJwk = {
    kty: 'EC'
    crv: 'P-384'
    x: string
    y: string
}

export type AnchorKeyPair = {
    es384: {
        privateKey: CryptoKey
        publicKeyJwk: EcP384PublicJwk
    }
    mldsa87: {
        // Raw 32-byte seed from which the key is regenerated on every sign/verify.
        seed: Uint8Array
        // Raw public key bytes (2592 B).
        publicKey: Uint8Array
    }
}

export type AttestationPayload = {
    userId: string
    credentialId: string
    credentialPublicKeyHash: string
    wrappedKeyEpoch: number
    createdAt: number
}

export type PubkeyBundlePayload = {
    userId: string
    requestEncEcdhPubkey: string
    requestEncMlkemPubkey: string
    anchorEs384Crv: string
    anchorEs384Kty: string
    anchorEs384X: string
    anchorEs384Y: string
    anchorMldsa87PublicKey: string
    wrappedKeyEpoch: number
}

/**
 * Generate a fresh hybrid anchor: an extractable ES384 key pair plus an
 * ML-DSA-87 seed (we regenerate the key from the seed on each sign; the seed
 * is what we wrap and store, which keeps the wrapped blob small).
 */
export async function generateAnchorKeyPair(): Promise<AnchorKeyPair> {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'])
    const jwk = (await crypto.subtle.exportKey('jwk', kp.publicKey)) as JsonWebKey
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-384' || !jwk.x || !jwk.y) {
        throw new Error('Failed to export anchor ES384 public key as P-384 JWK')
    }

    const seed = crypto.getRandomValues(new Uint8Array(32))
    const mldsa = ml_dsa87.keygen(seed)

    return {
        es384: {
            privateKey: kp.privateKey,
            publicKeyJwk: { kty: 'EC', crv: 'P-384', x: jwk.x, y: jwk.y },
        },
        mldsa87: {
            seed,
            publicKey: new Uint8Array(mldsa.publicKey),
        },
    }
}

/**
 * Serialize the anchor secret (ES384 PKCS8 bytes + ML-DSA-87 seed) as a
 * length-prefixed concat. Stable format — `revaulter/v2/anchor-secret\nv=1`
 * prefix lets us reject blobs from unrelated contexts.
 */
export async function serializeAnchorSecret(kp: AnchorKeyPair): Promise<Uint8Array> {
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.es384.privateKey))
    const prefix = new TextEncoder().encode('revaulter/v2/anchor-secret\nv=1\n')
    const out = new Uint8Array(prefix.length + 4 + pkcs8.length + 4 + kp.mldsa87.seed.length)
    let offset = 0
    out.set(prefix, offset)
    offset += prefix.length
    writeUint32BE(out, offset, pkcs8.length)
    offset += 4
    out.set(pkcs8, offset)
    offset += pkcs8.length
    writeUint32BE(out, offset, kp.mldsa87.seed.length)
    offset += 4
    out.set(kp.mldsa87.seed, offset)
    return out
}

export async function parseAnchorSecret(blob: Uint8Array): Promise<AnchorKeyPair> {
    const prefix = new TextEncoder().encode('revaulter/v2/anchor-secret\nv=1\n')
    if (blob.length < prefix.length + 8) {
        throw new Error('Anchor secret blob is too small')
    }
    for (let i = 0; i < prefix.length; i++) {
        if (blob[i] !== prefix[i]) {
            throw new Error('Anchor secret blob has invalid prefix')
        }
    }

    let offset = prefix.length
    const pkcs8Len = readUint32BE(blob, offset)
    offset += 4
    if (offset + pkcs8Len > blob.length) {
        throw new Error('Anchor secret blob is truncated (ES384 PKCS8)')
    }
    const pkcs8 = blob.slice(offset, offset + pkcs8Len)
    offset += pkcs8Len
    const seedLen = readUint32BE(blob, offset)
    offset += 4
    if (offset + seedLen > blob.length || seedLen !== 32) {
        throw new Error('Anchor secret blob is truncated or has invalid ML-DSA-87 seed')
    }
    const seed = blob.slice(offset, offset + seedLen)

    const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        asBuf(pkcs8),
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign']
    )
    const pubJwk = await derivePublicJwkFromEcdsaPrivate(privateKey)
    const mldsa = ml_dsa87.keygen(seed)

    return {
        es384: { privateKey, publicKeyJwk: pubJwk },
        mldsa87: { seed, publicKey: new Uint8Array(mldsa.publicKey) },
    }
}

async function derivePublicJwkFromEcdsaPrivate(privateKey: CryptoKey): Promise<EcP384PublicJwk> {
    const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-384' || !jwk.x || !jwk.y) {
        throw new Error('Imported anchor key is not a valid P-384 EC key')
    }
    return { kty: 'EC', crv: 'P-384', x: jwk.x, y: jwk.y }
}

// Wrapped anchor envelope schema: the decoded body is newline `key=value` in alphabetical order over the three required fields
// `v=1` is the only supported version; `nonce` is base64url of exactly 12 bytes; `ciphertext` is non-empty base64url
// Must be kept in sync with server route-level validator
export type WrappedAnchorEnvelope = {
    ciphertext: string
    nonce: string
    v: 1
}

const WRAPPED_ANCHOR_FIELDS = ['ciphertext', 'nonce', 'v'] as const
const WRAPPED_ANCHOR_NONCE_SIZE = 12

// Wrap the anchor secret blob with the user's wrapping key
export async function wrapAnchorKey(params: {
    anchorSecret: Uint8Array
    wrappingKeyBytes: Uint8Array
    userId: string
}): Promise<string> {
    const wrappingKey = await crypto.subtle.importKey(
        'raw',
        asBuf(params.wrappingKeyBytes),
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    )
    const nonce = crypto.getRandomValues(new Uint8Array(WRAPPED_ANCHOR_NONCE_SIZE))
    const aad = new TextEncoder().encode(`revaulter/v2/wrapped-anchor\nuserId=${params.userId}\nv=1`)
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: asBuf(nonce), additionalData: asBuf(aad) },
        wrappingKey,
        asBuf(params.anchorSecret)
    )
    const body = [`ciphertext=${bytesToBase64Url(ciphertext)}`, `nonce=${bytesToBase64Url(nonce)}`, `v=1`].join('\n')
    return bytesToBase64Url(new TextEncoder().encode(body))
}

// Parses and strictly validates a wrapped anchor envelope from its base64url-encoded form
// Rejects missing, duplicate, or unknown fields; malformed base64url; nonce not 12 bytes; empty ciphertext; wrong version
export function parseWrappedAnchorEnvelope(wrapped: string): WrappedAnchorEnvelope {
    const body = new TextDecoder().decode(base64UrlToBytes(wrapped))
    const lines = body.split('\n')
    if (lines.length !== WRAPPED_ANCHOR_FIELDS.length) {
        throw new Error(
            `Invalid wrapped anchor envelope: expected ${WRAPPED_ANCHOR_FIELDS.length} lines, got ${lines.length}`
        )
    }

    const seen = new Map<string, string>()
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        const eq = line.indexOf('=')
        if (eq < 1) {
            throw new Error(`Invalid wrapped anchor envelope: line ${i} missing '='`)
        }
        const key = line.slice(0, eq)
        const value = line.slice(eq + 1)
        if (key !== WRAPPED_ANCHOR_FIELDS[i]) {
            throw new Error(
                `Invalid wrapped anchor envelope: expected key "${WRAPPED_ANCHOR_FIELDS[i]}" at line ${i}, got "${key}"`
            )
        }
        if (seen.has(key)) {
            throw new Error(`Invalid wrapped anchor envelope: duplicate key "${key}"`)
        }
        seen.set(key, value)
    }

    const v = seen.get('v') as string
    if (v !== '1') {
        throw new Error(`Invalid wrapped anchor envelope: unsupported version "${v}"`)
    }

    const nonceB64 = seen.get('nonce') as string
    const ciphertextB64 = seen.get('ciphertext') as string
    if (!nonceB64) {
        throw new Error('Invalid wrapped anchor envelope: empty nonce')
    }
    if (!ciphertextB64) {
        throw new Error('Invalid wrapped anchor envelope: empty ciphertext')
    }

    let nonceBytes: Uint8Array
    try {
        nonceBytes = base64UrlToBytes(nonceB64)
    } catch {
        throw new Error('Invalid wrapped anchor envelope: nonce is not valid base64url')
    }

    if (nonceBytes.length !== WRAPPED_ANCHOR_NONCE_SIZE) {
        throw new Error(
            `Invalid wrapped anchor envelope: nonce must be ${WRAPPED_ANCHOR_NONCE_SIZE} bytes, got ${nonceBytes.length}`
        )
    }

    // Ensure the ciphertext is valid base64url
    try {
        base64UrlToBytes(ciphertextB64)
    } catch {
        throw new Error('Invalid wrapped anchor envelope: ciphertext is not valid base64url')
    }

    return { v: 1, nonce: nonceB64, ciphertext: ciphertextB64 }
}

export async function unwrapAnchorKey(params: {
    wrapped: string
    wrappingKeyBytes: Uint8Array
    userId: string
}): Promise<AnchorKeyPair> {
    const envelope = parseWrappedAnchorEnvelope(params.wrapped)
    const wrappingKey = await crypto.subtle.importKey(
        'raw',
        asBuf(params.wrappingKeyBytes),
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    )
    const aad = new TextEncoder().encode(`revaulter/v2/wrapped-anchor\nuserId=${params.userId}\nv=1`)
    let blob: Uint8Array
    try {
        const plain = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: asBuf(base64UrlToBytes(envelope.nonce)), additionalData: asBuf(aad) },
            wrappingKey,
            asBuf(base64UrlToBytes(envelope.ciphertext))
        )
        blob = new Uint8Array(plain)
    } catch {
        throw new Error('Failed to unwrap anchor key. The passkey may be incorrect.')
    }
    return parseAnchorSecret(blob)
}

/**
 * Serialize the attestation payload as ordered `key=value` lines separated by `\n`, with no trailing newline
 * This is the format stored in the database and sent on the wire, and the body that (with the domain-separation prefix) is signed by both anchor legs
 */
export function attestationPayloadCanonicalBody(payload: AttestationPayload): string {
    // Field order must exactly match the server
    return [
        `userId=${payload.userId}`,
        `credentialId=${payload.credentialId}`,
        `credentialPublicKeyHash=${payload.credentialPublicKeyHash}`,
        `wrappedKeyEpoch=${payload.wrappedKeyEpoch}`,
        `createdAt=${payload.createdAt}`,
    ].join('\n')
}

function canonicalAttestationMessage(body: string): Uint8Array {
    return new TextEncoder().encode(CRED_ATTEST_PREFIX + body)
}

/**
 * Serialize the pubkey-bundle payload as ordered `key=value` lines separated by `\n`, with no trailing newline
 * This is the body that (with the domain-separation prefix) is signed by both anchor legs
 */
export function pubkeyBundlePayloadCanonicalBody(payload: PubkeyBundlePayload): string {
    // Field order must exactly match pkg/protocolv2.PubkeyBundlePayload canonical body
    return [
        `userId=${payload.userId}`,
        `requestEncEcdhPubkey=${payload.requestEncEcdhPubkey}`,
        `requestEncMlkemPubkey=${payload.requestEncMlkemPubkey}`,
        `anchorEs384Crv=${payload.anchorEs384Crv}`,
        `anchorEs384Kty=${payload.anchorEs384Kty}`,
        `anchorEs384X=${payload.anchorEs384X}`,
        `anchorEs384Y=${payload.anchorEs384Y}`,
        `anchorMldsa87PublicKey=${payload.anchorMldsa87PublicKey}`,
        `wrappedKeyEpoch=${payload.wrappedKeyEpoch}`,
    ].join('\n')
}

function canonicalPubkeyBundleMessage(body: string): Uint8Array {
    return new TextEncoder().encode(PUBKEY_BUNDLE_PREFIX + body)
}

/**
 * Hybrid-sign a credential-attestation payload. Both legs MUST succeed; verifiers
 * reject the signature unless both ES384 and ML-DSA-87 check out.
 *
 * Returns the canonical body string alongside the signatures so the caller can
 * transmit the exact same bytes that were signed.
 */
export async function signCredentialAttestationHybrid(
    anchor: AnchorKeyPair,
    payload: AttestationPayload
): Promise<{ canonicalBody: string; sigEs384: string; sigMldsa87: string }> {
    const canonicalBody = attestationPayloadCanonicalBody(payload)
    const msg = canonicalAttestationMessage(canonicalBody)
    const sig = await signHybrid(anchor, msg)
    return { canonicalBody, ...sig }
}

export async function signPubkeyBundleHybrid(
    anchor: AnchorKeyPair,
    payload: PubkeyBundlePayload
): Promise<{ sigEs384: string; sigMldsa87: string }> {
    const msg = canonicalPubkeyBundleMessage(pubkeyBundlePayloadCanonicalBody(payload))
    return signHybrid(anchor, msg)
}

async function signHybrid(anchor: AnchorKeyPair, msg: Uint8Array): Promise<{ sigEs384: string; sigMldsa87: string }> {
    const esRaw = new Uint8Array(
        await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, anchor.es384.privateKey, asBuf(msg))
    )
    if (esRaw.length !== ES384_SIG_SIZE) {
        throw new Error(`ES384 signature has wrong length ${esRaw.length}, expected ${ES384_SIG_SIZE}`)
    }
    // ml_dsa87.sign expects (msg, secretKey); regenerate the full secret key from the wrapped seed each time.
    const mlkp = ml_dsa87.keygen(anchor.mldsa87.seed)
    const mlSig = ml_dsa87.sign(msg, mlkp.secretKey)
    if (mlSig.length !== MLDSA87_SIG_SIZE) {
        throw new Error(`ML-DSA-87 signature has wrong length ${mlSig.length}, expected ${MLDSA87_SIG_SIZE}`)
    }
    return {
        sigEs384: bytesToBase64Url(esRaw),
        sigMldsa87: bytesToBase64Url(new Uint8Array(mlSig)),
    }
}

/**
 * SHA-256 fingerprint of the anchor pubkey pair (SEC1 uncompressed ES384 point || ML-DSA-87 pubkey)
 * This is what the CLI pins and what humans compare; matches pkg/protocolv2.AnchorFingerprint
 */
export async function anchorFingerprint(
    anchorEs384PublicKeyJwk: EcP384PublicJwk,
    anchorMldsa87PublicKey: Uint8Array
): Promise<string> {
    if (anchorMldsa87PublicKey.length !== MLDSA87_PUB_SIZE) {
        throw new Error(`ML-DSA-87 public key must be ${MLDSA87_PUB_SIZE} bytes, got ${anchorMldsa87PublicKey.length}`)
    }
    const xBytes = base64UrlToBytes(anchorEs384PublicKeyJwk.x)
    const yBytes = base64UrlToBytes(anchorEs384PublicKeyJwk.y)
    if (xBytes.length !== P384_COORD_SIZE || yBytes.length !== P384_COORD_SIZE) {
        throw new Error(
            `ES384 JWK coordinates must be ${P384_COORD_SIZE} bytes each, got x=${xBytes.length} y=${yBytes.length}`
        )
    }

    // SEC1 uncompressed point: 0x04 || X || Y
    const buf = new Uint8Array(1 + 2 * P384_COORD_SIZE + anchorMldsa87PublicKey.length)
    buf[0] = 0x04
    buf.set(xBytes, 1)
    buf.set(yBytes, 1 + P384_COORD_SIZE)
    buf.set(anchorMldsa87PublicKey, 1 + 2 * P384_COORD_SIZE)

    const digest = await crypto.subtle.digest('SHA-256', asBuf(buf))

    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** Serialize the ES384 JWK to its canonical wire string (what the server stores). */
export function anchorEs384JwkToString(jwk: EcP384PublicJwk): string {
    // Fields in alphabetical order, `key=value` separated by `\n`
    return [`crv=${jwk.crv}`, `kty=${jwk.kty}`, `x=${jwk.x}`, `y=${jwk.y}`].join('\n')
}

export function anchorMldsa87PubToString(pub: Uint8Array): string {
    if (pub.length !== MLDSA87_PUB_SIZE) {
        throw new Error(`ML-DSA-87 public key must be ${MLDSA87_PUB_SIZE} bytes, got ${pub.length}`)
    }
    return bytesToBase64Url(pub)
}

function writeUint32BE(buf: Uint8Array, offset: number, value: number): void {
    buf[offset] = (value >>> 24) & 0xff
    buf[offset + 1] = (value >>> 16) & 0xff
    buf[offset + 2] = (value >>> 8) & 0xff
    buf[offset + 3] = value & 0xff
}

function readUint32BE(buf: Uint8Array, offset: number): number {
    if (offset + 4 > buf.length) {
        throw new Error('readUint32BE: offset runs past end of buffer')
    }
    // Multiply the high byte instead of shifting to avoid the sign-extension trap on `byte << 24`
    // JavaScript's << returns a signed Int32, so `0x80 << 24` becomes a negative number
    // Using * keeps the result a positive JS Number throughout and avoids the need for a trailing `>>> 0`
    return buf[offset] * 0x1000000 + (((buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0)
}

// Re-exported sizes for use in tests.
export const ANCHOR_SIZES = {
    p384CoordSize: P384_COORD_SIZE,
    es384SigSize: ES384_SIG_SIZE,
    mldsa87PubSize: MLDSA87_PUB_SIZE,
    mldsa87SigSize: MLDSA87_SIG_SIZE,
}
