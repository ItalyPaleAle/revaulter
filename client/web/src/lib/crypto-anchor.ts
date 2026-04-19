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
    credentialPublicKey: string
    wrappedKeyEpoch: number
    createdAt: number
}

export type PubkeyBundlePayload = {
    userId: string
    requestEncEcdhPubkey: string
    requestEncMlkemPubkey: string
    anchorEs384PublicKey: string
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

/** Wrap the anchor secret blob with the user's wrapping key. Mirrors wrapPrimaryKey. */
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
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const aad = new TextEncoder().encode(`revaulter/v2/wrapped-anchor\nuserId=${params.userId}\nv=1`)
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: asBuf(nonce), additionalData: asBuf(aad) },
        wrappingKey,
        asBuf(params.anchorSecret)
    )
    const envelope = {
        v: 1,
        nonce: bytesToBase64Url(nonce),
        ciphertext: bytesToBase64Url(ciphertext),
    }
    return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(envelope)))
}

export async function unwrapAnchorKey(params: {
    wrapped: string
    wrappingKeyBytes: Uint8Array
    userId: string
}): Promise<AnchorKeyPair> {
    const envelope = JSON.parse(new TextDecoder().decode(base64UrlToBytes(params.wrapped))) as {
        v: number
        nonce: string
        ciphertext: string
    }
    if (envelope.v !== 1 || !envelope.nonce || !envelope.ciphertext) {
        throw new Error('Invalid wrapped anchor envelope')
    }
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

/** Canonical JSON that matches Go's `json.Marshal` + HTML-unescape. Field order is critical. */
function canonicalJson(obj: unknown): Uint8Array {
    return new TextEncoder().encode(JSON.stringify(obj))
}

function canonicalAttestationMessage(payload: AttestationPayload): Uint8Array {
    // Field order must exactly match the Go struct tag ordering in pkg/protocolv2.
    const ordered = {
        userId: payload.userId,
        credentialId: payload.credentialId,
        credentialPublicKey: payload.credentialPublicKey,
        wrappedKeyEpoch: payload.wrappedKeyEpoch,
        createdAt: payload.createdAt,
    }
    return concatBytes(new TextEncoder().encode(CRED_ATTEST_PREFIX), canonicalJson(ordered))
}

function canonicalPubkeyBundleMessage(payload: PubkeyBundlePayload): Uint8Array {
    const ordered = {
        userId: payload.userId,
        requestEncEcdhPubkey: payload.requestEncEcdhPubkey,
        requestEncMlkemPubkey: payload.requestEncMlkemPubkey,
        anchorEs384PublicKey: payload.anchorEs384PublicKey,
        anchorMldsa87PublicKey: payload.anchorMldsa87PublicKey,
        wrappedKeyEpoch: payload.wrappedKeyEpoch,
    }
    return concatBytes(new TextEncoder().encode(PUBKEY_BUNDLE_PREFIX), canonicalJson(ordered))
}

/**
 * Hybrid-sign a credential-attestation payload. Both legs MUST succeed; verifiers
 * reject the signature unless both ES384 and ML-DSA-87 check out.
 */
export async function signCredentialAttestationHybrid(
    anchor: AnchorKeyPair,
    payload: AttestationPayload
): Promise<{ sigEs384: string; sigMldsa87: string }> {
    const msg = canonicalAttestationMessage(payload)
    return signHybrid(anchor, msg)
}

export async function signPubkeyBundleHybrid(
    anchor: AnchorKeyPair,
    payload: PubkeyBundlePayload
): Promise<{ sigEs384: string; sigMldsa87: string }> {
    const msg = canonicalPubkeyBundleMessage(payload)
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
 * SHA-256 fingerprint of the anchor pubkey pair (length-prefixed JWK || length-prefixed ML-DSA-87 pubkey).
 * This is what the CLI pins and what humans compare. Matches pkg/protocolv2.AnchorFingerprint.
 */
export async function anchorFingerprint(
    anchorEs384PublicKeyJwk: EcP384PublicJwk,
    anchorMldsa87PublicKey: Uint8Array
): Promise<string> {
    if (anchorMldsa87PublicKey.length !== MLDSA87_PUB_SIZE) {
        throw new Error(`ML-DSA-87 public key must be ${MLDSA87_PUB_SIZE} bytes, got ${anchorMldsa87PublicKey.length}`)
    }
    const jwkBytes = canonicalJson(anchorEs384PublicKeyJwk)
    const buf = new Uint8Array(4 + jwkBytes.length + 4 + anchorMldsa87PublicKey.length)
    let offset = 0
    writeUint32BE(buf, offset, jwkBytes.length)
    offset += 4
    buf.set(jwkBytes, offset)
    offset += jwkBytes.length
    writeUint32BE(buf, offset, anchorMldsa87PublicKey.length)
    offset += 4
    buf.set(anchorMldsa87PublicKey, offset)
    const digest = await crypto.subtle.digest('SHA-256', asBuf(buf))
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** Serialize the ES384 JWK to its canonical wire string (what the server stores). */
export function anchorEs384JwkToString(jwk: EcP384PublicJwk): string {
    return new TextDecoder().decode(canonicalJson(jwk))
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
    return ((buf[offset] << 24) >>> 0) + (buf[offset + 1] << 16) + (buf[offset + 2] << 8) + buf[offset + 3]
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
    const len = parts.reduce((n, p) => n + p.length, 0)
    const out = new Uint8Array(len)
    let offset = 0
    for (const p of parts) {
        out.set(p, offset)
        offset += p.length
    }
    return out
}

// Re-exported sizes for use in tests.
export const ANCHOR_SIZES = {
    p384CoordSize: P384_COORD_SIZE,
    es384SigSize: ES384_SIG_SIZE,
    mldsa87PubSize: MLDSA87_PUB_SIZE,
    mldsa87SigSize: MLDSA87_SIG_SIZE,
}
