import { describe, expect, it } from 'vitest'

import {
    type AttestationPayload,
    SIGNING_KEY_PUBLICATION_VERSION,
    type SigningKeyPublicationPayload,
    anchorEs384JwkToString,
    anchorFingerprint,
    anchorMldsa87PubToString,
    attestationPayloadCanonicalBody,
    generateAnchorKeyPair,
    type PubkeyBundlePayload,
    parseAnchorSecret,
    parseWrappedAnchorEnvelope,
    pubkeyBundlePayloadCanonicalBody,
    serializeAnchorSecret,
    signCredentialAttestationHybrid,
    signPubkeyBundleHybrid,
    signSigningKeyPublicationHybrid,
    signingKeyPublicationPayloadCanonicalBody,
    unwrapAnchorKey,
    wrapAnchorKey,
} from '$lib/crypto-anchor'
import { bytesToBase64Url } from '$lib/utils'

// Shared wrapping key for wrap/unwrap round-trip tests.
const WRAP_KEY = new Uint8Array(32).fill(0x11)

describe('anchor secret serialize/parse', () => {
    it('round-trips ES384 private material and ML-DSA-87 seed', async () => {
        const kp = await generateAnchorKeyPair()
        const blob = await serializeAnchorSecret(kp)
        const parsed = await parseAnchorSecret(blob)
        expect(parsed.mldsa87.seed).toEqual(kp.mldsa87.seed)
        expect(parsed.mldsa87.publicKey).toEqual(kp.mldsa87.publicKey)
        expect(parsed.es384.publicKeyJwk).toEqual(kp.es384.publicKeyJwk)
    })

    it('rejects a blob with the wrong prefix', async () => {
        const kp = await generateAnchorKeyPair()
        const blob = await serializeAnchorSecret(kp)
        blob[0] = 0
        await expect(parseAnchorSecret(blob)).rejects.toThrow(/prefix/)
    })
})

describe('wrapAnchorKey / unwrapAnchorKey', () => {
    it('round-trips an anchor secret through the wrapping envelope', async () => {
        const kp = await generateAnchorKeyPair()
        const secret = await serializeAnchorSecret(kp)
        const wrapped = await wrapAnchorKey({
            anchorSecret: secret,
            wrappingKeyBytes: WRAP_KEY,
            userId: 'u-1',
        })
        const unwrapped = await unwrapAnchorKey({
            wrapped,
            wrappingKeyBytes: WRAP_KEY,
            userId: 'u-1',
        })
        expect(unwrapped.mldsa87.seed).toEqual(kp.mldsa87.seed)
    })

    it('rejects decryption under a different userId AAD', async () => {
        const kp = await generateAnchorKeyPair()
        const secret = await serializeAnchorSecret(kp)
        const wrapped = await wrapAnchorKey({
            anchorSecret: secret,
            wrappingKeyBytes: WRAP_KEY,
            userId: 'u-1',
        })
        await expect(
            unwrapAnchorKey({
                wrapped,
                wrappingKeyBytes: WRAP_KEY,
                userId: 'u-2',
            })
        ).rejects.toThrow(/passkey/)
    })
})

describe('hybrid attestation signatures', () => {
    it('produces ES384 and ML-DSA-87 signatures of the expected length', async () => {
        const kp = await generateAnchorKeyPair()
        const payload: AttestationPayload = {
            userId: 'u-1',
            credentialId: 'cred-1',
            credentialPublicKeyHash: bytesToBase64Url(new Uint8Array(32)),
            wrappedKeyEpoch: 1,
            createdAt: 1700000000,
        }
        const sig = await signCredentialAttestationHybrid(kp, payload)
        // 96 bytes of ES384 raw r||s → 128 base64url chars
        expect(sig.sigEs384.length).toBeGreaterThan(120)
        // 4627 bytes of ML-DSA-87 signature → ~6170 base64url chars
        expect(sig.sigMldsa87.length).toBeGreaterThan(6000)
        // The returned canonical body matches the stand-alone helper
        expect(sig.canonicalBody).toBe(attestationPayloadCanonicalBody(payload))
    })

    it('produces a stable canonical body with ordered key=value lines', () => {
        const payload: AttestationPayload = {
            userId: 'u-1',
            credentialId: 'cred-1',
            credentialPublicKeyHash: 'pk',
            wrappedKeyEpoch: 1,
            createdAt: 1700000000,
        }
        expect(attestationPayloadCanonicalBody(payload)).toBe(
            [
                'userId=u-1',
                'credentialId=cred-1',
                'credentialPublicKeyHash=pk',
                'wrappedKeyEpoch=1',
                'createdAt=1700000000',
            ].join('\n')
        )
    })

    it('signs pubkey bundles with both legs', async () => {
        const kp = await generateAnchorKeyPair()
        const sig = await signPubkeyBundleHybrid(kp, {
            userId: 'u-1',
            requestEncEcdhPubkey: '{"kty":"EC","crv":"P-256","x":"a","y":"b"}',
            requestEncMlkemPubkey: bytesToBase64Url(new Uint8Array(32)),
            anchorEs384Crv: kp.es384.publicKeyJwk.crv,
            anchorEs384Kty: kp.es384.publicKeyJwk.kty,
            anchorEs384X: kp.es384.publicKeyJwk.x,
            anchorEs384Y: kp.es384.publicKeyJwk.y,
            anchorMldsa87PublicKey: anchorMldsa87PubToString(kp.mldsa87.publicKey),
            wrappedKeyEpoch: 1,
        })
        expect(sig.sigEs384).toBeTruthy()
        expect(sig.sigMldsa87).toBeTruthy()
    })

    it('produces a stable canonical pubkey bundle body with ordered key=value lines', () => {
        const payload: PubkeyBundlePayload = {
            userId: 'u-1',
            requestEncEcdhPubkey: 'ecdh',
            requestEncMlkemPubkey: 'mlkem',
            anchorEs384Crv: 'P-384',
            anchorEs384Kty: 'EC',
            anchorEs384X: 'aaa',
            anchorEs384Y: 'bbb',
            anchorMldsa87PublicKey: 'mldsa87',
            wrappedKeyEpoch: 2,
        }
        expect(pubkeyBundlePayloadCanonicalBody(payload)).toBe(
            [
                'userId=u-1',
                'requestEncEcdhPubkey=ecdh',
                'requestEncMlkemPubkey=mlkem',
                'anchorEs384Crv=P-384',
                'anchorEs384Kty=EC',
                'anchorEs384X=aaa',
                'anchorEs384Y=bbb',
                'anchorMldsa87PublicKey=mldsa87',
                'wrappedKeyEpoch=2',
            ].join('\n')
        )
    })

    it('serializes an ES384 JWK as alphabetical key=value lines', () => {
        const jwk = { kty: 'EC', crv: 'P-384', x: 'aaa', y: 'bbb' } as const
        expect(anchorEs384JwkToString(jwk)).toBe(['crv=P-384', 'kty=EC', 'x=aaa', 'y=bbb'].join('\n'))
    })

    it('signs publication payloads with both legs', async () => {
        const kp = await generateAnchorKeyPair()
        const sig = await signSigningKeyPublicationHybrid(kp, {
            userId: 'u-1',
            algorithm: 'ES256',
            keyLabel: 'release-signing',
            keyId: '0123456789abcdef',
            wrappedKeyEpoch: 1,
            createdAt: 1700000000,
            v: SIGNING_KEY_PUBLICATION_VERSION,
        })
        expect(sig.sigEs384.length).toBeGreaterThan(120)
        expect(sig.sigMldsa87.length).toBeGreaterThan(6000)
    })

    it('produces a stable canonical publication body matching the Go fixture', () => {
        // This must byte-match the expected body in pkg/protocolv2/signing-key-publication_test.go::TestSigningKeyPublicationCanonicalBody
        const payload: SigningKeyPublicationPayload = {
            userId: 'user-pub-1',
            algorithm: 'ES256',
            keyLabel: 'release-signing',
            keyId: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            wrappedKeyEpoch: 1,
            createdAt: 1730000000,
            v: 1,
        }
        const expected = [
            'userId=user-pub-1',
            'algorithm=ES256',
            'keyLabel=release-signing',
            'keyId=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            'wrappedKeyEpoch=1',
            'createdAt=1730000000',
            'v=1',
        ].join('\n')
        expect(signingKeyPublicationPayloadCanonicalBody(payload)).toBe(expected)
    })
})

describe('parseWrappedAnchorEnvelope', () => {
    // wrapBody base64url-encodes a literal newline body so tests can construct invalid shapes directly
    function wrapBody(body: string): string {
        return bytesToBase64Url(new TextEncoder().encode(body))
    }
    const goodCiphertext = bytesToBase64Url(new TextEncoder().encode('ct'))
    const goodNonce = bytesToBase64Url(new Uint8Array(12))
    const goodBody = `ciphertext=${goodCiphertext}\nnonce=${goodNonce}\nv=1`

    it('round-trips wrapAnchorKey output', async () => {
        const kp = await generateAnchorKeyPair()
        const secret = await serializeAnchorSecret(kp)
        const wrapped = await wrapAnchorKey({
            anchorSecret: secret,
            wrappingKeyBytes: WRAP_KEY,
            userId: 'u-1',
        })
        const env = parseWrappedAnchorEnvelope(wrapped)
        expect(env.v).toBe(1)
        expect(env.nonce).toBeTruthy()
        expect(env.ciphertext).toBeTruthy()
    })

    it('rejects wrong line count', () => {
        expect(() => parseWrappedAnchorEnvelope(wrapBody(`ciphertext=${goodCiphertext}\nv=1`))).toThrow(
            /expected 3 lines/
        )
        expect(() => parseWrappedAnchorEnvelope(wrapBody(`${goodBody}\nextra=x`))).toThrow(/expected 3 lines/)
    })

    it('rejects fields in the wrong order', () => {
        const reordered = `nonce=${goodNonce}\nciphertext=${goodCiphertext}\nv=1`
        expect(() => parseWrappedAnchorEnvelope(wrapBody(reordered))).toThrow(/expected key/)
    })

    it('rejects unknown fields', () => {
        const withUnknown = `ciphertext=${goodCiphertext}\nnonce=${goodNonce}\nversion=1`
        expect(() => parseWrappedAnchorEnvelope(wrapBody(withUnknown))).toThrow(/expected key/)
    })

    it('rejects duplicate keys', () => {
        // A duplicate nonce inserted in ciphertext's slot breaks the ordered key check first, which still proves duplicates cannot slip through
        const dup = `nonce=${goodNonce}\nnonce=${goodNonce}\nv=1`
        expect(() => parseWrappedAnchorEnvelope(wrapBody(dup))).toThrow()
    })

    it('rejects lines missing an =', () => {
        const missingEquals = `ciphertext\nnonce=${goodNonce}\nv=1`
        expect(() => parseWrappedAnchorEnvelope(wrapBody(missingEquals))).toThrow(/missing '='/)
    })

    it('rejects unsupported version', () => {
        const v2 = `ciphertext=${goodCiphertext}\nnonce=${goodNonce}\nv=2`
        expect(() => parseWrappedAnchorEnvelope(wrapBody(v2))).toThrow(/unsupported version/)
    })

    it('rejects empty ciphertext', () => {
        const emptyCt = `ciphertext=\nnonce=${goodNonce}\nv=1`
        expect(() => parseWrappedAnchorEnvelope(wrapBody(emptyCt))).toThrow(/ciphertext/)
    })

    it('rejects empty nonce', () => {
        const emptyNonce = `ciphertext=${goodCiphertext}\nnonce=\nv=1`
        expect(() => parseWrappedAnchorEnvelope(wrapBody(emptyNonce))).toThrow(/nonce/)
    })

    it('rejects nonce of wrong size', () => {
        const shortNonce = bytesToBase64Url(new Uint8Array(8))
        const body = `ciphertext=${goodCiphertext}\nnonce=${shortNonce}\nv=1`
        expect(() => parseWrappedAnchorEnvelope(wrapBody(body))).toThrow(/12 bytes/)
    })
})

describe('anchorFingerprint', () => {
    it('produces a lowercase hex digest', async () => {
        const kp = await generateAnchorKeyPair()
        const fp = await anchorFingerprint(kp.es384.publicKeyJwk, kp.mldsa87.publicKey)
        expect(fp).toMatch(/^[0-9a-f]{64}$/)
    })

    it('changes when either half of the anchor changes', async () => {
        const a = await generateAnchorKeyPair()
        const b = await generateAnchorKeyPair()
        const fpA = await anchorFingerprint(a.es384.publicKeyJwk, a.mldsa87.publicKey)
        const fpMixed1 = await anchorFingerprint(b.es384.publicKeyJwk, a.mldsa87.publicKey)
        const fpMixed2 = await anchorFingerprint(a.es384.publicKeyJwk, b.mldsa87.publicKey)
        expect(fpA).not.toEqual(fpMixed1)
        expect(fpA).not.toEqual(fpMixed2)
        expect(fpMixed1).not.toEqual(fpMixed2)
    })
})
