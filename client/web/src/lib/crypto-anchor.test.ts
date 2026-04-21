import { describe, expect, it } from 'vitest'
import {
    type AttestationPayload,
    type PubkeyBundlePayload,
    anchorEs384JwkToString,
    anchorFingerprint,
    anchorMldsa87PubToString,
    attestationPayloadCanonicalBody,
    generateAnchorKeyPair,
    parseAnchorSecret,
    pubkeyBundlePayloadCanonicalBody,
    serializeAnchorSecret,
    signCredentialAttestationHybrid,
    signPubkeyBundleHybrid,
    unwrapAnchorKey,
    wrapAnchorKey,
} from './crypto-anchor'
import { bytesToBase64Url } from './utils'

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
            credentialPublicKey: bytesToBase64Url(new Uint8Array(32)),
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
            credentialPublicKey: 'pk',
            wrappedKeyEpoch: 1,
            createdAt: 1700000000,
        }
        expect(attestationPayloadCanonicalBody(payload)).toBe(
            [
                'userId=u-1',
                'credentialId=cred-1',
                'credentialPublicKey=pk',
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
            anchorEs384PublicKey: anchorEs384JwkToString(kp.es384.publicKeyJwk),
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
            anchorEs384PublicKey: 'es384',
            anchorMldsa87PublicKey: 'mldsa87',
            wrappedKeyEpoch: 2,
        }
        expect(pubkeyBundlePayloadCanonicalBody(payload)).toBe(
            [
                'userId=u-1',
                'requestEncEcdhPubkey=ecdh',
                'requestEncMlkemPubkey=mlkem',
                'anchorEs384PublicKey=es384',
                'anchorMldsa87PublicKey=mldsa87',
                'wrappedKeyEpoch=2',
            ].join('\n')
        )
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
