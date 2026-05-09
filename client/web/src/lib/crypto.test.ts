import { argon2id } from '@awasm/noble'
import { ed25519, ed25519ph } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { bytesToHex } from '@noble/curves/utils.js'
import { describe, expect, it } from 'vitest'

import {
    computeSigningKeyThumbprint,
    decryptTransportEnvelope,
    deriveOperationKeyBytes,
    deriveRequestEncKeyPair,
    deriveRequestEncMlkemKeyPair,
    deriveSigningKeyPair,
    deriveWrappingKey,
    encryptTransportEnvelope,
    generatePrimaryKey,
    parseWrappedPrimaryKeyEnvelope,
    signingJwkToPem,
    signingJwkToSshPublicKey,
    signDigestEd25519ph,
    signDigestEs256,
    signMessageEd25519,
    unwrapPrimaryKey,
    wrapPrimaryKey,
} from '$lib/crypto'
import { base64UrlToBytes, bytesToBase64Url } from '$lib/utils'

// Shared test primary key: 32 bytes of 0xAA (used as IKM for HKDF derivation tests)
const TEST_PRIMARY_KEY = new Uint8Array(32).fill(0xaa)

// Shared test PRF secret: 32 bytes of 0xBB (used for wrapping key derivation tests)
const TEST_PRF_SECRET = new Uint8Array(32).fill(0xbb)

// Low-cost Argon2id parameters used only for tests to keep derivation fast
const TEST_ARGON2ID_COST = { m: 8, t: 1, p: 1 }

describe('generatePrimaryKey', () => {
    it('produces 32 bytes', async () => {
        const pk = await generatePrimaryKey()
        expect(pk.length).toBe(32)
    })

    it('produces different keys each call', async () => {
        const pk1 = await generatePrimaryKey()
        const pk2 = await generatePrimaryKey()
        expect(bytesToHex(pk1)).not.toBe(bytesToHex(pk2))
    })
})

describe('argon2id (awasm-noble) determinism', () => {
    // Pinned vector to catch any awasm-noble change that would break existing wrapped-primary-key envelopes
    // The same (password, salt, t, m, p, dkLen) was verified to produce the same output under @noble/hashes 2.2.0 (RFC 9106 conformant)
    it('matches the pinned RFC 9106-conformant vector for ASCII inputs', async () => {
        const password = new TextEncoder().encode('password')
        const salt = new TextEncoder().encode('saltsalt12345678')
        const expected = '4599a3b4658f4a3266e49ef7964b36d9dc8cc6b75a30295ac3b02d85539c0072'

        const out = await argon2id.async(password, salt, { t: 2, m: 256, p: 1, dkLen: 32 })
        expect(bytesToHex(out)).toBe(expected)
    })

    it('matches the pinned vector for binary salt at low cost (deriveWrappingKey-style inputs)', async () => {
        const password = new TextEncoder().encode('test-password')
        const salt = new Uint8Array(16).fill(0x42)
        const expected = 'd7a02862ff4436f797551af3df85d4ea5951e76a0997ffdb8ca2d38497ec9002'

        const out = await argon2id.async(password, salt, { t: 1, m: 8, p: 1, dkLen: 32 })
        expect(bytesToHex(out)).toBe(expected)
    })
})

describe('deriveWrappingKey', () => {
    it('produces 32 bytes without password', async () => {
        const { wrappingKeyBytes } = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
        })
        expect(wrappingKeyBytes.length).toBe(32)
    })

    it('is deterministic without password', async () => {
        const r1 = await deriveWrappingKey({ prfSecret: TEST_PRF_SECRET, userId: 'user-1' })
        const r2 = await deriveWrappingKey({ prfSecret: TEST_PRF_SECRET, userId: 'user-1' })
        expect(bytesToHex(r1.wrappingKeyBytes)).toBe(bytesToHex(r2.wrappingKeyBytes))
    })

    it('differs for different users', async () => {
        const r1 = await deriveWrappingKey({ prfSecret: TEST_PRF_SECRET, userId: 'user-1' })
        const r2 = await deriveWrappingKey({ prfSecret: TEST_PRF_SECRET, userId: 'user-2' })
        expect(bytesToHex(r1.wrappingKeyBytes)).not.toBe(bytesToHex(r2.wrappingKeyBytes))
    })

    it('returns argon2idSalt and stretched when password is provided', async () => {
        const { wrappingKeyBytes, stretched, argon2idSalt } = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'hunter2',
            argon2idCost: TEST_ARGON2ID_COST,
        })
        expect(wrappingKeyBytes.length).toBe(32)
        expect(stretched).toBeDefined()
        expect(stretched?.length).toBe(32)
        expect(argon2idSalt).toBeDefined()
        expect(argon2idSalt?.length).toBe(16)
    }, 30_000)

    it('throws when password is provided without argon2idCost', async () => {
        await expect(
            deriveWrappingKey({
                prfSecret: TEST_PRF_SECRET,
                userId: 'user-1',
                password: 'hunter2',
            })
        ).rejects.toThrow(/argon2idCost is required/)
    })

    it('is deterministic with password and fixed salt', async () => {
        const fixedSalt = new Uint8Array(16).fill(0x42)
        const r1 = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'hunter2',
            argon2idSalt: fixedSalt,
            argon2idCost: TEST_ARGON2ID_COST,
        })
        const r2 = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'hunter2',
            argon2idSalt: fixedSalt,
            argon2idCost: TEST_ARGON2ID_COST,
        })
        expect(bytesToHex(r1.wrappingKeyBytes)).toBe(bytesToHex(r2.wrappingKeyBytes))
    }, 30_000)

    it('password changes the wrapping key', async () => {
        const fixedSalt = new Uint8Array(16).fill(0x42)
        const r1 = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'password-a',
            argon2idSalt: fixedSalt,
            argon2idCost: TEST_ARGON2ID_COST,
        })
        const r2 = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'password-b',
            argon2idSalt: fixedSalt,
            argon2idCost: TEST_ARGON2ID_COST,
        })
        expect(bytesToHex(r1.wrappingKeyBytes)).not.toBe(bytesToHex(r2.wrappingKeyBytes))
    }, 30_000)
})

describe('wrapPrimaryKey / unwrapPrimaryKey', () => {
    it('round-trips without password', async () => {
        const pk = await generatePrimaryKey()
        const { wrappingKeyBytes } = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: 'user-1',
            passwordRequired: false,
        })

        const unwrapped = await unwrapPrimaryKey({
            wrapped,
            wrappingKeyBytes,
            userId: 'user-1',
        })
        expect(bytesToHex(unwrapped)).toBe(bytesToHex(pk))
    })

    it('round-trips with password', async () => {
        const pk = await generatePrimaryKey()
        const { wrappingKeyBytes, argon2idSalt } = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'test-password',
            argon2idCost: TEST_ARGON2ID_COST,
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: 'user-1',
            passwordRequired: true,
            argon2idSalt,
            argon2idCost: TEST_ARGON2ID_COST,
        })

        const unwrapped = await unwrapPrimaryKey({
            wrapped,
            wrappingKeyBytes,
            userId: 'user-1',
        })
        expect(bytesToHex(unwrapped)).toBe(bytesToHex(pk))
    }, 30_000)

    it('envelope has correct structure without password', async () => {
        const pk = await generatePrimaryKey()
        const { wrappingKeyBytes } = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: 'user-1',
            passwordRequired: false,
        })

        const envelope = parseWrappedPrimaryKeyEnvelope(wrapped)
        expect(envelope.v).toBe(1)
        expect(envelope.passwordRequired).toBe(false)
        expect(envelope.argon2id).toBeUndefined()
        expect(envelope.nonce).toBeTruthy()
        expect(envelope.ciphertext).toBeTruthy()
    })

    it('envelope has correct structure with password', async () => {
        const pk = await generatePrimaryKey()
        const salt = new Uint8Array(16).fill(0x11)
        const { wrappingKeyBytes } = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'pw',
            argon2idSalt: salt,
            argon2idCost: TEST_ARGON2ID_COST,
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: 'user-1',
            passwordRequired: true,
            argon2idSalt: salt,
            argon2idCost: TEST_ARGON2ID_COST,
        })

        const envelope = parseWrappedPrimaryKeyEnvelope(wrapped)
        expect(envelope.v).toBe(1)
        expect(envelope.passwordRequired).toBe(true)
        expect(envelope.argon2id).toBeDefined()
        expect(envelope.argon2id?.m).toBe(TEST_ARGON2ID_COST.m)
        expect(envelope.argon2id?.t).toBe(TEST_ARGON2ID_COST.t)
        expect(envelope.argon2id?.p).toBe(TEST_ARGON2ID_COST.p)
        expect(envelope.argon2id?.salt).toBeTruthy()
    }, 30_000)

    it('rejects wrong wrapping key', async () => {
        const pk = await generatePrimaryKey()
        const { wrappingKeyBytes } = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: 'user-1',
            passwordRequired: false,
        })

        const wrongKey = crypto.getRandomValues(new Uint8Array(32))
        await expect(
            unwrapPrimaryKey({
                wrapped,
                wrappingKeyBytes: wrongKey,
                userId: 'user-1',
            })
        ).rejects.toThrow('Failed to unwrap')
    })

    it('rejects wrong userId (AAD mismatch)', async () => {
        const pk = await generatePrimaryKey()
        const { wrappingKeyBytes } = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: 'user-1',
            passwordRequired: false,
        })

        await expect(
            unwrapPrimaryKey({
                wrapped,
                wrappingKeyBytes,
                userId: 'user-2',
            })
        ).rejects.toThrow('Failed to unwrap')
    })
})

describe('parseWrappedPrimaryKeyEnvelope', () => {
    it('rejects invalid version', () => {
        const json = JSON.stringify({ v: 2, passwordRequired: false, nonce: 'aaa', ciphertext: 'bbb' })
        const encoded = bytesToBase64Url(new TextEncoder().encode(json))
        expect(() => parseWrappedPrimaryKeyEnvelope(encoded)).toThrow('Unsupported wrapped key version')
    })

    it('rejects missing passwordRequired', () => {
        const json = JSON.stringify({ v: 1, nonce: 'aaa', ciphertext: 'bbb' })
        const encoded = bytesToBase64Url(new TextEncoder().encode(json))
        expect(() => parseWrappedPrimaryKeyEnvelope(encoded)).toThrow('missing passwordRequired')
    })

    it('rejects password-required envelope without argon2id params', () => {
        const json = JSON.stringify({ v: 1, passwordRequired: true, nonce: 'aaa', ciphertext: 'bbb' })
        const encoded = bytesToBase64Url(new TextEncoder().encode(json))
        expect(() => parseWrappedPrimaryKeyEnvelope(encoded)).toThrow('argon2id params missing')
    })
})

describe('deriveOperationKeyBytes', () => {
    it('produces 32 bytes', async () => {
        const key = await deriveOperationKeyBytes({
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'A256GCM',
            primaryKey: TEST_PRIMARY_KEY,
        })
        expect(key.length).toBe(32)
    })

    it('is deterministic', async () => {
        const params = {
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'A256GCM',
            primaryKey: TEST_PRIMARY_KEY,
        }
        const k1 = await deriveOperationKeyBytes(params)
        const k2 = await deriveOperationKeyBytes(params)
        expect(bytesToHex(k1)).toBe(bytesToHex(k2))
    })

    it('differs when userId changes', async () => {
        const base = {
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'A256GCM',
            primaryKey: TEST_PRIMARY_KEY,
        }
        const k1 = await deriveOperationKeyBytes(base)
        const k2 = await deriveOperationKeyBytes({ ...base, userId: 'user-2' })
        expect(bytesToHex(k1)).not.toBe(bytesToHex(k2))
    })

    it('differs when keyLabel changes', async () => {
        const base = {
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'A256GCM',
            primaryKey: TEST_PRIMARY_KEY,
        }
        const k1 = await deriveOperationKeyBytes(base)
        const k2 = await deriveOperationKeyBytes({ ...base, keyLabel: 'other-key' })
        expect(bytesToHex(k1)).not.toBe(bytesToHex(k2))
    })

    it('differs when primaryKey changes', async () => {
        const base = {
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'A256GCM',
            primaryKey: TEST_PRIMARY_KEY,
        }
        const k1 = await deriveOperationKeyBytes(base)
        const k2 = await deriveOperationKeyBytes({
            ...base,
            primaryKey: new Uint8Array(32).fill(0xbb),
        })
        expect(bytesToHex(k1)).not.toBe(bytesToHex(k2))
    })
})

describe('deriveRequestEncKeyPair', () => {
    it('is deterministic', async () => {
        const params = { userId: 'user-1', primaryKey: TEST_PRIMARY_KEY }
        const kp1 = await deriveRequestEncKeyPair(params)
        const kp2 = await deriveRequestEncKeyPair(params)
        expect(kp1.publicKeyJwk.x).toBe(kp2.publicKeyJwk.x)
        expect(kp1.publicKeyJwk.y).toBe(kp2.publicKeyJwk.y)
    })

    it('produces different keys for different users', async () => {
        const kp1 = await deriveRequestEncKeyPair({ userId: 'user-1', primaryKey: TEST_PRIMARY_KEY })
        const kp2 = await deriveRequestEncKeyPair({ userId: 'user-2', primaryKey: TEST_PRIMARY_KEY })
        expect(kp1.publicKeyJwk.x).not.toBe(kp2.publicKeyJwk.x)
    })

    it('produces different keys for different primary keys', async () => {
        const kp1 = await deriveRequestEncKeyPair({ userId: 'user-1', primaryKey: TEST_PRIMARY_KEY })
        const kp2 = await deriveRequestEncKeyPair({
            userId: 'user-1',
            primaryKey: new Uint8Array(32).fill(0xcc),
        })
        expect(kp1.publicKeyJwk.x).not.toBe(kp2.publicKeyJwk.x)
    })

    it('returns a valid P-256 JWK', async () => {
        const { publicKeyJwk } = await deriveRequestEncKeyPair({ userId: 'u', primaryKey: TEST_PRIMARY_KEY })
        expect(publicKeyJwk.kty).toBe('EC')
        expect(publicKeyJwk.crv).toBe('P-256')
        expect(publicKeyJwk.x.length).toBeGreaterThan(0)
        expect(publicKeyJwk.y.length).toBeGreaterThan(0)
    })

    it('private scalar is usable for ECDH against a peer', async () => {
        const { scalar } = await deriveRequestEncKeyPair({ userId: 'u', primaryKey: TEST_PRIMARY_KEY })
        expect(scalar).toBeInstanceOf(Uint8Array)
        expect(scalar.length).toBe(32)

        // Pair with a peer generated via noble and confirm getSharedSecret returns the expected 33-byte compressed shared point
        const peer = p256.utils.randomSecretKey()
        const peerPub = p256.getPublicKey(peer, false)
        const shared = p256.getSharedSecret(scalar, peerPub)
        expect(shared.length).toBe(33)
    })
})

describe('deriveRequestEncMlkemKeyPair', () => {
    it('is deterministic', async () => {
        const params = { userId: 'user-1', primaryKey: TEST_PRIMARY_KEY }
        const kp1 = await deriveRequestEncMlkemKeyPair(params)
        const kp2 = await deriveRequestEncMlkemKeyPair(params)
        expect(kp1.encapsulationKeyB64).toBe(kp2.encapsulationKeyB64)
    })

    it('produces different keys for different primary keys', async () => {
        const kp1 = await deriveRequestEncMlkemKeyPair({ userId: 'user-1', primaryKey: TEST_PRIMARY_KEY })
        const kp2 = await deriveRequestEncMlkemKeyPair({
            userId: 'user-1',
            primaryKey: new Uint8Array(32).fill(0xcc),
        })
        expect(kp1.encapsulationKeyB64).not.toBe(kp2.encapsulationKeyB64)
    })

    it('produces different keys for different users', async () => {
        const kp1 = await deriveRequestEncMlkemKeyPair({ userId: 'user-1', primaryKey: TEST_PRIMARY_KEY })
        const kp2 = await deriveRequestEncMlkemKeyPair({ userId: 'user-2', primaryKey: TEST_PRIMARY_KEY })
        expect(kp1.encapsulationKeyB64).not.toBe(kp2.encapsulationKeyB64)
    })

    it('encapsulation key is 1184 bytes (ML-KEM-768)', async () => {
        const { encapsulationKeyB64 } = await deriveRequestEncMlkemKeyPair({
            userId: 'u',
            primaryKey: TEST_PRIMARY_KEY,
        })
        // base64url decode to check raw size
        const raw = Uint8Array.from(atob(encapsulationKeyB64.replace(/-/g, '+').replace(/_/g, '/')), (c) =>
            c.charCodeAt(0)
        )
        expect(raw.length).toBe(1184)
    })
})

describe('transport envelope encrypt/decrypt round-trip', () => {
    /** Reconstructs the public JWK from a P-256 scalar so test code can hand it to encryptTransportEnvelope */
    function publicJwkFromScalar(scalar: Uint8Array) {
        const pub = p256.getPublicKey(scalar, false)
        return {
            kty: 'EC' as const,
            crv: 'P-256' as const,
            x: bytesToBase64Url(pub.subarray(1, 33)),
            y: bytesToBase64Url(pub.subarray(33, 65)),
        }
    }

    it('encrypts and decrypts with hybrid ECDH + ML-KEM', async () => {
        // Simulate CLI: generate transport key pairs as raw scalar/public-key bytes
        const ecdhScalar = p256.utils.randomSecretKey()

        // ML-KEM key pair for transport
        const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js')
        const mlkemKP = ml_kem768.keygen(crypto.getRandomValues(new Uint8Array(64)))
        const mlkemPubB64 = bytesToBase64Url(mlkemKP.publicKey)

        const plaintext = new TextEncoder().encode('secret response data')
        const aad = new TextEncoder().encode('algorithm=A256GCM\noperation=encrypt\nstate=test-state\nv=1')

        // Browser encrypts the response envelope
        const envelope = await encryptTransportEnvelope(
            'test-state',
            publicJwkFromScalar(ecdhScalar),
            mlkemPubB64,
            plaintext,
            aad
        )

        expect(envelope.transportAlg).toBe('ecdh-p256+mlkem768+a256gcm')
        expect(envelope.mlkemCiphertext).toBeTruthy()
        expect(envelope.nonce).toBeTruthy()
        expect(envelope.ciphertext).toBeTruthy()

        // CLI decrypts the response envelope
        const decrypted = await decryptTransportEnvelope('test-state', ecdhScalar, mlkemKP.secretKey, envelope, aad)

        expect(new TextDecoder().decode(decrypted)).toBe('secret response data')
    })

    it('rejects envelope with wrong state', async () => {
        const ecdhScalar = p256.utils.randomSecretKey()

        const { ml_kem768 } = await import('@noble/post-quantum/ml-kem.js')
        const mlkemKP = ml_kem768.keygen(crypto.getRandomValues(new Uint8Array(64)))
        const mlkemPubB64 = bytesToBase64Url(mlkemKP.publicKey)

        const plaintext = new TextEncoder().encode('data')

        const envelope = await encryptTransportEnvelope(
            'state-A',
            publicJwkFromScalar(ecdhScalar),
            mlkemPubB64,
            plaintext
        )

        // Decrypt with a different state — HKDF produces a different key, so decryption fails
        await expect(decryptTransportEnvelope('state-B', ecdhScalar, mlkemKP.secretKey, envelope)).rejects.toThrow()
    })
})

describe('deriveSigningKeyPair', () => {
    it('is deterministic for the same inputs', async () => {
        for (const algorithm of ['ES256', 'Ed25519', 'Ed25519ph']) {
            const a = await deriveSigningKeyPair({
                userId: 'user-1',
                keyLabel: 'payments',
                algorithm,
                primaryKey: TEST_PRIMARY_KEY,
            })
            const b = await deriveSigningKeyPair({
                userId: 'user-1',
                keyLabel: 'payments',
                algorithm,
                primaryKey: TEST_PRIMARY_KEY,
            })
            expect(a.publicJwk).toStrictEqual(b.publicJwk)
        }
    })

    it('is domain-separated by userId, keyLabel, and primary key', async () => {
        for (const algorithm of ['ES256', 'Ed25519', 'Ed25519ph']) {
            const base = await deriveSigningKeyPair({
                userId: 'user-1',
                keyLabel: 'payments',
                algorithm,
                primaryKey: TEST_PRIMARY_KEY,
            })
            const diffUser = await deriveSigningKeyPair({
                userId: 'user-2',
                keyLabel: 'payments',
                algorithm,
                primaryKey: TEST_PRIMARY_KEY,
            })
            const diffLabel = await deriveSigningKeyPair({
                userId: 'user-1',
                keyLabel: 'refunds',
                algorithm,
                primaryKey: TEST_PRIMARY_KEY,
            })
            const diffKey = await deriveSigningKeyPair({
                userId: 'user-1',
                keyLabel: 'payments',
                algorithm,
                primaryKey: new Uint8Array(32).fill(0xcc),
            })
            expect(diffUser.publicJwk).not.toStrictEqual(base.publicJwk)
            expect(diffLabel.publicJwk).not.toStrictEqual(base.publicJwk)
            expect(diffKey.publicJwk).not.toStrictEqual(base.publicJwk)
        }
    })

    it('rejects unsupported algorithms', async () => {
        await expect(
            deriveSigningKeyPair({
                userId: 'u',
                keyLabel: 'k',
                algorithm: 'ES384',
                primaryKey: TEST_PRIMARY_KEY,
            })
        ).rejects.toThrow(/Unsupported signing algorithm/)
    })

    it('returns algorithm-appropriate public JWKs without private material', async () => {
        const es256 = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k-es',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        expect(es256.publicJwk.kty).toBe('EC')
        expect(es256.publicJwk.crv).toBe('P-256')
        expect((es256.publicJwk as Record<string, unknown>).d).toBeUndefined()

        const ed25519Key = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k-ed',
            algorithm: 'Ed25519',
            primaryKey: TEST_PRIMARY_KEY,
        })
        expect(ed25519Key.publicJwk.kty).toBe('OKP')
        expect(ed25519Key.publicJwk.crv).toBe('Ed25519')
        expect((ed25519Key.publicJwk as Record<string, unknown>).d).toBeUndefined()
    })
})

describe('signDigestEs256', () => {
    /** Reconstructs the uncompressed P-256 public key bytes (0x04 || X || Y) from the public JWK */
    function publicKeyBytesFromJwk(jwk: { x: string; y: string }): Uint8Array {
        const x = base64UrlToBytes(jwk.x)
        const y = base64UrlToBytes(jwk.y)
        const out = new Uint8Array(65)
        out[0] = 0x04
        out.set(x, 1)
        out.set(y, 33)
        return out
    }

    it('produces a 64-byte raw r||s signature that verifies against the supplied digest', async () => {
        const { secretKey, publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const digest = new Uint8Array(32)
        crypto.getRandomValues(digest)
        const sig = await signDigestEs256(secretKey, digest)
        expect(sig).toBeInstanceOf(Uint8Array)
        expect(sig.length).toBe(64)
        expect(publicJwk.kty).toBe('EC')
        if (publicJwk.kty !== 'EC') {
            throw new Error('expected EC signing key')
        }

        // Verify with prehash:false because the browser now signs the digest directly without re-hashing
        const pubBytes = publicKeyBytesFromJwk(publicJwk)
        const ok = p256.verify(sig, digest, pubBytes, { prehash: false, format: 'compact' })
        expect(ok).toBe(true)
    })

    it('does not verify when the digest is treated as a message that should be hashed (regression check for the prior bug)', async () => {
        const { secretKey, publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const digest = new Uint8Array(32)
        crypto.getRandomValues(digest)
        const sig = await signDigestEs256(secretKey, digest)
        expect(publicJwk.kty).toBe('EC')
        if (publicJwk.kty !== 'EC') {
            throw new Error('expected EC signing key')
        }
        const pubBytes = publicKeyBytesFromJwk(publicJwk)

        // Under the old (buggy) WebCrypto path the browser signed SHA-256(digest)
        // With the fix, signing over the digest directly must NOT verify against SHA-256(digest)
        const rehashed = new Uint8Array(await crypto.subtle.digest('SHA-256', digest as BufferSource))
        const okRehashed = p256.verify(sig, rehashed, pubBytes, { prehash: false, format: 'compact' })
        expect(okRehashed).toBe(false)
    })

    it('rejects digests that are not 32 bytes', async () => {
        const { secretKey } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        await expect(signDigestEs256(secretKey, new Uint8Array(31))).rejects.toThrow(/32-byte digest/)
        await expect(signDigestEs256(secretKey, new Uint8Array(33))).rejects.toThrow(/32-byte digest/)
    })
})

describe('signMessageEd25519', () => {
    it('matches noble Ed25519 signatures over raw message bytes', async () => {
        const { secretKey, publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'Ed25519',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const msg = new TextEncoder().encode('hello ed25519')
        const sig = await signMessageEd25519(secretKey, msg)
        expect(sig.length).toBe(64)
        expect(sig).toStrictEqual(ed25519.sign(msg, secretKey))
        expect(ed25519.verify(sig, msg, base64UrlToBytes(publicJwk.x))).toBe(true)
    })
})

describe('signDigestEd25519ph', () => {
    it('matches standard Ed25519ph signing of the original message digest', async () => {
        const { secretKey, publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'Ed25519ph',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const msg = new TextEncoder().encode('hello ed25519ph')
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', msg as BufferSource))
        const sig = await signDigestEd25519ph(secretKey, digest)
        expect(sig.length).toBe(64)
        expect(sig).toStrictEqual(ed25519ph.sign(msg, secretKey))
        expect(ed25519ph.verify(sig, msg, base64UrlToBytes(publicJwk.x))).toBe(true)
    })

    it('rejects digests that are not 64 bytes', async () => {
        const { secretKey } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'Ed25519ph',
            primaryKey: TEST_PRIMARY_KEY,
        })
        await expect(signDigestEd25519ph(secretKey, new Uint8Array(63))).rejects.toThrow(/64-byte digest/)
        await expect(signDigestEd25519ph(secretKey, new Uint8Array(65))).rejects.toThrow(/64-byte digest/)
    })
})

describe('computeSigningKeyThumbprint', () => {
    it('matches the expected base64url-encoded SHA-256 over the canonical JWK', async () => {
        const jwk = {
            kty: 'EC' as const,
            crv: 'P-256' as const,
            x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        }
        const canonical = `{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`
        const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
        const expected = bytesToBase64Url(new Uint8Array(hash))

        const got = await computeSigningKeyThumbprint(jwk)
        expect(got).toBe(expected)

        // base64url-unpadded length for 32 bytes is 43 chars
        expect(got).toHaveLength(43)
    })

    it('is deterministic across calls', async () => {
        const { publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const a = await computeSigningKeyThumbprint(publicJwk)
        const b = await computeSigningKeyThumbprint(publicJwk)
        expect(a).toBe(b)
    })

    it('differs for different keys', async () => {
        const k1 = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k1',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const k2 = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k2',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const tp1 = await computeSigningKeyThumbprint(k1.publicJwk)
        const tp2 = await computeSigningKeyThumbprint(k2.publicJwk)
        expect(tp1).not.toBe(tp2)
    })
})

describe('signingJwkToPem', () => {
    it('round-trips through SPKI back to the same public JWK', async () => {
        const { publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const pem = await signingJwkToPem(publicJwk)
        expect(pem.startsWith('-----BEGIN PUBLIC KEY-----\n')).toBe(true)
        expect(pem.endsWith('-----END PUBLIC KEY-----\n')).toBe(true)
        expect(publicJwk.kty).toBe('EC')
        if (publicJwk.kty !== 'EC') {
            throw new Error('expected EC signing key')
        }

        // Lines between the envelope must be pure base64 wrapped at 64 chars
        const body = pem.replace('-----BEGIN PUBLIC KEY-----\n', '').replace('-----END PUBLIC KEY-----\n', '')
        const lines = body.split('\n').filter((l) => l.length > 0)
        for (let i = 0; i < lines.length - 1; i++) {
            expect(lines[i].length).toBe(64)
        }

        const der = Uint8Array.from(atob(lines.join('')), (c) => c.charCodeAt(0))
        const pub = await crypto.subtle.importKey(
            'spki',
            der as BufferSource,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        )
        const reJwk = (await crypto.subtle.exportKey('jwk', pub)) as JsonWebKey
        expect(reJwk.kty).toBe('EC')
        expect(reJwk.crv).toBe('P-256')
        expect(reJwk.x).toBe(publicJwk.x)
        expect(reJwk.y).toBe(publicJwk.y)
    })

    it('serializes an Ed25519 public JWK as PKIX PEM', async () => {
        const { publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k-ed',
            algorithm: 'Ed25519',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const pem = await signingJwkToPem(publicJwk)
        expect(pem.startsWith('-----BEGIN PUBLIC KEY-----\n')).toBe(true)
        expect(pem.endsWith('-----END PUBLIC KEY-----\n')).toBe(true)
    })
})

describe('signingJwkToSshPublicKey', () => {
    it('serializes a P-256 JWK as an OpenSSH authorized_keys line', async () => {
        const { publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const ssh = signingJwkToSshPublicKey(publicJwk, 'k-ES256')
        const parts = ssh.trim().split(' ')
        expect(parts).toHaveLength(3)
        expect(parts[0]).toBe('ecdsa-sha2-nistp256')
        expect(parts[2]).toBe('k-ES256')
        expect(publicJwk.kty).toBe('EC')
        if (publicJwk.kty !== 'EC') {
            throw new Error('expected EC signing key')
        }

        const blob = Uint8Array.from(atob(parts[1]), (c) => c.charCodeAt(0))
        let offset = 0
        const readString = () => {
            const len = (blob[offset] << 24) | (blob[offset + 1] << 16) | (blob[offset + 2] << 8) | blob[offset + 3]
            offset += 4
            const out = blob.slice(offset, offset + len)
            offset += len
            return out
        }

        expect(new TextDecoder().decode(readString())).toBe('ecdsa-sha2-nistp256')
        expect(new TextDecoder().decode(readString())).toBe('nistp256')
        const point = readString()
        expect(point[0]).toBe(0x04)
        expect(bytesToBase64Url(point.slice(1, 33))).toBe(publicJwk.x)
        expect(bytesToBase64Url(point.slice(33, 65))).toBe(publicJwk.y)
        expect(offset).toBe(blob.length)
    })

    it('serializes an Ed25519 JWK as an OpenSSH authorized_keys line', async () => {
        const { publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k-ed',
            algorithm: 'Ed25519',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const ssh = signingJwkToSshPublicKey(publicJwk, 'k-Ed25519')
        const parts = ssh.trim().split(' ')
        expect(parts).toHaveLength(3)
        expect(parts[0]).toBe('ssh-ed25519')
        expect(parts[2]).toBe('k-Ed25519')
    })
})
