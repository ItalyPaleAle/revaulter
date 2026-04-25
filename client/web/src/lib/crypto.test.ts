import { argon2id } from '@awasm/noble'
import { p256 } from '@noble/curves/nist.js'
import { describe, expect, it } from 'vitest'
import {
    buildRequestEncAAD,
    buildTransportAAD,
    computeEcP256Thumbprint,
    decryptTransportEnvelope,
    deriveOperationKeyBytes,
    deriveRequestEncKeyPair,
    deriveRequestEncMlkemKeyPair,
    deriveSigningKeyPair,
    deriveWrappingKey,
    ecP256JwkToPem,
    encryptTransportEnvelope,
    generatePrimaryKey,
    generateTransportKeyPairJwk,
    isSupportedAeadAlgorithm,
    normalizeAeadAlgorithm,
    parseWrappedPrimaryKeyEnvelope,
    performAesGcmOperation,
    performChaCha20Poly1305Operation,
    signDigestEs256,
    splitAeadCiphertextAndTag,
    unwrapPrimaryKey,
    wrapPrimaryKey,
} from './crypto'
import { base64UrlToBytes, bytesToBase64Url } from './utils'

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
    }
    return bytes
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
}

// Shared test primary key: 32 bytes of 0xAA (used as IKM for HKDF derivation tests)
const TEST_PRIMARY_KEY = new Uint8Array(32).fill(0xaa)

// Shared test PRF secret: 32 bytes of 0xBB (used for wrapping key derivation tests)
const TEST_PRF_SECRET = new Uint8Array(32).fill(0xbb)

// Low-cost Argon2id parameters used only for tests to keep derivation fast
const TEST_ARGON2ID_COST = { m: 8, t: 1, p: 1 }

describe('buildTransportAAD', () => {
    it('matches the Go CLI format', () => {
        const aad = buildTransportAAD('state-42', 'encrypt', 'A256GCM')
        expect(bytesToHex(aad)).toBe(
            '616c676f726974686d3d4132353647434d0a6f7065726174696f6e3d656e63727970740a73746174653d73746174652d34320a763d31'
        )
    })

    it('produces the expected human-readable string', () => {
        const aad = buildTransportAAD('s1', 'decrypt', 'A256GCM')
        const str = new TextDecoder().decode(aad)
        expect(str).toBe('algorithm=A256GCM\noperation=decrypt\nstate=s1\nv=1')
    })

    it('sorts fields alphabetically', () => {
        const str = new TextDecoder().decode(buildTransportAAD('x', 'encrypt', 'a'))
        const lines = str.split('\n')
        expect(lines[0]).toMatch(/^algorithm=/)
        expect(lines[1]).toMatch(/^operation=/)
        expect(lines[2]).toMatch(/^state=/)
        expect(lines[3]).toMatch(/^v=/)
    })

    it('binds the algorithm name verbatim — different name forms produce different AAD', () => {
        // The algorithm string flows into AAD verbatim, so the CLI and browser must use matching forms even though both are accepted for dispatch
        const a = buildTransportAAD('s', 'encrypt', 'A256GCM')
        const b = buildTransportAAD('s', 'encrypt', 'aes-256-gcm')
        expect(bytesToHex(a)).not.toBe(bytesToHex(b))
    })
})

describe('buildRequestEncAAD', () => {
    it('matches the Go CLI format', () => {
        const aad = buildRequestEncAAD('A256GCM', 'disk-key', 'encrypt')
        expect(bytesToHex(aad)).toBe(
            '616c676f726974686d3d4132353647434d0a6b65794c6162656c3d6469736b2d6b65790a6f7065726174696f6e3d656e63727970740a763d31'
        )
    })

    it('produces the expected human-readable string', () => {
        const aad = buildRequestEncAAD('A256GCM', 'disk-key', 'decrypt')
        const str = new TextDecoder().decode(aad)
        expect(str).toBe('algorithm=A256GCM\nkeyLabel=disk-key\noperation=decrypt\nv=1')
    })
})

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

describe('performAesGcmOperation', () => {
    // Test vector from Go: key=e105..., nonce=000102..., plain="hello world", aad="aad-test"
    const TV_KEY = hexToBytes('e105e4fbd91e213395c486229e05c167733d6b550a5a33dfaf7578228f305569')
    const TV_NONCE = hexToBytes('000102030405060708090a0b')
    const TV_PLAIN = new TextEncoder().encode('hello world')
    const TV_AAD = new TextEncoder().encode('aad-test')
    const TV_CT = hexToBytes('bdc0ea59da6f9e0d98224c')
    const TV_TAG = hexToBytes('288c2ba2dc96b65b6904aea70f7f8f64')
    const TV_CT_WITH_TAG = hexToBytes('bdc0ea59da6f9e0d98224c288c2ba2dc96b65b6904aea70f7f8f64')

    it('encrypts to match Go AES-GCM output', async () => {
        const result = await performAesGcmOperation({
            mode: 'encrypt',
            keyBytes: TV_KEY,
            value: TV_PLAIN,
            nonce: TV_NONCE,
            aad: TV_AAD,
        })
        // WebCrypto returns ciphertext+tag concatenated
        expect(bytesToHex(result)).toBe(bytesToHex(TV_CT_WITH_TAG))
    })

    it('decrypts Go-produced ciphertext with separate tag', async () => {
        const result = await performAesGcmOperation({
            mode: 'decrypt',
            keyBytes: TV_KEY,
            value: TV_CT,
            nonce: TV_NONCE,
            aad: TV_AAD,
            tag: TV_TAG,
        })
        expect(new TextDecoder().decode(result)).toBe('hello world')
    })

    it('decrypts Go-produced ciphertext with combined tag', async () => {
        const result = await performAesGcmOperation({
            mode: 'decrypt',
            keyBytes: TV_KEY,
            value: TV_CT_WITH_TAG,
            nonce: TV_NONCE,
            aad: TV_AAD,
        })
        expect(new TextDecoder().decode(result)).toBe('hello world')
    })

    it('encrypt then decrypt round-trips with explicit nonce', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32))
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const plaintext = new TextEncoder().encode('round trip test')
        const aad = new TextEncoder().encode('context')

        const encrypted = await performAesGcmOperation({
            mode: 'encrypt',
            keyBytes: key,
            value: plaintext,
            nonce,
            aad,
        })

        const { data: ct, tag } = splitAeadCiphertextAndTag(encrypted)

        const decrypted = await performAesGcmOperation({
            mode: 'decrypt',
            keyBytes: key,
            value: ct,
            nonce,
            aad,
            tag,
        })
        expect(new TextDecoder().decode(decrypted)).toBe('round trip test')
    })

    it('rejects tampered ciphertext', async () => {
        const tampered = new Uint8Array(TV_CT_WITH_TAG)
        tampered[0] ^= 0xff

        await expect(
            performAesGcmOperation({
                mode: 'decrypt',
                keyBytes: TV_KEY,
                value: tampered,
                nonce: TV_NONCE,
                aad: TV_AAD,
            })
        ).rejects.toThrow('Decryption failed')
    })

    it('rejects wrong AAD', async () => {
        await expect(
            performAesGcmOperation({
                mode: 'decrypt',
                keyBytes: TV_KEY,
                value: TV_CT_WITH_TAG,
                nonce: TV_NONCE,
                aad: new TextEncoder().encode('wrong-aad'),
            })
        ).rejects.toThrow('Decryption failed')
    })

    it('generates a random nonce when none is provided for encrypt', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32))
        const plain = new TextEncoder().encode('test')

        const r1 = await performAesGcmOperation({ mode: 'encrypt', keyBytes: key, value: plain })
        const r2 = await performAesGcmOperation({ mode: 'encrypt', keyBytes: key, value: plain })
        // Different random nonces should produce different ciphertexts
        expect(bytesToHex(r1)).not.toBe(bytesToHex(r2))
    })
})

describe('performChaCha20Poly1305Operation', () => {
    it('round-trips with explicit nonce and AAD', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32))
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const plaintext = new TextEncoder().encode('chacha round trip')
        const aad = new TextEncoder().encode('context')

        const encrypted = await performChaCha20Poly1305Operation({
            mode: 'encrypt',
            keyBytes: key,
            value: plaintext,
            nonce,
            aad,
        })

        // The combined buffer is ciphertext||tag with a 16-byte Poly1305 tag
        expect(encrypted.length).toBe(plaintext.length + 16)
        const { data, tag } = splitAeadCiphertextAndTag(encrypted)
        expect(tag.length).toBe(16)

        const decrypted = await performChaCha20Poly1305Operation({
            mode: 'decrypt',
            keyBytes: key,
            value: data,
            nonce,
            aad,
            tag,
        })
        expect(new TextDecoder().decode(decrypted)).toBe('chacha round trip')
    })

    it('round-trips without AAD', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32))
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const plaintext = new TextEncoder().encode('no aad')

        const encrypted = await performChaCha20Poly1305Operation({
            mode: 'encrypt',
            keyBytes: key,
            value: plaintext,
            nonce,
        })

        const decrypted = await performChaCha20Poly1305Operation({
            mode: 'decrypt',
            keyBytes: key,
            value: encrypted,
            nonce,
        })
        expect(new TextDecoder().decode(decrypted)).toBe('no aad')
    })

    it('decrypt accepts the combined ciphertext+tag form', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32))
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const plaintext = new TextEncoder().encode('combined form')
        const aad = new TextEncoder().encode('a')

        const combined = await performChaCha20Poly1305Operation({
            mode: 'encrypt',
            keyBytes: key,
            value: plaintext,
            nonce,
            aad,
        })

        const decrypted = await performChaCha20Poly1305Operation({
            mode: 'decrypt',
            keyBytes: key,
            value: combined,
            nonce,
            aad,
        })
        expect(new TextDecoder().decode(decrypted)).toBe('combined form')
    })

    it('rejects ciphertext decrypted under a different AAD', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32))
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const plaintext = new TextEncoder().encode('aad bound')

        const encrypted = await performChaCha20Poly1305Operation({
            mode: 'encrypt',
            keyBytes: key,
            value: plaintext,
            nonce,
            aad: new TextEncoder().encode('expected'),
        })

        await expect(
            performChaCha20Poly1305Operation({
                mode: 'decrypt',
                keyBytes: key,
                value: encrypted,
                nonce,
                aad: new TextEncoder().encode('attacker'),
            })
        ).rejects.toThrow('Decryption failed')
    })

    it('rejects tampered ciphertext', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32))
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const plaintext = new TextEncoder().encode('integrity test')

        const encrypted = await performChaCha20Poly1305Operation({
            mode: 'encrypt',
            keyBytes: key,
            value: plaintext,
            nonce,
        })

        const tampered = new Uint8Array(encrypted)
        tampered[0] ^= 0xff

        await expect(
            performChaCha20Poly1305Operation({
                mode: 'decrypt',
                keyBytes: key,
                value: tampered,
                nonce,
            })
        ).rejects.toThrow('Decryption failed')
    })

    it('generates a random 12-byte nonce when none is provided for encrypt', async () => {
        const key = crypto.getRandomValues(new Uint8Array(32))
        const plain = new TextEncoder().encode('test')

        const r1 = await performChaCha20Poly1305Operation({ mode: 'encrypt', keyBytes: key, value: plain })
        const r2 = await performChaCha20Poly1305Operation({ mode: 'encrypt', keyBytes: key, value: plain })
        expect(bytesToHex(r1)).not.toBe(bytesToHex(r2))
    })
})

describe('end-to-end operation key + AEAD round-trip per algorithm name', () => {
    // Each name form derives a distinct operation key (the algorithm string is part of HKDF info), so encrypt and decrypt must be paired with the SAME name
    const cases = [
        { algorithm: 'A256GCM', primitive: 'aes-256-gcm' as const },
        { algorithm: 'aes-256-gcm', primitive: 'aes-256-gcm' as const },
        { algorithm: 'C20P', primitive: 'chacha20-poly1305' as const },
        { algorithm: 'chacha20-poly1305', primitive: 'chacha20-poly1305' as const },
    ]

    for (const { algorithm, primitive } of cases) {
        it(`round-trips with algorithm=${algorithm} (${primitive})`, async () => {
            const operationKey = await deriveOperationKeyBytes({
                userId: 'user-1',
                keyLabel: 'k',
                algorithm,
                primaryKey: TEST_PRIMARY_KEY,
            })

            const nonce = crypto.getRandomValues(new Uint8Array(12))
            const plaintext = new TextEncoder().encode(`hello ${algorithm}`)
            const aad = new TextEncoder().encode('aad')

            const encOp = primitive === 'aes-256-gcm' ? performAesGcmOperation : performChaCha20Poly1305Operation
            const combined = await encOp({ mode: 'encrypt', keyBytes: operationKey, value: plaintext, nonce, aad })

            const decOp = primitive === 'aes-256-gcm' ? performAesGcmOperation : performChaCha20Poly1305Operation
            const decrypted = await decOp({ mode: 'decrypt', keyBytes: operationKey, value: combined, nonce, aad })
            expect(new TextDecoder().decode(decrypted)).toBe(`hello ${algorithm}`)
        })
    }

    it('different accepted name forms produce the same operation key (HKDF canonicalizes the algorithm)', async () => {
        const forms = ['A256GCM', 'aes-256-gcm', 'AES-256-GCM', 'aes256gcm']
        const keys = await Promise.all(
            forms.map((algorithm) =>
                deriveOperationKeyBytes({
                    userId: 'u',
                    keyLabel: 'k',
                    algorithm,
                    primaryKey: TEST_PRIMARY_KEY,
                })
            )
        )
        const ref = bytesToHex(keys[0])
        for (const key of keys) {
            expect(bytesToHex(key)).toBe(ref)
        }
    })

    it('encrypt with one accepted algorithm form decrypts under any other accepted form', async () => {
        // Encrypt under A256GCM, decrypt under aes-256-gcm (and vice versa) — both must succeed because the operation key derivation canonicalizes the algorithm name
        const userId = 'u'
        const keyLabel = 'k'
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const plaintext = new TextEncoder().encode('cross-form round trip')
        const aad = new TextEncoder().encode('aad')

        const encKey = await deriveOperationKeyBytes({
            userId,
            keyLabel,
            algorithm: 'A256GCM',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const combined = await performAesGcmOperation({
            mode: 'encrypt',
            keyBytes: encKey,
            value: plaintext,
            nonce,
            aad,
        })

        const decKey = await deriveOperationKeyBytes({
            userId,
            keyLabel,
            algorithm: 'aes-256-gcm',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const decrypted = await performAesGcmOperation({
            mode: 'decrypt',
            keyBytes: decKey,
            value: combined,
            nonce,
            aad,
        })
        expect(new TextDecoder().decode(decrypted)).toBe('cross-form round trip')
    })

    it('unknown algorithm strings still flow through HKDF verbatim (graceful fallback)', async () => {
        const k1 = await deriveOperationKeyBytes({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'unknown-A',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const k2 = await deriveOperationKeyBytes({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'unknown-B',
            primaryKey: TEST_PRIMARY_KEY,
        })
        expect(bytesToHex(k1)).not.toBe(bytesToHex(k2))
    })
})

describe('algorithm name handling', () => {
    it('normalizeAeadAlgorithm accepts all name forms (case-insensitive) and returns canonical long-form names', () => {
        expect(normalizeAeadAlgorithm('A256GCM')).toBe('aes-256-gcm')
        expect(normalizeAeadAlgorithm('a256gcm')).toBe('aes-256-gcm')
        expect(normalizeAeadAlgorithm('aes-256-gcm')).toBe('aes-256-gcm')
        expect(normalizeAeadAlgorithm('AES-256-GCM')).toBe('aes-256-gcm')
        expect(normalizeAeadAlgorithm('aes256gcm')).toBe('aes-256-gcm')

        expect(normalizeAeadAlgorithm('C20P')).toBe('chacha20-poly1305')
        expect(normalizeAeadAlgorithm('c20p')).toBe('chacha20-poly1305')
        expect(normalizeAeadAlgorithm('chacha20-poly1305')).toBe('chacha20-poly1305')
        expect(normalizeAeadAlgorithm('ChaCha20-Poly1305')).toBe('chacha20-poly1305')
        expect(normalizeAeadAlgorithm('chacha20poly1305')).toBe('chacha20-poly1305')
    })

    it('normalizeAeadAlgorithm returns null for unknown algorithms', () => {
        expect(normalizeAeadAlgorithm('rsa-oaep')).toBe(null)
        expect(normalizeAeadAlgorithm('ES256')).toBe(null)
        expect(normalizeAeadAlgorithm('')).toBe(null)
    })

    it('isSupportedAeadAlgorithm matches normalizeAeadAlgorithm', () => {
        expect(isSupportedAeadAlgorithm('A256GCM')).toBe(true)
        expect(isSupportedAeadAlgorithm('aes-256-gcm')).toBe(true)
        expect(isSupportedAeadAlgorithm('C20P')).toBe(true)
        expect(isSupportedAeadAlgorithm('chacha20-poly1305')).toBe(true)
        expect(isSupportedAeadAlgorithm('rsa-oaep')).toBe(false)
    })
})

describe('splitAeadCiphertextAndTag', () => {
    it('splits combined output into ciphertext and 16-byte tag', () => {
        const combined = hexToBytes('bdc0ea59da6f9e0d98224c288c2ba2dc96b65b6904aea70f7f8f64')
        const { data, tag } = splitAeadCiphertextAndTag(combined)
        expect(bytesToHex(data)).toBe('bdc0ea59da6f9e0d98224c')
        expect(bytesToHex(tag)).toBe('288c2ba2dc96b65b6904aea70f7f8f64')
        expect(tag.length).toBe(16)
    })

    it('handles minimum-length input (tag only, no ciphertext)', () => {
        const tagOnly = new Uint8Array(16).fill(0xab)
        const { data, tag } = splitAeadCiphertextAndTag(tagOnly)
        expect(data.length).toBe(0)
        expect(tag.length).toBe(16)
    })

    it('throws for input shorter than tag length', () => {
        expect(() => splitAeadCiphertextAndTag(new Uint8Array(15))).toThrow('too short')
    })

    it('supports custom tag length', () => {
        const input = new Uint8Array(20).fill(0xcc)
        const { data, tag } = splitAeadCiphertextAndTag(input, 8)
        expect(data.length).toBe(12)
        expect(tag.length).toBe(8)
    })
})

describe('generateTransportKeyPairJwk', () => {
    it('returns a P-256 ECDH key pair as raw scalar bytes plus public JWK', () => {
        const { scalar, publicKeyJwk } = generateTransportKeyPairJwk()
        expect(scalar).toBeInstanceOf(Uint8Array)
        expect(scalar.length).toBe(32)
        expect(publicKeyJwk.kty).toBe('EC')
        expect(publicKeyJwk.crv).toBe('P-256')
        expect(publicKeyJwk.x).toBeTruthy()
        expect(publicKeyJwk.y).toBeTruthy()
    })

    it('produces different key pairs each call', () => {
        const kp1 = generateTransportKeyPairJwk()
        const kp2 = generateTransportKeyPairJwk()
        expect(kp1.publicKeyJwk.x).not.toBe(kp2.publicKeyJwk.x)
        expect(bytesToHex(kp1.scalar)).not.toBe(bytesToHex(kp2.scalar))
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
        const a = await deriveSigningKeyPair({
            userId: 'user-1',
            keyLabel: 'payments',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const b = await deriveSigningKeyPair({
            userId: 'user-1',
            keyLabel: 'payments',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        expect(a.publicJwk).toStrictEqual(b.publicJwk)
    })

    it('is domain-separated by userId, keyLabel, and primary key', async () => {
        const base = await deriveSigningKeyPair({
            userId: 'user-1',
            keyLabel: 'payments',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const diffUser = await deriveSigningKeyPair({
            userId: 'user-2',
            keyLabel: 'payments',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const diffLabel = await deriveSigningKeyPair({
            userId: 'user-1',
            keyLabel: 'refunds',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const diffKey = await deriveSigningKeyPair({
            userId: 'user-1',
            keyLabel: 'payments',
            algorithm: 'ES256',
            primaryKey: new Uint8Array(32).fill(0xcc),
        })
        expect(diffUser.publicJwk).not.toStrictEqual(base.publicJwk)
        expect(diffLabel.publicJwk).not.toStrictEqual(base.publicJwk)
        expect(diffKey.publicJwk).not.toStrictEqual(base.publicJwk)
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

    it('returns a P-256 public JWK without the private scalar', async () => {
        const { publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        expect(publicJwk.kty).toBe('EC')
        expect(publicJwk.crv).toBe('P-256')
        expect(publicJwk.x).toBeTruthy()
        expect(publicJwk.y).toBeTruthy()
        expect((publicJwk as Record<string, unknown>).d).toBeUndefined()
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
        const { scalar, publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const digest = new Uint8Array(32)
        crypto.getRandomValues(digest)
        const sig = await signDigestEs256(scalar, digest)
        expect(sig).toBeInstanceOf(Uint8Array)
        expect(sig.length).toBe(64)

        // Verify with prehash:false because the browser now signs the digest directly without re-hashing
        const pubBytes = publicKeyBytesFromJwk(publicJwk)
        const ok = p256.verify(sig, digest, pubBytes, { prehash: false, format: 'compact' })
        expect(ok).toBe(true)
    })

    it('does not verify when the digest is treated as a message that should be hashed (regression check for the prior bug)', async () => {
        const { scalar, publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const digest = new Uint8Array(32)
        crypto.getRandomValues(digest)
        const sig = await signDigestEs256(scalar, digest)
        const pubBytes = publicKeyBytesFromJwk(publicJwk)

        // Under the old (buggy) WebCrypto path the browser signed SHA-256(digest)
        // With the fix, signing over the digest directly must NOT verify against SHA-256(digest)
        const rehashed = new Uint8Array(await crypto.subtle.digest('SHA-256', digest as BufferSource))
        const okRehashed = p256.verify(sig, rehashed, pubBytes, { prehash: false, format: 'compact' })
        expect(okRehashed).toBe(false)
    })

    it('rejects digests that are not 32 bytes', async () => {
        const { scalar } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        await expect(signDigestEs256(scalar, new Uint8Array(31))).rejects.toThrow(/32-byte digest/)
        await expect(signDigestEs256(scalar, new Uint8Array(33))).rejects.toThrow(/32-byte digest/)
    })
})

describe('computeEcP256Thumbprint', () => {
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

        const got = await computeEcP256Thumbprint(jwk)
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
        const a = await computeEcP256Thumbprint(publicJwk)
        const b = await computeEcP256Thumbprint(publicJwk)
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
        const tp1 = await computeEcP256Thumbprint(k1.publicJwk)
        const tp2 = await computeEcP256Thumbprint(k2.publicJwk)
        expect(tp1).not.toBe(tp2)
    })
})

describe('ecP256JwkToPem', () => {
    it('round-trips through SPKI back to the same public JWK', async () => {
        const { publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const pem = await ecP256JwkToPem(publicJwk)
        expect(pem.startsWith('-----BEGIN PUBLIC KEY-----\n')).toBe(true)
        expect(pem.endsWith('-----END PUBLIC KEY-----\n')).toBe(true)

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
})
