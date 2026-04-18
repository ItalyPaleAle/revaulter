import { describe, expect, it } from 'vitest'
import {
    buildRequestEncAAD,
    buildTransportAAD,
    computeEcP256ThumbprintHex,
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
    parseWrappedPrimaryKeyEnvelope,
    performAesGcmOperation,
    signDigestEs256,
    splitAesGcmCiphertextAndTag,
    unwrapPrimaryKey,
    wrapPrimaryKey,
} from './crypto'
import { asBuf, bytesToBase64Url } from './utils'

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
        })
        expect(wrappingKeyBytes.length).toBe(32)
        expect(stretched).toBeDefined()
        expect(stretched?.length).toBe(32)
        expect(argon2idSalt).toBeDefined()
        expect(argon2idSalt?.length).toBe(16)
    }, 30_000)

    it('is deterministic with password and fixed salt', async () => {
        const fixedSalt = new Uint8Array(16).fill(0x42)
        const r1 = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'hunter2',
            argon2idSalt: fixedSalt,
        })
        const r2 = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'hunter2',
            argon2idSalt: fixedSalt,
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
        })
        const r2 = await deriveWrappingKey({
            prfSecret: TEST_PRF_SECRET,
            userId: 'user-1',
            password: 'password-b',
            argon2idSalt: fixedSalt,
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
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: 'user-1',
            passwordRequired: true,
            argon2idSalt,
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
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: 'user-1',
            passwordRequired: true,
            argon2idSalt: salt,
        })

        const envelope = parseWrappedPrimaryKeyEnvelope(wrapped)
        expect(envelope.v).toBe(1)
        expect(envelope.passwordRequired).toBe(true)
        expect(envelope.argon2id).toBeDefined()
        expect(envelope.argon2id?.m).toBe(131072)
        expect(envelope.argon2id?.t).toBe(4)
        expect(envelope.argon2id?.p).toBe(1)
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

        const { data: ct, tag } = splitAesGcmCiphertextAndTag(encrypted)

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

describe('splitAesGcmCiphertextAndTag', () => {
    it('splits combined output into ciphertext and 16-byte tag', () => {
        const combined = hexToBytes('bdc0ea59da6f9e0d98224c288c2ba2dc96b65b6904aea70f7f8f64')
        const { data, tag } = splitAesGcmCiphertextAndTag(combined)
        expect(bytesToHex(data)).toBe('bdc0ea59da6f9e0d98224c')
        expect(bytesToHex(tag)).toBe('288c2ba2dc96b65b6904aea70f7f8f64')
        expect(tag.length).toBe(16)
    })

    it('handles minimum-length input (tag only, no ciphertext)', () => {
        const tagOnly = new Uint8Array(16).fill(0xab)
        const { data, tag } = splitAesGcmCiphertextAndTag(tagOnly)
        expect(data.length).toBe(0)
        expect(tag.length).toBe(16)
    })

    it('throws for input shorter than tag length', () => {
        expect(() => splitAesGcmCiphertextAndTag(new Uint8Array(15))).toThrow('too short')
    })

    it('supports custom tag length', () => {
        const input = new Uint8Array(20).fill(0xcc)
        const { data, tag } = splitAesGcmCiphertextAndTag(input, 8)
        expect(data.length).toBe(12)
        expect(tag.length).toBe(8)
    })
})

describe('generateTransportKeyPairJwk', () => {
    it('returns a P-256 ECDH key pair', async () => {
        const { privateKey, publicKeyJwk } = await generateTransportKeyPairJwk()
        expect(privateKey.type).toBe('private')
        expect(privateKey.algorithm).toMatchObject({ name: 'ECDH', namedCurve: 'P-256' })
        expect(publicKeyJwk.kty).toBe('EC')
        expect(publicKeyJwk.crv).toBe('P-256')
        expect(publicKeyJwk.x).toBeTruthy()
        expect(publicKeyJwk.y).toBeTruthy()
    })

    it('produces different key pairs each call', async () => {
        const kp1 = await generateTransportKeyPairJwk()
        const kp2 = await generateTransportKeyPairJwk()
        expect(kp1.publicKeyJwk.x).not.toBe(kp2.publicKeyJwk.x)
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

    it('private key is usable for ECDH', async () => {
        const { privateKey } = await deriveRequestEncKeyPair({ userId: 'u', primaryKey: TEST_PRIMARY_KEY })
        const peer = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
        const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peer.publicKey }, privateKey, 256)
        expect(shared.byteLength).toBe(32)
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
    it('encrypts and decrypts with hybrid ECDH + ML-KEM', async () => {
        // Simulate CLI: generate transport key pairs
        const ecdhKP = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
        const ecdhPubJwk = (await crypto.subtle.exportKey('jwk', ecdhKP.publicKey)) as JsonWebKey
        if (!ecdhPubJwk.x || !ecdhPubJwk.y) {
            throw new Error('Invalid ECDH key imported: missing x or y parameters')
        }

        // ML-KEM key pair for transport
        const mlkem = await import('mlkem-wasm')
        const mlkemKP = await mlkem.default.generateKey('ML-KEM-768', true, ['decapsulateBits', 'encapsulateBits'])
        const mlkemPubRaw = await mlkem.default.exportKey('raw-public', mlkemKP.publicKey)
        const { bytesToBase64Url } = await import('./utils')
        const mlkemPubB64 = bytesToBase64Url(mlkemPubRaw)

        const plaintext = new TextEncoder().encode('secret response data')
        const aad = new TextEncoder().encode('algorithm=A256GCM\noperation=encrypt\nstate=test-state\nv=1')

        // Browser encrypts the response envelope
        const envelope = await encryptTransportEnvelope(
            'test-state',
            { kty: 'EC', crv: 'P-256', x: ecdhPubJwk.x, y: ecdhPubJwk.y },
            mlkemPubB64,
            plaintext,
            aad
        )

        expect(envelope.transportAlg).toBe('ecdh-p256+mlkem768+a256gcm')
        expect(envelope.mlkemCiphertext).toBeTruthy()
        expect(envelope.nonce).toBeTruthy()
        expect(envelope.ciphertext).toBeTruthy()

        // CLI decrypts the response envelope
        const decrypted = await decryptTransportEnvelope(
            'test-state',
            ecdhKP.privateKey,
            mlkemKP.privateKey,
            envelope,
            aad
        )

        expect(new TextDecoder().decode(decrypted)).toBe('secret response data')
    })

    it('rejects envelope with wrong state', async () => {
        const ecdhKP = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
        const ecdhPubJwk = (await crypto.subtle.exportKey('jwk', ecdhKP.publicKey)) as JsonWebKey
        if (!ecdhPubJwk.x || !ecdhPubJwk.y) {
            throw new Error('Invalid ECDH key imported: missing x or y parameters')
        }

        const mlkem = await import('mlkem-wasm')
        const mlkemKP = await mlkem.default.generateKey('ML-KEM-768', true, ['decapsulateBits', 'encapsulateBits'])
        const mlkemPubRaw = await mlkem.default.exportKey('raw-public', mlkemKP.publicKey)
        const { bytesToBase64Url } = await import('./utils')
        const mlkemPubB64 = bytesToBase64Url(mlkemPubRaw)

        const plaintext = new TextEncoder().encode('data')

        const envelope = await encryptTransportEnvelope(
            'state-A',
            { kty: 'EC', crv: 'P-256', x: ecdhPubJwk.x, y: ecdhPubJwk.y },
            mlkemPubB64,
            plaintext
        )

        // Decrypt with a different state — HKDF produces a different key, so decryption fails
        await expect(
            decryptTransportEnvelope('state-B', ecdhKP.privateKey, mlkemKP.privateKey, envelope)
        ).rejects.toThrow()
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
    it('produces a 64-byte raw r||s signature that verifies against the public key', async () => {
        const { privateKey, publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const digest = new Uint8Array(32)
        crypto.getRandomValues(digest)
        const sig = await signDigestEs256(privateKey, digest)
        expect(sig).toBeInstanceOf(Uint8Array)
        expect(sig.length).toBe(64)

        const pub = await crypto.subtle.importKey(
            'jwk',
            { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y, ext: true } as JsonWebKey,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        )
        const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, asBuf(sig), asBuf(digest))
        expect(ok).toBe(true)
    })

    it('rejects digests that are not 32 bytes', async () => {
        const { privateKey } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        await expect(signDigestEs256(privateKey, new Uint8Array(31))).rejects.toThrow(/32-byte digest/)
        await expect(signDigestEs256(privateKey, new Uint8Array(33))).rejects.toThrow(/32-byte digest/)
    })
})

describe('computeEcP256ThumbprintHex', () => {
    it('matches the RFC 7638 reference example', async () => {
        // The RFC 7638 test vector is for RSA; for EC we compute SHA-256 of the canonical JSON with lex-ordered required members and compare against an independent digest
        const jwk = {
            kty: 'EC' as const,
            crv: 'P-256' as const,
            x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        }
        const canonical = `{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`
        const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
        const expected = bytesToHex(new Uint8Array(hash))

        const got = await computeEcP256ThumbprintHex(jwk)
        expect(got).toBe(expected)
        expect(got).toHaveLength(64)
    })

    it('is deterministic across calls', async () => {
        const { publicJwk } = await deriveSigningKeyPair({
            userId: 'u',
            keyLabel: 'k',
            algorithm: 'ES256',
            primaryKey: TEST_PRIMARY_KEY,
        })
        const a = await computeEcP256ThumbprintHex(publicJwk)
        const b = await computeEcP256ThumbprintHex(publicJwk)
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
        const tp1 = await computeEcP256ThumbprintHex(k1.publicJwk)
        const tp2 = await computeEcP256ThumbprintHex(k2.publicJwk)
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
