import { describe, expect, it } from 'vitest'
import {
    buildRequestEncAAD,
    buildTransportAAD,
    deriveOperationKeyBytes,
    deriveRequestEncKeyPair,
    deriveRequestEncMlkemKeyPair,
    encryptTransportEnvelope,
    decryptTransportEnvelope,
    performAesGcmOperation,
    splitAesGcmCiphertextAndTag,
    generateTransportKeyPairJwk,
} from './crypto'

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

// Shared test PRF secret: 32 bytes of 0xAA
const TEST_PRF_SECRET = new Uint8Array(32).fill(0xaa)

describe('buildTransportAAD', () => {
    it('matches the Go CLI format', () => {
        const aad = buildTransportAAD('state-42', 'encrypt', 'aes-gcm-256')
        expect(bytesToHex(aad)).toBe(
            '616c676f726974686d3d6165732d67636d2d3235360a6f7065726174696f6e3d656e63727970740a73746174653d73746174652d34320a763d31'
        )
    })

    it('produces the expected human-readable string', () => {
        const aad = buildTransportAAD('s1', 'decrypt', 'aes-gcm-256')
        const str = new TextDecoder().decode(aad)
        expect(str).toBe('algorithm=aes-gcm-256\noperation=decrypt\nstate=s1\nv=1')
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
        const aad = buildRequestEncAAD('aes-gcm-256', 'disk-key', 'encrypt')
        expect(bytesToHex(aad)).toBe(
            '616c676f726974686d3d6165732d67636d2d3235360a6b65794c6162656c3d6469736b2d6b65790a6f7065726174696f6e3d656e63727970740a763d31'
        )
    })

    it('produces the expected human-readable string', () => {
        const aad = buildRequestEncAAD('aes-gcm-256', 'disk-key', 'decrypt')
        const str = new TextDecoder().decode(aad)
        expect(str).toBe('algorithm=aes-gcm-256\nkeyLabel=disk-key\noperation=decrypt\nv=1')
    })
})

describe('deriveOperationKeyBytes', () => {
    it('produces 32 bytes', async () => {
        const key = await deriveOperationKeyBytes({
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'aes-gcm-256',
            prfSecret: TEST_PRF_SECRET,
        })
        expect(key.length).toBe(32)
    })

    it('matches the Go HKDF output without password', async () => {
        const key = await deriveOperationKeyBytes({
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'aes-gcm-256',
            prfSecret: TEST_PRF_SECRET,
        })
        expect(bytesToHex(key)).toBe('e105e4fbd91e213395c486229e05c167733d6b550a5a33dfaf7578228f305569')
    })

    it('matches the Go HKDF output with password', async () => {
        const key = await deriveOperationKeyBytes({
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'aes-gcm-256',
            prfSecret: TEST_PRF_SECRET,
            password: 'hunter2',
        })
        expect(bytesToHex(key)).toBe('4e6fcb13afaf0098d36e719bd83ba22c656851ceff12b2cacfcc23c78dac9b8c')
    })

    it('is deterministic', async () => {
        const params = {
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'aes-gcm-256',
            prfSecret: TEST_PRF_SECRET,
        }
        const k1 = await deriveOperationKeyBytes(params)
        const k2 = await deriveOperationKeyBytes(params)
        expect(bytesToHex(k1)).toBe(bytesToHex(k2))
    })

    it('differs when password changes', async () => {
        const base = {
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'aes-gcm-256',
            prfSecret: TEST_PRF_SECRET,
        }
        const k1 = await deriveOperationKeyBytes(base)
        const k2 = await deriveOperationKeyBytes({ ...base, password: 'p' })
        expect(bytesToHex(k1)).not.toBe(bytesToHex(k2))
    })

    it('differs when userId changes', async () => {
        const base = {
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'aes-gcm-256',
            prfSecret: TEST_PRF_SECRET,
        }
        const k1 = await deriveOperationKeyBytes(base)
        const k2 = await deriveOperationKeyBytes({ ...base, userId: 'user-2' })
        expect(bytesToHex(k1)).not.toBe(bytesToHex(k2))
    })

    it('differs when keyLabel changes', async () => {
        const base = {
            userId: 'user-1',
            keyLabel: 'disk-key',
            algorithm: 'aes-gcm-256',
            prfSecret: TEST_PRF_SECRET,
        }
        const k1 = await deriveOperationKeyBytes(base)
        const k2 = await deriveOperationKeyBytes({ ...base, keyLabel: 'other-key' })
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
    it('is deterministic without password', async () => {
        const params = { userId: 'user-1', prfSecret: TEST_PRF_SECRET }
        const kp1 = await deriveRequestEncKeyPair(params)
        const kp2 = await deriveRequestEncKeyPair(params)
        expect(kp1.publicKeyJwk.x).toBe(kp2.publicKeyJwk.x)
        expect(kp1.publicKeyJwk.y).toBe(kp2.publicKeyJwk.y)
    })

    it('is deterministic with password', async () => {
        const params = { userId: 'user-1', prfSecret: TEST_PRF_SECRET, password: 'hunter2' }
        const kp1 = await deriveRequestEncKeyPair(params)
        const kp2 = await deriveRequestEncKeyPair(params)
        expect(kp1.publicKeyJwk.x).toBe(kp2.publicKeyJwk.x)
        expect(kp1.publicKeyJwk.y).toBe(kp2.publicKeyJwk.y)
    })

    it('produces different keys with vs without password', async () => {
        const kp1 = await deriveRequestEncKeyPair({ userId: 'user-1', prfSecret: TEST_PRF_SECRET })
        const kp2 = await deriveRequestEncKeyPair({ userId: 'user-1', prfSecret: TEST_PRF_SECRET, password: 'p' })
        expect(kp1.publicKeyJwk.x).not.toBe(kp2.publicKeyJwk.x)
    })

    it('produces different keys for different users', async () => {
        const kp1 = await deriveRequestEncKeyPair({ userId: 'user-1', prfSecret: TEST_PRF_SECRET })
        const kp2 = await deriveRequestEncKeyPair({ userId: 'user-2', prfSecret: TEST_PRF_SECRET })
        expect(kp1.publicKeyJwk.x).not.toBe(kp2.publicKeyJwk.x)
    })

    it('returns a valid P-256 JWK', async () => {
        const { publicKeyJwk } = await deriveRequestEncKeyPair({ userId: 'u', prfSecret: TEST_PRF_SECRET })
        expect(publicKeyJwk.kty).toBe('EC')
        expect(publicKeyJwk.crv).toBe('P-256')
        expect(publicKeyJwk.x.length).toBeGreaterThan(0)
        expect(publicKeyJwk.y.length).toBeGreaterThan(0)
    })

    it('private key is usable for ECDH', async () => {
        const { privateKey } = await deriveRequestEncKeyPair({ userId: 'u', prfSecret: TEST_PRF_SECRET })
        const peer = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
        const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peer.publicKey }, privateKey, 256)
        expect(shared.byteLength).toBe(32)
    })
})

describe('deriveRequestEncMlkemKeyPair', () => {
    it('is deterministic', async () => {
        const params = { userId: 'user-1', prfSecret: TEST_PRF_SECRET }
        const kp1 = await deriveRequestEncMlkemKeyPair(params)
        const kp2 = await deriveRequestEncMlkemKeyPair(params)
        expect(kp1.encapsulationKeyB64).toBe(kp2.encapsulationKeyB64)
    })

    it('produces different keys with vs without password', async () => {
        const kp1 = await deriveRequestEncMlkemKeyPair({ userId: 'user-1', prfSecret: TEST_PRF_SECRET })
        const kp2 = await deriveRequestEncMlkemKeyPair({
            userId: 'user-1',
            prfSecret: TEST_PRF_SECRET,
            password: 'p',
        })
        expect(kp1.encapsulationKeyB64).not.toBe(kp2.encapsulationKeyB64)
    })

    it('produces different keys for different users', async () => {
        const kp1 = await deriveRequestEncMlkemKeyPair({ userId: 'user-1', prfSecret: TEST_PRF_SECRET })
        const kp2 = await deriveRequestEncMlkemKeyPair({ userId: 'user-2', prfSecret: TEST_PRF_SECRET })
        expect(kp1.encapsulationKeyB64).not.toBe(kp2.encapsulationKeyB64)
    })

    it('encapsulation key is 1184 bytes (ML-KEM-768)', async () => {
        const { encapsulationKeyB64 } = await deriveRequestEncMlkemKeyPair({
            userId: 'u',
            prfSecret: TEST_PRF_SECRET,
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

        // ML-KEM key pair for transport
        const mlkem = await import('mlkem-wasm')
        const mlkemKP = await mlkem.default.generateKey('ML-KEM-768', true, ['decapsulateBits', 'encapsulateBits'])
        const mlkemPubRaw = await mlkem.default.exportKey('raw-public', mlkemKP.publicKey)
        const { bytesToBase64Url } = await import('./utils')
        const mlkemPubB64 = bytesToBase64Url(mlkemPubRaw)

        const plaintext = new TextEncoder().encode('secret response data')
        const aad = new TextEncoder().encode('algorithm=aes-gcm-256\noperation=encrypt\nstate=test-state\nv=1')

        // Browser encrypts the response envelope
        const envelope = await encryptTransportEnvelope(
            'test-state',
            { kty: 'EC', crv: 'P-256', x: ecdhPubJwk.x!, y: ecdhPubJwk.y! },
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

        const mlkem = await import('mlkem-wasm')
        const mlkemKP = await mlkem.default.generateKey('ML-KEM-768', true, ['decapsulateBits', 'encapsulateBits'])
        const mlkemPubRaw = await mlkem.default.exportKey('raw-public', mlkemKP.publicKey)
        const { bytesToBase64Url } = await import('./utils')
        const mlkemPubB64 = bytesToBase64Url(mlkemPubRaw)

        const plaintext = new TextEncoder().encode('data')

        const envelope = await encryptTransportEnvelope(
            'state-A',
            { kty: 'EC', crv: 'P-256', x: ecdhPubJwk.x!, y: ecdhPubJwk.y! },
            mlkemPubB64,
            plaintext
        )

        // Decrypt with a different state — HKDF produces a different key, so decryption fails
        await expect(
            decryptTransportEnvelope('state-B', ecdhKP.privateKey, mlkemKP.privateKey, envelope)
        ).rejects.toThrow()
    })
})
