import { bytesToHex, hexToBytes } from '@noble/curves/utils.js'
import { describe, expect, it } from 'vitest'

import {
    buildRequestEncAAD,
    buildTransportAAD,
    isSupportedAeadAlgorithm,
    normalizeAeadAlgorithm,
    performAesGcmOperation,
    performChaCha20Poly1305Operation,
    splitAeadCiphertextAndTag,
} from '$lib/crypto-symmetric'
import { deriveOperationKeyBytes } from './crypto'

// Shared test primary key: 32 bytes of 0xAA (used as IKM for HKDF derivation tests)
const TEST_PRIMARY_KEY = new Uint8Array(32).fill(0xaa)

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
