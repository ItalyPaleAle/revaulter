import { describe, expect, it } from 'vitest'
import { hashToP256Scalar, importP256ScalarAsEcdhKey } from './crypto'

/** Converts a hex string to Uint8Array. */
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

describe('hashToP256Scalar', () => {
    it('reduces 48 bytes of 0xFF correctly', () => {
        const input = new Uint8Array(48).fill(0xff)
        const result = hashToP256Scalar(input)
        expect(bytesToHex(result)).toBe('431905529c0166ce652e96b7ccca0a9a679b73e29ad16947f01cf012fc632550')
    })

    it('reduces 0x01 followed by 47 zero bytes', () => {
        const input = new Uint8Array(48)
        input[0] = 1
        const result = hashToP256Scalar(input)
        expect(bytesToHex(result)).toBe('ff431904539c0167cd652e96b7ccca0a5791af26dc0b584fb6b62de84c632551')
    })

    it('always produces a 32-byte output', () => {
        const input = new Uint8Array(48) // all zeros
        const result = hashToP256Scalar(input)
        expect(result.length).toBe(32)
    })

    it('never produces the zero scalar', () => {
        // Input of all zeros: (0 mod (n-1)) + 1 = 1
        const input = new Uint8Array(48)
        const result = hashToP256Scalar(input)
        const isZero = result.every((b) => b === 0)
        expect(isZero).toBe(false)
        // Should be scalar = 1
        expect(result[31]).toBe(1)
        expect(result.slice(0, 31).every((b) => b === 0)).toBe(true)
    })
})

describe('importP256ScalarAsEcdhKey', () => {
    it('imports scalar=1 and produces the P-256 generator point', async () => {
        const scalar = new Uint8Array(32)
        scalar[31] = 1

        const key = await importP256ScalarAsEcdhKey(scalar)
        expect(key.type).toBe('private')

        // Export and verify the public key matches the well-known P-256 generator G
        const jwk = await crypto.subtle.exportKey('jwk', key)
        expect(jwk.x).toBe('axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY')
        expect(jwk.y).toBe('T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU')
    })

    it('imports an arbitrary scalar and produces the correct public key', async () => {
        // Test vector generated with Go crypto/ecdh
        const scalar = hexToBytes('20ca469e43d3ef2cb2d971cc4c756551d8aac040a4d14d69b221fc669df77809')

        const key = await importP256ScalarAsEcdhKey(scalar)
        const jwk = await crypto.subtle.exportKey('jwk', key)
        expect(jwk.x).toBe('PnEdQGPjXPREN-FRYNYYBKO5KoEuIrcwqyUB3V107Qg')
        expect(jwk.y).toBe('z1pr1btDR-aWA8XV60AFv96NKt7UiJIa4ILH5WzszUM')
    })

    it('produces a key usable for ECDH deriveBits', async () => {
        const scalar = new Uint8Array(32)
        scalar[31] = 42

        const privateKey = await importP256ScalarAsEcdhKey(scalar)

        // Generate an ephemeral peer key and perform ECDH
        const peer = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
        const shared = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: peer.publicKey },
            privateKey,
            256
        )
        expect(shared.byteLength).toBe(32)
    })

    it('is deterministic — same scalar produces same key', async () => {
        const scalar = hexToBytes('20ca469e43d3ef2cb2d971cc4c756551d8aac040a4d14d69b221fc669df77809')

        const key1 = await importP256ScalarAsEcdhKey(scalar)
        const key2 = await importP256ScalarAsEcdhKey(scalar)

        const jwk1 = await crypto.subtle.exportKey('jwk', key1)
        const jwk2 = await crypto.subtle.exportKey('jwk', key2)
        expect(jwk1.x).toBe(jwk2.x)
        expect(jwk1.y).toBe(jwk2.y)
        expect(jwk1.d).toBe(jwk2.d)
    })

    it('rejects a scalar that is not 32 bytes', async () => {
        await expect(importP256ScalarAsEcdhKey(new Uint8Array(16))).rejects.toThrow('must be exactly 32 bytes')
        await expect(importP256ScalarAsEcdhKey(new Uint8Array(0))).rejects.toThrow('must be exactly 32 bytes')
        await expect(importP256ScalarAsEcdhKey(new Uint8Array(33))).rejects.toThrow('must be exactly 32 bytes')
    })
})
