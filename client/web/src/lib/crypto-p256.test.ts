import { describe, expect, it } from 'vitest'
import { importP256ScalarAsEcdhKey } from './crypto-p256'

/** Converts a hex string to Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
    }
    return bytes
}

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
        const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peer.publicKey }, privateKey, 256)
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
