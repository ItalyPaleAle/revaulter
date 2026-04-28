import { bytesToHex, hexToBytes } from '@noble/curves/utils.js'
import { describe, expect, it } from 'vitest'

import { ecP256JwkToPublicBytes, ecP256ScalarToPublicJwk, generateTransportKeyPairJwk } from '$lib/crypto-ecdh'

const SCALAR_ONE = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001')
const PUBLIC_POINT_ONE_HEX =
    '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'
const PUBLIC_JWK_ONE = {
    kty: 'EC' as const,
    crv: 'P-256' as const,
    x: 'axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY',
    y: 'T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU',
}

describe('ecP256ScalarToPublicJwk', () => {
    it('derives the pinned P-256 public JWK for scalar value 1', () => {
        expect(ecP256ScalarToPublicJwk(SCALAR_ONE)).toEqual(PUBLIC_JWK_ONE)
    })
})

describe('ecP256JwkToPublicBytes', () => {
    it('reconstructs the uncompressed SEC1 public point from a JWK', () => {
        expect(bytesToHex(ecP256JwkToPublicBytes(PUBLIC_JWK_ONE))).toBe(PUBLIC_POINT_ONE_HEX)
    })

    it('throws when x or y are not 32 bytes', () => {
        expect(() =>
            ecP256JwkToPublicBytes({
                ...PUBLIC_JWK_ONE,
                x: 'AA',
            })
        ).toThrow(/x and y must each be 32 bytes/)
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
