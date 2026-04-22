import { describe, expect, it } from 'vitest'
import { extractCredentialPublicKeyCose } from './cose-extract'
import { bytesToBase64Url } from './utils'

// Shared cross-language fixture: the same raw COSE bytes must hash to the same base64url digest on the browser (this file) and in pkg/protocolv2/credential_pubkey_test.go
// If these constants change they must change in both places together
// cose_es256_hex is a hand-encoded ES256 (kty=EC2, alg=-7, crv=P-256) COSE key with x=32*0xAA and y=32*0xBB
const COSE_ES256_HEX =
    'a5010203262001215820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa225820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
const EXPECTED_HASH_BASE64URL = 'YLaAiaKKf8P_gxCZdaWAwIiQLkrJAoCjl0QLZZb7sYk'

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2)
    for (let i = 0; i < out.length; i++) {
        out[i] = Number.parseInt(hex.substr(i * 2, 2), 16)
    }
    return out
}

// Builds the attestationObject CBOR around a provided raw COSE key
// Layout: a3 (map 3) | "fmt"->"none" | "attStmt"->{} | "authData"->bstr(authData)
// authData = rpIdHash(32*0x11) | flags(0x45 = UP|UV|AT) | signCount(0x00000001) | aaguid(16*0x00) | credIdLen(big-endian u16) | credId | cose
function buildAttestationObject(cose: Uint8Array, credId: Uint8Array): Uint8Array {
    const authData: number[] = []
    for (let i = 0; i < 32; i++) {
        authData.push(0x11)
    }
    authData.push(0x45)
    authData.push(0x00, 0x00, 0x00, 0x01)
    for (let i = 0; i < 16; i++) {
        authData.push(0x00)
    }
    authData.push((credId.length >> 8) & 0xff, credId.length & 0xff)
    for (const b of credId) {
        authData.push(b)
    }
    for (const b of cose) {
        authData.push(b)
    }

    const out: number[] = []
    out.push(0xa3)
    out.push(0x63, 0x66, 0x6d, 0x74)
    out.push(0x64, 0x6e, 0x6f, 0x6e, 0x65)
    out.push(0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74)
    out.push(0xa0)
    out.push(0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61)
    if (authData.length < 24) {
        out.push(0x40 | authData.length)
    } else if (authData.length < 256) {
        out.push(0x58, authData.length)
    } else if (authData.length < 65536) {
        out.push(0x59, (authData.length >> 8) & 0xff, authData.length & 0xff)
    } else {
        throw new Error('authData too large for test fixture')
    }
    for (const b of authData) {
        out.push(b)
    }
    return new Uint8Array(out)
}

async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
    const buf = new ArrayBuffer(bytes.length)
    new Uint8Array(buf).set(bytes)
    const digest = await crypto.subtle.digest('SHA-256', buf)
    return bytesToBase64Url(new Uint8Array(digest))
}

describe('extractCredentialPublicKeyCose', () => {
    it('returns the exact COSE bytes that were embedded in authData (ES256)', () => {
        const cose = hexToBytes(COSE_ES256_HEX)
        const credId = new TextEncoder().encode('test-credential-id-bytes-16')
        const ao = buildAttestationObject(cose, credId)
        const extracted = extractCredentialPublicKeyCose(
            ao.buffer.slice(ao.byteOffset, ao.byteOffset + ao.byteLength) as ArrayBuffer
        )
        expect(extracted).toEqual(cose)
    })

    it('hashes the extracted COSE to the same digest the server computes', async () => {
        const cose = hexToBytes(COSE_ES256_HEX)
        const credId = new TextEncoder().encode('test-credential-id-bytes-16')
        const ao = buildAttestationObject(cose, credId)
        const extracted = extractCredentialPublicKeyCose(
            ao.buffer.slice(ao.byteOffset, ao.byteOffset + ao.byteLength) as ArrayBuffer
        )
        const hash = await sha256Base64Url(extracted)
        expect(hash).toBe(EXPECTED_HASH_BASE64URL)
    })

    it('works for short credential IDs', () => {
        const cose = hexToBytes(COSE_ES256_HEX)
        const credId = new Uint8Array([1, 2, 3, 4])
        const ao = buildAttestationObject(cose, credId)
        const extracted = extractCredentialPublicKeyCose(
            ao.buffer.slice(ao.byteOffset, ao.byteOffset + ao.byteLength) as ArrayBuffer
        )
        expect(extracted).toEqual(cose)
    })

    it('works for arbitrary non-ES256 COSE payloads without per-algorithm logic', () => {
        // A synthetic RSA-shaped COSE map: kty=3 alg=-257 with two short bstr values for -1 and -2
        // Values are not real RSA material, but the CBOR is well-formed so the extractor can slice it
        const cose = hexToBytes('a40103033901002044010203042143010001')
        const credId = new TextEncoder().encode('rsa-cred')
        const ao = buildAttestationObject(cose, credId)
        const extracted = extractCredentialPublicKeyCose(
            ao.buffer.slice(ao.byteOffset, ao.byteOffset + ao.byteLength) as ArrayBuffer
        )
        expect(extracted).toEqual(cose)
    })

    it('throws when the AT flag is missing', () => {
        const cose = hexToBytes(COSE_ES256_HEX)
        const credId = new TextEncoder().encode('cred')
        const ao = buildAttestationObject(cose, credId)
        // Locate and clear the AT flag in authData's flags byte
        // Search the CBOR bytes for the 0x45 flag, which is unique in this fixture
        for (let i = 0; i < ao.length; i++) {
            if (ao[i] === 0x45) {
                ao[i] = 0x05
                break
            }
        }
        expect(() =>
            extractCredentialPublicKeyCose(ao.buffer.slice(ao.byteOffset, ao.byteOffset + ao.byteLength) as ArrayBuffer)
        ).toThrow(/AT flag/)
    })

    it('throws when attestationObject is missing authData', () => {
        // a2 (map, 2) | "fmt" "none" | "attStmt" {}
        const bad = new Uint8Array([
            0xa2, 0x63, 0x66, 0x6d, 0x74, 0x64, 0x6e, 0x6f, 0x6e, 0x65, 0x67, 0x61, 0x74, 0x74, 0x53, 0x74, 0x6d, 0x74,
            0xa0,
        ])
        expect(() =>
            extractCredentialPublicKeyCose(
                bad.buffer.slice(bad.byteOffset, bad.byteOffset + bad.byteLength) as ArrayBuffer
            )
        ).toThrow(/authData/)
    })
})
