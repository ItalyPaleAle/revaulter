import { describe, expect, it } from 'vitest'

import { serializePublicKeyCredential, serializeWebAuthnExtensionResults } from '$lib/webauthn'

describe('serializePublicKeyCredential', () => {
    it('uses native core fields but normalizes the browser extension result', () => {
        const serialized = {
            id: 'credential',
            rawId: 'Y3JlZGVudGlhbA',
            type: 'public-key',
            clientExtensionResults: { prf: { results: { first: [251, 255, 0] } } },
        }
        const credential = {
            toJSON: () => serialized,
            getClientExtensionResults: () => ({
                prf: { results: { first: new Uint8Array([0xfb, 0xff, 0x00]).buffer } },
            }),
        } as unknown as PublicKeyCredential

        expect(serializePublicKeyCredential(credential)).toEqual({
            id: 'credential',
            rawId: 'Y3JlZGVudGlhbA',
            type: 'public-key',
            clientExtensionResults: { prf: { results: { first: '-_8A' } } },
        })
    })
})

describe('serializeWebAuthnExtensionResults', () => {
    it('encodes nested PRF ArrayBuffer outputs as base64url', () => {
        const first = new Uint8Array([0xfb, 0xff, 0x00]).buffer

        expect(
            serializeWebAuthnExtensionResults({
                prf: {
                    enabled: true,
                    results: { first },
                },
            })
        ).toEqual({
            prf: {
                enabled: true,
                results: { first: '-_8A' },
            },
        })
    })

    it('encodes typed array views without including bytes outside the view', () => {
        const source = new Uint8Array([0x00, 0xfb, 0xff, 0x00, 0x00])
        const first = source.subarray(1, 4)

        expect(serializeWebAuthnExtensionResults({ prf: { results: { first } } })).toEqual({
            prf: { results: { first: '-_8A' } },
        })
    })

    it('encodes PRF byte arrays returned by the browser as base64url', () => {
        expect(
            serializeWebAuthnExtensionResults({
                prf: { results: { first: [251, 255, 0], second: [1, 2, 3] } },
                uvm: [[1, 2, 3]],
            })
        ).toEqual({
            prf: { results: { first: '-_8A', second: 'AQID' } },
            uvm: [[1, 2, 3]],
        })
    })
})
