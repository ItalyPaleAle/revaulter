import { describe, expect, it } from 'vitest'

import { serializeWebAuthnExtensionResults } from '$lib/webauthn'

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
})
