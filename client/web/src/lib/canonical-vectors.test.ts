import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'
import { computeSigningKeyThumbprint } from '$lib/crypto'
import {
    anchorEs384JwkToString,
    attestationPayloadCanonicalBody,
    canonicalAttestationMessage,
    canonicalPubkeyBundleMessage,
    canonicalSigningKeyPublicationMessage,
    pubkeyBundlePayloadCanonicalBody,
    signingKeyPublicationPayloadCanonicalBody,
} from '$lib/crypto-anchor'
import { buildRequestEncAAD, buildTransportAAD } from '$lib/crypto-symmetric'
import type { V2Operation, V2SigningJwk } from '$lib/v2-types'

/**
 * Shared Go/TypeScript test vectors for every byte string both implementations must construct identically.
 *
 * The Go suites in pkg/protocolv2/canonical_vectors_test.go and cmd/cli/cmd/canonical_vectors_test.go read the same
 * file, so a change to either implementation that is not mirrored in the other fails both test suites instead of
 * silently producing signatures or AEAD tags the other side cannot verify.
 *
 * If a value here changes the wire format changed, and every
 * already-issued signature over the old bytes stops verifying.
 */
const vectorsPath = join(
    dirname(fileURLToPath(import.meta.url)),
    '../../../../testdata/protocol-canonical-vectors.json'
)
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'))

const decoder = new TextDecoder()

describe('shared canonical vectors', () => {
    it('loads the shared vectors file', () => {
        expect(vectors.attestation.length).toBeGreaterThan(0)
    })

    describe('es384JwkCanonicalBody', () => {
        for (const tc of vectors.es384JwkCanonicalBody) {
            it(tc.name, () => {
                expect(anchorEs384JwkToString(tc.jwk)).toBe(tc.canonicalBody)
            })
        }
    })

    describe('attestation', () => {
        for (const tc of vectors.attestation) {
            it(tc.name, () => {
                const body = attestationPayloadCanonicalBody(tc.payload)
                expect(body).toBe(tc.canonicalBody)
                expect(decoder.decode(canonicalAttestationMessage(body))).toBe(tc.message)
            })
        }
    })

    describe('pubkeyBundleV2', () => {
        for (const tc of vectors.pubkeyBundleV2) {
            it(tc.name, () => {
                const body = pubkeyBundlePayloadCanonicalBody(tc.payload)
                expect(body).toBe(tc.canonicalBody)
                expect(decoder.decode(canonicalPubkeyBundleMessage(body))).toBe(tc.message)
            })
        }
    })

    describe('signingKeyPublication', () => {
        for (const tc of vectors.signingKeyPublication) {
            it(tc.name, () => {
                const body = signingKeyPublicationPayloadCanonicalBody(tc.payload)
                expect(body).toBe(tc.canonicalBody)
                expect(decoder.decode(canonicalSigningKeyPublicationMessage(body))).toBe(tc.message)
            })
        }
    })

    describe('transportAad', () => {
        for (const tc of vectors.transportAad) {
            it(tc.name, () => {
                const aad = buildTransportAAD(tc.state, tc.operation as V2Operation, tc.algorithm)
                expect(decoder.decode(aad)).toBe(tc.aad)
            })
        }
    })

    describe('requestEncAad', () => {
        for (const tc of vectors.requestEncAad) {
            it(tc.name, () => {
                const aad = buildRequestEncAAD(tc.algorithm, tc.keyLabel, tc.operation)
                expect(decoder.decode(aad)).toBe(tc.aad)
            })
        }
    })

    describe('jwkThumbprint', () => {
        for (const tc of vectors.jwkThumbprint) {
            it(tc.name, async () => {
                expect(await computeSigningKeyThumbprint(tc.jwk as V2SigningJwk)).toBe(tc.thumbprint)
            })
        }
    })
})
