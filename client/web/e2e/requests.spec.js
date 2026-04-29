import { createPublicKey, verify } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { expect, test } from '@playwright/test'

import {
    fetchRequestPubkey,
    getSeededRequest,
    registerAndReachReady,
    resetBrowserState,
    resetState,
    seedPendingRequest,
    seedUser,
    startCLIRequest,
    waitForListStream,
} from './helpers.mjs'

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

test('empty ready state is shown when there are no requests', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Request User')

    try {
        await waitForListStream(page)
        await expect(page.getByText('All clear')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('seeded encrypt request appears in the list', async ({ page, request }) => {
    const auth = await registerAndReachReady(page, 'Request User')
    await seedPendingRequest(request, {
        userId: auth.session.userId,
        operation: 'encrypt',
        keyLabel: 'disk-key',
        algorithm: 'A256GCM',
        requestor: '203.0.113.20',
        note: 'boot unlock',
    })

    try {
        await expect(page.getByText('Encrypt', { exact: true }).last()).toBeVisible()
        await expect(page.getByText('disk-key')).toBeVisible()
        await expect(page.getByText(/from\s+203\.0\.113\.20/)).toBeVisible()
        await expect(page.getByText('boot unlock')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('seeded decrypt request appears in the list', async ({ page, request }) => {
    const auth = await registerAndReachReady(page, 'Request User')
    await seedPendingRequest(request, {
        userId: auth.session.userId,
        operation: 'decrypt',
        keyLabel: 'db-key',
        algorithm: 'A256GCM',
        requestor: '203.0.113.21',
    })

    try {
        await expect(page.getByText('Decrypt', { exact: true }).last()).toBeVisible()
        await expect(page.getByText('db-key')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('canceling a pending request removes it from the UI and updates state', async ({ page, request }) => {
    const auth = await registerAndReachReady(page, 'Request User')
    const seeded = await seedPendingRequest(request, {
        userId: auth.session.userId,
        operation: 'encrypt',
        keyLabel: 'cancel-key',
        algorithm: 'A256GCM',
        requestor: '203.0.113.22',
    })

    try {
        await page.getByRole('button', { name: 'Decline' }).click()
        await expect(page.getByText('All clear')).toBeVisible()

        const rec = await getSeededRequest(request, seeded.state)
        expect(rec.status).toBe('canceled')
    } finally {
        await auth.passkey.dispose()
    }
})

test('second long-poll subscriber evicts the first and the response is unavailable to the evicted caller', async ({
    page,
    request,
}) => {
    const auth = await registerAndReachReady(page, 'Subscriber Evict User')

    try {
        await waitForListStream(page)

        const seeded = await seedPendingRequest(request, {
            userId: auth.session.userId,
            operation: 'encrypt',
            keyLabel: 'evict-key',
            algorithm: 'A256GCM',
            requestor: '198.51.100.30',
        })

        await expect(page.getByText('evict-key')).toBeVisible()

        const url = `/v2/request/result/${seeded.state}`
        const requestOpts = {
            headers: { Authorization: `Bearer ${auth.session.requestKey}` },
        }

        // Start subscriber #1 — it should block on the still-pending request
        const sub1Promise = request.get(url, requestOpts)

        // Give the server a moment to register subscriber #1 before subscriber #2 evicts it
        await page.waitForTimeout(500)

        // Subscriber #2 takes over the subscription, which evicts subscriber #1
        const sub2Promise = request.get(url, requestOpts)

        // Evicted subscriber #1 must return 202 pending without receiving any result
        const sub1Res = await sub1Promise
        expect(sub1Res.status()).toBe(202)
        const sub1Body = await sub1Res.json()
        expect(sub1Body.pending).toBe(true)
        expect(sub1Body.responseEnvelope).toBeUndefined()

        // Cancel the pending request from the UI so subscriber #2 can observe the terminal state
        await page.getByRole('button', { name: 'Decline' }).click()
        await expect(page.getByText('All clear')).toBeVisible()

        // Subscriber #2 receives the terminal response
        const sub2Res = await sub2Promise
        expect(sub2Res.status()).toBe(409)
        const sub2Body = await sub2Res.json()
        expect(sub2Body.failed).toBe(true)

        // Any further long-poll on the same state must report not-found because the response is consumed
        const tailRes = await request.get(url, requestOpts)
        expect(tailRes.status()).toBe(404)
    } finally {
        await auth.passkey.dispose()
    }
})

test('requests for another user are not shown', async ({ page, request }) => {
    const auth = await registerAndReachReady(page, 'Request User')
    await seedUser(request, {
        userId: 'other-user',
        displayName: 'Other User',
        state: 'ready-no-password',
    })
    await seedPendingRequest(request, {
        userId: 'other-user',
        operation: 'encrypt',
        keyLabel: 'other-key',
        algorithm: 'A256GCM',
        requestor: '203.0.113.23',
    })

    try {
        await waitForListStream(page)
        await expect(page.getByText('other-key')).toHaveCount(0)
        await expect(page.getByText('All clear')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('new seeded request appears without reload after stream is connected', async ({ page, request }) => {
    const auth = await registerAndReachReady(page, 'Request User')

    try {
        await waitForListStream(page)
        await expect(page.getByText('All clear')).toBeVisible()

        await seedPendingRequest(request, {
            userId: auth.session.userId,
            operation: 'encrypt',
            keyLabel: 'stream-key',
            algorithm: 'A256GCM',
            requestor: '203.0.113.24',
        })

        await expect(page.getByText('stream-key')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('regenerating the request key invalidates the old public key endpoint', async ({ page, request }) => {
    const auth = await registerAndReachReady(page, 'Request User')
    const oldKey = auth.session.requestKey

    try {
        const before = await fetchRequestPubkey(request, oldKey)
        expect(before.status).toBe(200)

        await page.getByRole('button', { name: 'Open settings' }).click()
        await page.getByRole('button', { name: 'Regenerate Regenerate' }).click()
        await page.getByRole('button', { name: 'Yes, regenerate' }).click()
        await expect(page.getByText('Request key regenerated.')).toBeVisible()

        const current = await page.request.get('/v2/auth/session')
        const session = await current.json()
        const newKey = session.requestKey

        expect(newKey).not.toBe(oldKey)

        const oldKeyResponse = await fetchRequestPubkey(request, oldKey)
        expect(oldKeyResponse.status).toBe(404)

        const newKeyResponse = await fetchRequestPubkey(request, newKey)
        expect(newKeyResponse.status).toBe(200)
    } finally {
        await auth.passkey.dispose()
    }
})

test('cli sign round-trips and the signature verifies against the browser-derived public key', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'CLI Sign User')

    // Create a temp file with known content; CLI will SHA-256 it internally and request the browser to sign the digest
    const tmpRoot = mkdtempSync(join(tmpdir(), 'revaulter-e2e-sign-'))
    const inputPath = join(tmpRoot, 'sign-input.bin')
    const message = Buffer.from('revaulter sign e2e — the quick brown fox jumps over the lazy dog', 'utf8')
    writeFileSync(inputPath, message)

    try {
        await waitForListStream(page)

        // Capture the public key the browser sends alongside the response envelope
        // This is the ground truth for verification: server auto-stores exactly this JWK as published=false
        const confirmRequestPromise = page.waitForRequest(
            (req) => req.url().endsWith('/v2/api/confirm') && req.method() === 'POST'
        )

        const signRun = startCLIRequest({
            operation: 'sign',
            requestKey: auth.session.requestKey,
            keyLabel: 'sign-e2e-label',
            algorithm: 'ES256',
            note: 'cli sign e2e',
            input: inputPath,
        })

        await expect(page.getByText('cli sign e2e')).toBeVisible()
        await page.getByRole('button', { name: 'Confirm' }).click()

        const confirmRequest = await confirmRequestPromise
        const confirmBody = JSON.parse(confirmRequest.postData() || '{}')
        expect(confirmBody.confirm).toBe(true)
        expect(confirmBody.publicKey).toBeDefined()
        expect(confirmBody.publicKey.jwk).toBeDefined()
        expect(confirmBody.publicKey.pem).toMatch(/-----BEGIN PUBLIC KEY-----/)

        const signResult = await signRun.done
        expect(signResult.json.operation).toBe('sign')
        expect(signResult.json.algorithm).toBe('ES256')
        expect(signResult.json.keyLabel).toBe('sign-e2e-label')
        expect(typeof signResult.json.signature).toBe('string')

        // Signature is base64url-encoded raw r||s (64 bytes for ES256)
        const sigBytes = Buffer.from(signResult.json.signature, 'base64url')
        expect(sigBytes.length).toBe(64)

        // The browser signs the 32-byte SHA-256 digest of the message directly (prehashed)
        // Node's verify with 'sha256' hashes the message once, matching standard ES256 semantics
        const publicKey = createPublicKey({ key: confirmBody.publicKey.jwk, format: 'jwk' })
        const ok = verify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sigBytes)
        expect(ok, 'CLI signature must verify against the browser-derived public key').toBe(true)

        // And the same signature must not verify against a tampered message — sanity check
        const tampered = Buffer.concat([message, Buffer.from('!')])
        const bad = verify('sha256', tampered, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sigBytes)
        expect(bad, 'signature must not verify against a tampered message').toBe(false)
    } finally {
        rmSync(tmpRoot, { recursive: true, force: true })
        await auth.passkey.dispose()
    }
})

// Cover all four accepted name forms — both the JOSE-style and long-form name pair for AES-GCM and ChaCha20-Poly1305
// Encrypt and decrypt must use the SAME spelling because the algorithm string is bound into HKDF info and AAD verbatim
for (const algorithm of ['A256GCM', 'aes-256-gcm', 'C20P', 'chacha20-poly1305']) {
    test(`cli encrypt then decrypt round-trips hello world (algorithm=${algorithm})`, async ({ page }) => {
        const auth = await registerAndReachReady(page, `CLI Crypto User ${algorithm}`)

        try {
            await waitForListStream(page)

            const encryptRun = startCLIRequest({
                operation: 'encrypt',
                requestKey: auth.session.requestKey,
                keyLabel: 'disk-key',
                algorithm,
                note: 'cli round trip encrypt',
                value: 'hello world',
            })

            await expect(page.getByText('cli round trip encrypt')).toBeVisible()
            await page.getByRole('button', { name: 'Confirm' }).click()

            const encryptResult = await encryptRun.done
            expect(encryptResult.json.operation).toBe('encrypt')
            expect(typeof encryptResult.json.value).toBe('string')
            expect(typeof encryptResult.json.nonce).toBe('string')
            expect(typeof encryptResult.json.tag).toBe('string')

            const decryptRun = startCLIRequest({
                operation: 'decrypt',
                requestKey: auth.session.requestKey,
                keyLabel: 'disk-key',
                algorithm,
                note: 'cli round trip decrypt',
                value: encryptResult.json.value,
                nonce: encryptResult.json.nonce,
                tag: encryptResult.json.tag,
                aad: encryptResult.json.additionalData,
            })

            await expect(page.getByText('cli round trip decrypt')).toBeVisible()
            await page.getByRole('button', { name: 'Confirm' }).click()

            const decryptResult = await decryptRun.done
            expect(decryptResult.json.operation).toBe('decrypt')
            expect(decryptResult.json.decodedValue).toBe('hello world')
        } finally {
            await auth.passkey.dispose()
        }
    })
}
