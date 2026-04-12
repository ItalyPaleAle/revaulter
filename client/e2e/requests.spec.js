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
        await expect(page.getByText('No pending requests')).toBeVisible()
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
        algorithm: 'aes-gcm-256',
        requestor: '203.0.113.20',
        note: 'boot unlock',
    })

    try {
        await expect(page.getByText('Encrypt request')).toBeVisible()
        await expect(page.getByText('disk-key')).toBeVisible()
        await expect(page.getByText('Requestor:')).toContainText('203.0.113.20')
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
        algorithm: 'aes-gcm-256',
        requestor: '203.0.113.21',
    })

    try {
        await expect(page.getByText('Decrypt request')).toBeVisible()
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
        algorithm: 'aes-gcm-256',
        requestor: '203.0.113.22',
    })

    try {
        await page.getByRole('button', { name: 'Cancel' }).click()
        await expect(page.getByText('No pending requests')).toBeVisible()

        const rec = await getSeededRequest(request, seeded.state)
        expect(rec.status).toBe('canceled')
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
        algorithm: 'aes-gcm-256',
        requestor: '203.0.113.23',
    })

    try {
        await waitForListStream(page)
        await expect(page.getByText('other-key')).toHaveCount(0)
        await expect(page.getByText('No pending requests')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('new seeded request appears without reload after stream is connected', async ({ page, request }) => {
    const auth = await registerAndReachReady(page, 'Request User')

    try {
        await waitForListStream(page)
        await expect(page.getByText('No pending requests')).toBeVisible()

        await seedPendingRequest(request, {
            userId: auth.session.userId,
            operation: 'encrypt',
            keyLabel: 'stream-key',
            algorithm: 'aes-gcm-256',
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

        await page.getByRole('button', { name: 'Open security settings' }).click()
        await page.getByRole('button', { name: 'Regenerate' }).click()
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

test('cli encrypt then decrypt round-trips hello world', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'CLI Crypto User')

    try {
        await waitForListStream(page)

        const encryptRun = startCLIRequest({
            operation: 'encrypt',
            requestKey: auth.session.requestKey,
            keyLabel: 'disk-key',
            algorithm: 'aes-gcm-256',
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
            algorithm: 'aes-gcm-256',
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
