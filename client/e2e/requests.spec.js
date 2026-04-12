import { expect, test } from '@playwright/test'

import {
    getSeededRequest,
    registerAndReachReady,
    resetBrowserState,
    resetState,
    seedPendingRequest,
    seedUser,
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
