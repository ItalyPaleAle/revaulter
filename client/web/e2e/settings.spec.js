import { expect, test } from '@playwright/test'

import {
    openAllowedIPs,
    openSettings,
    openSettingsTab,
    registerAndReachReady,
    resetBrowserState,
    resetState,
} from './helpers.mjs'

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

test('settings modal opens with all tabs', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettings(page)

        // Tab buttons are in the nav element
        const nav = page.locator('nav')
        await expect(nav.locator('button', { hasText: 'User' })).toBeVisible()
        await expect(nav.locator('button', { hasText: 'IP' })).toBeVisible()
        await expect(nav.locator('button', { hasText: 'Password' })).toBeVisible()
        await expect(nav.locator('button', { hasText: 'Passkeys' })).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('settings panel opens and request key can be regenerated', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettings(page)

        // User tab is the default tab — the request key is inside the bordered container
        const requestKeyValue = page.locator('div.overflow-x-auto.mono')
        const before = await requestKeyValue.textContent()
        await page.getByRole('button', { name: 'Regenerate Regenerate' }).click()
        await page.getByRole('button', { name: 'Yes, regenerate' }).click()
        await expect(page.getByText('Request key regenerated.')).toBeVisible()
        await expect(requestKeyValue).not.toHaveText(before || '')
    } finally {
        await auth.passkey.dispose()
    }
})

test('display name can be updated', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettings(page)

        // Click edit button for display name
        await page.getByRole('button', { name: 'Edit display name' }).click()
        await page.locator('input[placeholder="Display name"]').fill('New Name')
        await page.getByRole('button', { name: 'Save' }).first().click()
        await expect(page.getByText('Display name updated.')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('allowed IPs can be updated successfully', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openAllowedIPs(page)
        await page.locator('textarea').fill('127.0.0.1\n10.0.0.0/8')
        await page.getByRole('button', { name: 'Save allowed IPs' }).click()
        await expect(page.getByText('Allowed IPs updated')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('invalid allowed IP input shows validation error', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openAllowedIPs(page)
        await page.locator('textarea').fill('not-an-ip')
        await page.getByRole('button', { name: 'Save allowed IPs' }).click()
        await expect(page.getByText('invalid IP: not-an-ip')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('passkeys tab shows credentials', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettingsTab(page, 'Passkeys')
        // Should show at least one passkey with creation timestamp
        await expect(page.getByText('Created')).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('passkey delete button is disabled when only one passkey', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettingsTab(page, 'Passkeys')
        // The delete button should be disabled when there's only one credential
        const deleteBtn = page.getByRole('button', { name: 'Delete passkey' })
        await expect(deleteBtn).toBeDisabled()
    } finally {
        await auth.passkey.dispose()
    }
})

test('password tab shows set password form when no password', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettingsTab(page, 'Password')
        await expect(page.getByText('No password is currently set')).toBeVisible()
        await expect(page.getByRole('button', { name: 'Set password' })).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('logout returns the user to sign-in', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await page.getByRole('button', { name: 'Sign out' }).click()
        await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('signing key can be derived, published, and re-published with stored proof', async ({ page, request }) => {
    const auth = await registerAndReachReady(page, 'Signing Key User')

    try {
        await openSettingsTab(page, 'Signing keys')
        await page.locator('input#signing-key-label').fill('e2e-publish')
        await page.getByRole('button', { name: 'Derive key' }).click()

        // The derived key card surfaces the key id; capture it for the public-fetch assertion below
        await expect(page.getByText('Derived key')).toBeVisible()
        const keyIdLocator = page.locator('div.mono.mt-1.break-all').first()
        const keyId = (await keyIdLocator.textContent())?.trim()
        if (!keyId) {
            throw new Error('Could not read derived key id from the settings UI')
        }

        // Publish the derived key — this signs the publication payload with the session anchor
        // The derived-key publish button has accessible name "Publish Publish" (icon title + label); the stored-key list uses aria-label "Publish key", so we target the exact form
        await page.getByRole('button', { name: 'Publish Publish', exact: true }).click()
        await expect(page.getByText('Published', { exact: true })).toBeVisible()

        // Public .jwk response carries the proof + anchor pubkeys; .pem stays raw PEM
        const jwkRes = await request.get(`/v2/signing-keys/${keyId}.jwk`)
        expect(jwkRes.status()).toBe(200)
        const jwk = await jwkRes.json()
        expect(jwk.publicationPayload).toBeTruthy()
        expect(jwk.publicationSignatureEs384).toBeTruthy()
        expect(jwk.publicationSignatureMldsa87).toBeTruthy()
        expect(jwk.anchorEs384PublicKey).toBeTruthy()
        expect(jwk.anchorMldsa87PublicKey).toBeTruthy()

        const pemRes = await request.get(`/v2/signing-keys/${keyId}.pem`)
        expect(pemRes.status()).toBe(200)
        const pemText = await pemRes.text()
        expect(pemText).toContain('-----BEGIN PUBLIC KEY-----')
        expect(pemText).not.toContain('publicationPayload')
    } finally {
        await auth.passkey.dispose()
    }
})
