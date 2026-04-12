import { expect, test } from '@playwright/test'

import { openAllowedIPs, openSettings, registerAndReachReady, resetBrowserState, resetState } from './helpers.mjs'

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

test('settings panel opens and request key can be regenerated', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettings(page)

        const requestKeyValue = page.locator('div.font-mono.text-sm').first()
        const before = await requestKeyValue.textContent()
        await page.getByRole('button', { name: 'Regenerate' }).click()
        await expect(page.getByText('Request key regenerated.')).toBeVisible()
        await expect(requestKeyValue).not.toHaveText(before || '')
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

test('logout returns the user to sign-in', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettings(page)
        await page.getByRole('button', { name: 'Sign out' }).click()
        await expect(page.getByRole('heading', { name: 'Sign in with your passkey' })).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})
