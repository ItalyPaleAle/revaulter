import { expect, test } from '@playwright/test'

import { createVirtualPasskey } from './passkeys.mjs'

test('user can register and sign in with a PRF-capable passkey', async ({ page }) => {
    const passkey = await createVirtualPasskey(page)

    try {
        await page.goto('/')

        await expect(page.getByRole('heading', { name: 'Sign in with your passkey' })).toBeVisible()

        await page.getByRole('button', { name: 'Create a new account' }).click()
        await page.getByLabel('Display name (optional)').fill('Playwright User')
        await page.getByRole('button', { name: 'Create account with passkey' }).click()

        await expect(page.getByRole('heading', { name: 'Add a password' })).toBeVisible()
        await page.getByRole('button', { name: 'Skip password' }).click()

        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        await expect(page.getByText('No pending requests')).toBeVisible()

        await page.getByRole('button', { name: 'Open security settings' }).click()
        await expect(page.getByText('Request key')).toBeVisible()
        await page.getByRole('button', { name: 'Sign out' }).click()

        await expect(page.getByRole('heading', { name: 'Sign in with your passkey' })).toBeVisible()
        await page.getByRole('button', { name: 'Continue with passkey' }).click()

        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        await expect(page.getByText('No pending requests')).toBeVisible()
    } finally {
        await passkey.dispose()
    }
})
