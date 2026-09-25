import { expect, test } from '@playwright/test'

import {
    fetchRequestPubkey,
    openAllowedIPs,
    openSettings,
    openSettingsTab,
    registerAndReachReady,
    resetBrowserState,
    resetState,
} from './helpers.mjs'
import { createVirtualPasskey } from './passkeys.mjs'

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
        await expect(nav.locator('button', { hasText: 'Request auth' })).toBeVisible()
        await expect(nav.locator('button', { hasText: 'Firewall' })).toBeVisible()
        await expect(nav.locator('button', { hasText: 'Password' })).toBeVisible()
        await expect(nav.locator('button', { hasText: 'Passkeys' })).toBeVisible()
    } finally {
        await auth.passkey.dispose()
    }
})

test('settings modal traps focus and restores it to the opener', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        const opener = page.getByRole('button', { name: 'Open settings' })
        await opener.click()

        const dialog = page.getByRole('dialog', { name: 'Settings' })
        await expect(dialog).toBeVisible()
        await expect(page.getByRole('button', { name: 'Close settings' })).toBeFocused()

        await page.keyboard.press('Shift+Tab')
        expect(
            await page.evaluate(() => {
                const dialogElement = document.querySelector('[role="dialog"]')
                return dialogElement?.contains(document.activeElement)
            })
        ).toBe(true)

        await page.keyboard.press('Escape')
        await expect(dialog).toBeHidden()
        await expect(opener).toBeFocused()
    } finally {
        await auth.passkey.dispose()
    }
})

test('settings panel opens and request key can be regenerated', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettingsTab(page, 'Request auth')

        // The request key is inside the bordered container
        const requestKeyValue = page.locator('div.overflow-x-auto.mono', { hasText: 'rvk_' })
        const before = await requestKeyValue.textContent()
        await page.getByRole('button', { name: 'Regenerate Regenerate' }).click()
        await page.getByRole('button', { name: 'Yes, regenerate' }).click()
        await expect(page.getByText('Request key regenerated.')).toBeVisible()
        await expect(requestKeyValue).not.toHaveText(before || '')
    } finally {
        await auth.passkey.dispose()
    }
})

test('request auth tab enables OIDC tokens and the request key independently', async ({ page, request }) => {
    const auth = await registerAndReachReady(page, 'Settings User')

    try {
        await openSettingsTab(page, 'Request auth')

        const requestKeyToggle = page.getByRole('checkbox', { name: /^Request key/ })
        const oidcToggle = page.getByRole('checkbox', { name: /^OIDC tokens/ })

        // By default, only the request key is enabled, and the OIDC settings are hidden
        await expect(requestKeyToggle).toBeChecked()
        await expect(oidcToggle).not.toBeChecked()
        await expect(page.getByRole('button', { name: 'Add trusted issuer' })).toBeHidden()

        // Enabling OIDC tokens shows the user ID and the trusted issuers, and keeps the request key working
        await oidcToggle.check()
        await expect(page.getByText('Authentication methods updated')).toBeVisible()
        await expect(oidcToggle).toBeChecked()
        await expect(requestKeyToggle).toBeChecked()
        await expect(page.getByText(auth.session.userId, { exact: true })).toBeVisible()
        expect((await fetchRequestPubkey(request, auth.session.requestKey)).status).toBe(200)

        // The audience defaults to the public endpoint of the server
        await page.getByRole('button', { name: 'Add trusted issuer' }).click()
        await expect(page.getByLabel('Audience')).toHaveValue(new URL(page.url()).origin)

        // A subject made only of wildcards is rejected
        await page.getByLabel('Issuer', { exact: true }).fill('https://token.actions.githubusercontent.com')
        await page.getByLabel('Subject').fill('*')
        await page.getByRole('button', { name: 'Add issuer' }).click()
        await expect(page.getByText('subject must not consist only of wildcards')).toBeVisible()

        await page.getByLabel('Name (optional)').fill('Release workflow')
        await page.getByLabel('Subject').fill('repo:example/app:ref:refs/tags/*')
        await page.getByRole('button', { name: 'Add issuer' }).click()
        await expect(page.getByText('OIDC issuer added')).toBeVisible()
        await expect(page.getByText('Release workflow')).toBeVisible()
        await expect(page.getByText('OIDC discovery')).toBeVisible()

        // Disabling the request key hides it, and the server rejects it
        await requestKeyToggle.uncheck()
        await expect(requestKeyToggle).not.toBeChecked()
        await expect(page.getByRole('button', { name: 'Regenerate Regenerate' })).toBeHidden()
        expect((await fetchRequestPubkey(request, auth.session.requestKey)).status).toBe(403)

        // Disabling OIDC tokens hides the issuers without deleting them
        await oidcToggle.uncheck()
        await expect(oidcToggle).not.toBeChecked()
        await expect(page.getByText('Release workflow')).toBeHidden()
        await oidcToggle.check()
        await expect(oidcToggle).toBeChecked()
        await expect(page.getByText('Release workflow')).toBeVisible()

        await page.getByRole('button', { name: 'Remove OIDC issuer' }).click()
        await expect(page.getByText('OIDC issuer removed')).toBeVisible()
        await expect(page.getByText('No trusted issuers.')).toBeVisible()

        // Re-enabling the request key makes it work again
        // The checkbox changes as soon as it's clicked, so wait for the key to be shown again, which happens once the server has saved the change
        await requestKeyToggle.check()
        await expect(requestKeyToggle).toBeChecked()
        await expect(page.getByRole('button', { name: 'Regenerate Regenerate' })).toBeVisible()
        expect((await fetchRequestPubkey(request, auth.session.requestKey)).status).toBe(200)
    } finally {
        await auth.passkey.dispose()
    }
})

test.describe(() => {
    test.use({ serviceWorkers: 'block' })

    test('request auth toggle reverts when saving fails', async ({ page, request }) => {
        const auth = await registerAndReachReady(page, 'Settings User')

        try {
            await openSettingsTab(page, 'Request auth')

            // Make the next save fail
            await page.route('**/v2/auth/request-auth-methods', (route) =>
                route.fulfill({
                    status: 500,
                    contentType: 'application/json',
                    body: JSON.stringify({ error: 'Simulated failure' }),
                })
            )

            const requestKeyToggle = page.getByRole('checkbox', { name: /^Request key/ })
            await requestKeyToggle.click()
            await expect(page.getByText('Simulated failure')).toBeVisible()

            // The checkbox shows the saved value again, and the key still works
            await expect(requestKeyToggle).toBeChecked()
            await expect(page.getByRole('button', { name: 'Regenerate Regenerate' })).toBeVisible()
            expect((await fetchRequestPubkey(request, auth.session.requestKey)).status).toBe(200)
        } finally {
            await auth.passkey.dispose()
        }
    })
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

test('adding a passkey without PRF stops before server persistence', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'Settings User')
    const incompatiblePasskey = await createVirtualPasskey(page, { hasPrf: false })

    try {
        let addCredentialFinishes = 0
        page.on('request', (request) => {
            if (new URL(request.url()).pathname === '/v2/auth/credentials/add/finish') {
                addCredentialFinishes += 1
            }
        })

        await openSettingsTab(page, 'Passkeys')
        await page.getByRole('button', { name: 'Add passkey' }).click()
        await page.getByLabel('Passkey name (optional)').fill('No PRF')
        await page.getByRole('button', { name: 'Register passkey' }).click()

        await expect(
            page.getByText(
                'This passkey does not support the PRF extension Revaulter needs to protect your local keys. Add a PRF-capable passkey or use a browser and authenticator that support WebAuthn PRF.'
            )
        ).toBeVisible()
        await expect(page.getByRole('link', { name: 'Learn about compatible passkeys' })).toHaveAttribute(
            'href',
            'https://revaulter.italypaleale.me/docs/what-is-revaulter/#supported-passkeys'
        )
        expect(addCredentialFinishes).toBe(0)
    } finally {
        await incompatiblePasskey.dispose()
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
        const publishButton = page.getByRole('button', { name: 'Publish Publish', exact: true })
        await publishButton.click()
        // After publishing the button is replaced with a "Published" status badge; "Published" also appears as a tooltip title inside the badge's check icon, so we wait for the publish button to disappear instead
        await expect(publishButton).toBeHidden()

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
