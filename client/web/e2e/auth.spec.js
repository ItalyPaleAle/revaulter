import { expect, test } from '@playwright/test'

import {
    completePasswordSetup,
    installSessionCookie,
    loginToPasswordPrompt,
    registerThroughUI,
    resetBrowserState,
    resetState,
    seedUser,
    skipPasswordSetup,
    unlockWithPassword,
} from './helpers.mjs'

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

test('sign-in page renders on a clean instance', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Create a new account' })).toBeVisible()
})

test('user can register and skip password setup', async ({ page }) => {
    const passkey = await registerThroughUI(page, 'Skip Password User')

    try {
        await skipPasswordSetup(page)
        await expect(page.getByText('All clear')).toBeVisible()
    } finally {
        await passkey.dispose()
    }
})

test('user can register and save a password', async ({ page }) => {
    const passkey = await registerThroughUI(page, 'Password User')

    try {
        await completePasswordSetup(page, 'hunter2')
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
    } finally {
        await passkey.dispose()
    }
})

test('passwordless ready user logs in directly to ready view', async ({ page }) => {
    const passkey = await registerThroughUI(page, 'Passwordless User')

    try {
        await skipPasswordSetup(page)
        await openSignInState(page)
        await expect(
            page.getByText('Session exists but local key material is missing. Sign in again to continue.')
        ).toBeVisible()

        await page.getByRole('button', { name: 'Continue with passkey' }).click()
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
    } finally {
        await passkey.dispose()
    }
})

test('user can register and later return to sign-in after password setup', async ({ page }) => {
    const passkey = await registerThroughUI(page, 'Password User')

    try {
        await completePasswordSetup(page, 'hunter2')
        await openSignInState(page)
        await expect(page.getByRole('button', { name: 'Continue with passkey' })).toBeVisible()
    } finally {
        await passkey.dispose()
    }
})

test('password-protected user can unlock with the correct password', async ({ page }) => {
    const passkey = await registerThroughUI(page, 'Protected User')

    try {
        await completePasswordSetup(page, 'hunter2')
        await openSignInState(page)

        await loginToPasswordPrompt(page)
        await unlockWithPassword(page, 'hunter2')
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
    } finally {
        await passkey.dispose()
    }
})

test('password-protected user sees an error for a wrong password and can recover', async ({ page }) => {
    const passkey = await registerThroughUI(page, 'Protected User')

    try {
        await completePasswordSetup(page, 'hunter2')
        await openSignInState(page)

        await loginToPasswordPrompt(page)
        await unlockWithPassword(page, 'wrong-password')
        await expect(page.getByText('Incorrect password')).toBeVisible()
        await expect(page.getByRole('heading', { name: 'Unlock with your password' })).toBeVisible()

        await unlockWithPassword(page, 'hunter2')
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
    } finally {
        await passkey.dispose()
    }
})

test('expired ready session forces the UI back to sign-in', async ({ page, request }) => {
    const passkey = await registerThroughUI(page, 'Session User')

    try {
        await skipPasswordSetup(page)
        await resetState(request)

        await page.goto('/')
        await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()
    } finally {
        await passkey.dispose()
    }
})

test('reload during non-ready setup resumes via session endpoint', async ({ page, request, context }) => {
    await seedUser(request, {
        userId: 'user-nonready',
        displayName: 'Non-ready User',
        state: 'registered-nonready',
    })
    await installSessionCookie(context, request, 'user-nonready')

    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()
    await page.reload()
    await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()
})

async function openSignInState(page) {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()
}
