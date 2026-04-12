import { expect } from '@playwright/test'

import { createVirtualPasskey } from './passkeys.mjs'

async function fetchSessionState(page) {
    const sessionResponse = await page.request.get('/v2/auth/session')
    if (!sessionResponse.ok()) {
        throw new Error(`Failed to load session state: ${sessionResponse.status()} ${await sessionResponse.text()}`)
    }

    return sessionResponse.json()
}

const e2eToken = process.env.REVAULTER_E2E_TOKEN || 'playwright-e2e-token-fixed'

async function e2eFetch(request, path, options = {}) {
    const headers = {
        'x-revaulter-e2e-token': e2eToken,
        'content-type': 'application/json',
        ...(options.headers || {}),
    }

    const res = await request.fetch(path, {
        method: options.method || 'POST',
        headers,
        data: options.data,
    })
    if (!res.ok()) {
        throw new Error(`E2E control request failed: ${res.status()} ${await res.text()}`)
    }
    return res.json()
}

export async function resetState(request) {
    return e2eFetch(request, '/__e2e__/reset', { data: {} })
}

export async function resetBrowserState(page) {
    await page.goto('/')
    await page.context().clearCookies()
    await page.evaluate(async () => {
        localStorage.clear()
        sessionStorage.clear()

        const registrations = await navigator.serviceWorker.getRegistrations()
        await Promise.all(registrations.map((registration) => registration.unregister()))

        const cacheNames = await caches.keys()
        await Promise.all(cacheNames.map((cacheName) => caches.delete(cacheName)))

        indexedDB.deleteDatabase('revaulter')
    })
}

export async function seedUser(request, data) {
    return e2eFetch(request, '/__e2e__/seed-user', { data })
}

export async function seedSession(request, data) {
    return e2eFetch(request, '/__e2e__/seed-session', { data })
}

export async function seedPendingRequest(request, data) {
    return e2eFetch(request, '/__e2e__/seed-request', { data })
}

export async function getSeededRequest(request, state) {
    return e2eFetch(request, `/__e2e__/request/${state}`, { method: 'GET', data: undefined })
}

export async function installSessionCookie(context, request, userId) {
    const seeded = await seedSession(request, { userId })
    await context.addCookies([
        {
            name: seeded.cookieName,
            value: seeded.cookieValue,
            path: seeded.cookiePath,
            domain: 'localhost',
            httpOnly: true,
            sameSite: 'Lax',
        },
    ])
    return seeded
}

export async function gotoReadyPage(page) {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
}

export async function registerAndReachReady(page, displayName = 'Playwright Ready User') {
    const passkey = await registerThroughUI(page, displayName)
    await skipPasswordSetup(page)

    const session = await fetchSessionState(page)
    return { passkey, session }
}

export async function registerThroughUI(page, displayName = 'Playwright User') {
    const passkey = await createVirtualPasskey(page)
    await page.goto('/')
    await page.getByRole('button', { name: 'Create a new account' }).click()
    await page.getByLabel('Display name (optional)').fill(displayName)
    await page.getByRole('button', { name: 'Create account with passkey' }).click()
    await expect(page.getByRole('heading', { name: 'Add a password' })).toBeVisible()
    return passkey
}

export async function loginThroughUI(page) {
    const passkey = await createVirtualPasskey(page)
    await page.goto('/')
    await page.getByRole('button', { name: 'Continue with passkey' }).click()
    return passkey
}

export async function completePasswordSetup(page, password) {
    await page.getByLabel('Password').fill(password)
    await page.getByRole('button', { name: 'Save password' }).click()
    await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
}

export async function skipPasswordSetup(page) {
    await page.getByRole('button', { name: 'Skip password' }).click()
    await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
}

export async function waitForListStream(page) {
    await expect(page.getByText('Live stream connected')).toBeVisible()
}

export async function openSettings(page) {
    await page.getByRole('button', { name: 'Open security settings' }).click()
    await expect(page.getByText('Security settings')).toBeVisible()
}

export async function openAllowedIPs(page) {
    await openSettings(page)
    await page.getByRole('button', { name: 'Configure allowed IPs' }).click()
    await expect(page.getByText('Allowed IPs')).toBeVisible()
}
