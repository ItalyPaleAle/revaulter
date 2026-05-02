import { spawn } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect } from '@playwright/test'

import { createVirtualPasskey } from './passkeys.mjs'

export { createVirtualPasskeyManager as createPasskeyManager } from './passkeys.mjs'

function attachAuthDebugLogging(page) {
    const failures = []
    const trackedPaths = new Set([
        '/v2/auth/register/finish',
        '/v2/auth/login/finish',
        '/v2/auth/finalize-signup',
        '/v2/api/list',
    ])

    const responseHandler = async (response) => {
        const url = new URL(response.url())
        if (!trackedPaths.has(url.pathname)) {
            return
        }

        const contentType = response.headers()['content-type'] || ''
        if (response.ok() && contentType.includes('application/json')) {
            return
        }

        let body = ''
        try {
            body = await response.text()
        } catch (err) {
            body = err instanceof Error ? err.message : String(err)
        }

        failures.push({
            path: url.pathname,
            status: response.status(),
            contentType,
            body,
        })
    }

    page.on('response', responseHandler)

    return {
        detach() {
            page.off('response', responseHandler)
        },
        assertNoFailures() {
            if (failures.length === 0) {
                return
            }

            const details = failures
                .map((failure) => `${failure.path} -> ${failure.status} ${failure.contentType}\n${failure.body}`)
                .join('\n\n')
            throw new Error(`Auth flow returned unexpected response\n\n${details}`)
        },
    }
}

async function fetchSessionState(page) {
    const sessionResponse = await page.request.get('/v2/auth/session')
    if (!sessionResponse.ok()) {
        throw new Error(`Failed to load session state: ${sessionResponse.status()} ${await sessionResponse.text()}`)
    }

    return sessionResponse.json()
}

const e2eToken = process.env.REVAULTER_E2E_TOKEN || 'playwright-e2e-token-fixed'
const defaultServerURL = process.env.PLAYWRIGHT_TEST_BASE_URL || 'http://localhost:41741'
const currentDir = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(currentDir, '..', '..', '..')

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
    const authDebug = attachAuthDebugLogging(page)
    const passkey = await createVirtualPasskey(page)

    try {
        await page.goto('/')
        await page.getByRole('button', { name: 'Create a new account' }).click()
        await page.getByLabel('Display name (optional)').fill(displayName)
        await page.getByRole('button', { name: 'Create account with passkey' }).click()
        await expect(page.getByRole('heading', { name: 'Add a password' })).toBeVisible()
        authDebug.assertNoFailures()
        return passkey
    } catch (err) {
        authDebug.assertNoFailures()
        throw err
    } finally {
        authDebug.detach()
    }
}

export async function loginThroughUI(page) {
    const passkey = await createVirtualPasskey(page)
    await page.goto('/')
    await page.getByRole('button', { name: 'Continue with passkey' }).click()
    return passkey
}

export async function completePasswordSetup(page, password) {
    const authDebug = attachAuthDebugLogging(page)

    await page.getByLabel('Password', { exact: true }).fill(password)
    await page.getByLabel('Confirm password').fill(password)
    await page.getByRole('button', { name: 'Save password' }).click()

    try {
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        authDebug.assertNoFailures()
    } catch (err) {
        authDebug.assertNoFailures()
        throw err
    } finally {
        authDebug.detach()
    }
}

export async function skipPasswordSetup(page) {
    const authDebug = attachAuthDebugLogging(page)

    await page.getByRole('button', { name: 'Skip password' }).click()

    try {
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        authDebug.assertNoFailures()
    } catch (err) {
        authDebug.assertNoFailures()
        throw err
    } finally {
        authDebug.detach()
    }
}

export async function waitForListStream(page) {
    await expect(page.getByText('Connected', { exact: true })).toBeVisible()
}

export async function openSettings(page) {
    await page.getByRole('button', { name: 'Open settings' }).click()
    await expect(page.getByRole('button', { name: 'Close settings' })).toBeVisible()
}

export async function openSettingsTab(page, tabName) {
    await openSettings(page)
    // Tab buttons have accessible name like "User User" (icon title + text), so use text selector
    await page.locator('nav button', { hasText: tabName }).click()
}

export async function openAllowedIPs(page) {
    await openSettingsTab(page, 'Firewall')
}

export async function seedCredential(request, data) {
    return e2eFetch(request, '/__e2e__/seed-credential', { data })
}

export async function readSession(page) {
    return fetchSessionState(page)
}

export async function loginToPasswordPrompt(page) {
    await page.goto('/')
    await page.getByRole('button', { name: 'Continue with passkey' }).click()
    await expect(page.getByRole('heading', { name: 'Unlock with your password' })).toBeVisible()
}

export async function unlockWithPassword(page, password) {
    await page.getByLabel('Password').fill(password)
    await page.getByRole('button', { name: 'Unlock local keys' }).click()
}

export async function fetchRequestPubkey(request, requestKey) {
    const res = await request.get('/v2/request/pubkey', {
        headers: { Authorization: `Bearer ${requestKey}` },
    })
    const text = await res.text()
    return {
        ok: res.ok(),
        status: res.status(),
        text,
    }
}

function decodeBase64UrlUtf8(value) {
    return Buffer.from(value, 'base64url').toString('utf8')
}

function decodeCliJSON(stdout) {
    const parsed = JSON.parse(stdout)
    if (typeof parsed.value === 'string') {
        parsed.decodedValue = decodeBase64UrlUtf8(parsed.value)
    }
    if (typeof parsed.data === 'string') {
        parsed.decodedData = Buffer.from(parsed.data, 'base64').toString('utf8')
    }
    return parsed
}

// Completes signup using a passkey manager's authenticator as the active one
// Leaves the UI on the post-signup password-setup screen so the caller can decide whether to skip or set a password
export async function registerWithManager(page, manager, displayName = 'Playwright User') {
    const authDebug = attachAuthDebugLogging(page)
    const authenticatorId = await manager.addAuthenticator({ active: true })
    await manager.setActive(authenticatorId)

    try {
        await page.goto('/')
        await page.getByRole('button', { name: 'Create a new account' }).click()
        await page.getByLabel('Display name (optional)').fill(displayName)
        await page.getByRole('button', { name: 'Create account with passkey' }).click()
        await expect(page.getByRole('heading', { name: 'Add a password' })).toBeVisible()
        authDebug.assertNoFailures()
        return authenticatorId
    } catch (err) {
        authDebug.assertNoFailures()
        throw err
    } finally {
        authDebug.detach()
    }
}

// Forces the manager's specified authenticator to be the only active one and completes a passkey sign-in up to the ready or password-prompt screen
// Caller is responsible for unlocking with a password when needed
export async function signInWithAuthenticator(page, manager, authenticatorId) {
    await manager.setActive(authenticatorId)
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()
    await page.getByRole('button', { name: 'Continue with passkey' }).click()
}

// Signs out the current session, returning the UI to the sign-in screen
export async function signOutThroughUI(page) {
    await page.getByRole('button', { name: 'Sign out' }).click()
    await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()
}

// Adds a new passkey through the settings Passkeys tab using whichever authenticator is currently active on the manager
// The add-passkey flow performs two WebAuthn ceremonies (create + PRF get), both of which rely on the active authenticator
export async function addPasskeyThroughSettings(page, manager, name) {
    await openSettingsTab(page, 'Passkeys')
    await page.getByRole('button', { name: 'Add passkey' }).click()
    await page.getByLabel('Passkey name (optional)').fill(name)
    await page.getByRole('button', { name: 'Register passkey' }).click()
    await expect(page.getByText('Passkey added.')).toBeVisible({ timeout: 15_000 })
    // Close the settings modal so the ready view is interactable again
    await page.getByRole('button', { name: 'Close settings' }).click()
    // Touch the manager reference so the linter is aware the caller must have set the active authenticator beforehand
    void manager
}

// Sets a password from the Settings → Password tab (used when the account was created without a password)
export async function setPasswordThroughSettings(page, password) {
    await openSettingsTab(page, 'Password')

    const setPasswordInput = page.locator('input[placeholder="Enter password"]')
    const changePasswordInput = page.locator('input[placeholder="Enter new password"]')

    if (await setPasswordInput.count()) {
        await setPasswordInput.fill(password)
        await page.locator('input[placeholder="Confirm password"]').fill(password)
        const [response] = await Promise.all([
            page.waitForResponse((response) => {
                return response.url().includes('/v2/auth/update-wrapped-key') && response.request().method() === 'POST'
            }),
            page.getByRole('button', { name: 'Set password' }).click(),
        ])
        if (!response.ok()) {
            throw new Error(`Password update failed: ${response.status()} ${await response.text()}`)
        }
    } else {
        await changePasswordInput.fill(password)
        await page.locator('input[placeholder="Confirm new password"]').fill(password)
        const [response] = await Promise.all([
            page.waitForResponse((response) => {
                return response.url().includes('/v2/auth/update-wrapped-key') && response.request().method() === 'POST'
            }),
            page.getByRole('button', { name: 'Change password' }).click(),
        ])
        if (!response.ok()) {
            throw new Error(`Password update failed: ${response.status()} ${await response.text()}`)
        }
    }

    await expect(page.getByRole('button', { name: 'Close settings' })).toBeVisible()
    await page.getByRole('button', { name: 'Close settings' }).click()
}

export function startCLIRequest(args) {
    const cliArgs = [
        'run',
        './cmd/cli',
        args.operation,
        '--server',
        args.server || defaultServerURL,
        '--request-key',
        args.requestKey,
        '--key-label',
        args.keyLabel,
        '--algorithm',
        args.algorithm,
        '--note',
        args.note,
        // The CLI spawned by Playwright has no TTY; skip anchor pinning so the tests do not fail on first contact.
        '--no-trust-store',
    ]

    if (args.operation === 'encrypt') {
        // --message takes a raw UTF-8 string; the CLI handles base64url-encoding before submitting
        cliArgs.push('--message', args.value)
        if (args.aad) {
            cliArgs.push('--aad', Buffer.from(args.aad, 'utf8').toString('base64url'))
        }
    } else if (args.operation === 'sign') {
        // The sign op takes either --input (file) or --digest (pre-computed 32-byte SHA-256)
        // Tests pass --input so verifiers can re-hash the original message, matching Web Crypto / node's verify()
        if (args.input) {
            cliArgs.push('--input', args.input)
        } else {
            cliArgs.push('--digest', args.digest)
        }
    } else {
        cliArgs.push('--value', args.value)
        cliArgs.push('--nonce', args.nonce)
        cliArgs.push('--tag', args.tag)
        if (args.aad) {
            cliArgs.push('--aad', args.aad)
        }
    }

    const child = spawn('go', cliArgs, {
        cwd: repoRoot,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: process.env,
    })

    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => {
        stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
        stderr += chunk.toString()
    })

    const done = new Promise((resolve, reject) => {
        child.on('error', reject)
        child.on('close', (code) => {
            if (code !== 0) {
                reject(new Error(`CLI exited with ${code}\n${stderr || stdout}`))
                return
            }
            try {
                resolve({ stdout, stderr, json: decodeCliJSON(stdout) })
            } catch (err) {
                reject(err)
            }
        })
    })

    return { child, done }
}
