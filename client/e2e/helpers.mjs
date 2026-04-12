import { expect } from '@playwright/test'
import { spawn } from 'node:child_process'

import { createVirtualPasskey } from './passkeys.mjs'

function attachAuthDebugLogging(page) {
    const failures = []
    const trackedPaths = new Set(['/v2/auth/register/finish', '/v2/auth/login/finish', '/v2/auth/finalize-signup'])

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

    await page.getByLabel('Password').fill(password)
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
    await expect(page.getByText('Live stream connected')).toBeVisible()
}

export async function openSettings(page) {
    await page.getByRole('button', { name: 'Open security settings' }).click()
    await expect(page.getByRole('button', { name: 'Close security settings' })).toBeVisible()
}

export async function openAllowedIPs(page) {
    await openSettings(page)
    await page.getByRole('button', { name: 'Configure allowed IPs' }).click()
    await expect(page.getByRole('heading', { name: 'Allowed IPs' })).toBeVisible()
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
    const res = await request.get(`/v2/request/${requestKey}/pubkey`)
    const text = await res.text()
    return {
        ok: res.ok(),
        status: res.status(),
        text,
    }
}

function encodeBase64UrlUtf8(value) {
    return Buffer.from(value, 'utf8').toString('base64url')
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
    ]

    if (args.operation === 'encrypt') {
        cliArgs.push('--value', encodeBase64UrlUtf8(args.value))
        if (args.aad) {
            cliArgs.push('--aad', Buffer.from(args.aad, 'utf8').toString('base64url'))
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
        cwd: process.cwd().replace(/\/client$/, ''),
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
