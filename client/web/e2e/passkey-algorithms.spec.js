import { expect, test } from '@playwright/test'

import { cborInt } from './cbor.mjs'
import {
    clearSiteStorage,
    completeSignupForm,
    readSession,
    resetBrowserState,
    resetState,
    skipPasswordSetup,
    startCLIRequest,
    waitForListStream,
} from './helpers.mjs'
import { getPasskeyAlgorithm, isPasskeyAlgorithmAvailable } from './passkey-algorithms.mjs'
import { installSoftwareAuthenticator } from './software-authenticator.mjs'

// Chrome's virtual authenticator only mints ES256 credentials, so these run against the software authenticator in ./software-authenticator.mjs
// Each case covers the core lifecycle for one passkey algorithm: registering the credential, signing in again from a clean browser profile, and approving one operation
const ALGORITHMS = ['ed25519', 'rs256', 'mldsa44']

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

// The credential public key opens with its key type and algorithm, so the encoded pair appears verbatim in the attestation the browser sent to the server
// Hex keeps the comparison byte-aligned, which base64 would not
function coseKeyPrefixHex(algorithm) {
    return Buffer.concat([
        cborInt(1),
        cborInt(algorithm.keyType),
        cborInt(3),
        cborInt(algorithm.coseAlgorithm),
    ]).toString('hex')
}

for (const algorithmName of ALGORITHMS) {
    const algorithm = getPasskeyAlgorithm(algorithmName)

    test.describe(`passkey algorithm ${algorithm.label}`, () => {
        // ML-DSA needs a node build with a post-quantum-capable OpenSSL to generate the test credential
        test.skip(
            () => !isPasskeyAlgorithmAvailable(algorithmName),
            `node ${process.version} cannot generate ${algorithm.label} keys`
        )

        test('registers a passkey the server accepts', async ({ page }) => {
            const passkey = await installSoftwareAuthenticator(page, { algorithm: algorithmName })

            try {
                const registerRequest = page.waitForRequest((request) => {
                    return request.url().includes('/v2/auth/register/finish') && request.method() === 'POST'
                })

                await completeSignupForm(page, `${algorithm.label} User`)

                // Assert against the bytes the browser actually sent so the test fails if the credential silently falls back to another algorithm
                const body = (await registerRequest).postDataJSON()
                const attestationObject = Buffer.from(body.credential.response.attestationObject, 'base64url')
                expect(attestationObject.toString('hex')).toContain(coseKeyPrefixHex(algorithm))

                await skipPasswordSetup(page)
                await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
            } finally {
                await passkey.dispose()
            }
        })

        // Clearing site storage forces the client to re-derive its local keys from the PRF output of a fresh assertion, which is the path a returning user takes
        test('signs in again from a clean browser profile', async ({ page }) => {
            const passkey = await installSoftwareAuthenticator(page, { algorithm: algorithmName })

            try {
                await completeSignupForm(page, `${algorithm.label} Returning User`)
                await skipPasswordSetup(page)

                await page.context().clearCookies()
                await clearSiteStorage(page)
                await page.reload()
                await expect(page.getByRole('heading', { name: 'Sign in to Revaulter' })).toBeVisible()

                const loginRequest = page.waitForRequest((request) => {
                    return request.url().includes('/v2/auth/login/finish') && request.method() === 'POST'
                })
                await page.getByRole('button', { name: 'Continue with passkey' }).click()

                const body = (await loginRequest).postDataJSON()
                expect(typeof body.credential.clientExtensionResults.prf.results.first).toBe('string')
                await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
            } finally {
                await passkey.dispose()
            }
        })

        test('approves an encrypt request end to end', { tag: '@requeststream' }, async ({ page }) => {
            const passkey = await installSoftwareAuthenticator(page, { algorithm: algorithmName })

            try {
                await completeSignupForm(page, `${algorithm.label} Approver`)
                await skipPasswordSetup(page)
                const session = await readSession(page)
                await waitForListStream(page)

                const encryptRun = startCLIRequest({
                    operation: 'encrypt',
                    requestKey: session.requestKey,
                    keyLabel: 'disk-key',
                    algorithm: 'A256GCM',
                    note: `approval with ${algorithm.name}`,
                    value: 'hello world',
                })

                // The CLI is compiled on first use, which can take longer than the default expect timeout
                await expect(page.getByText(`approval with ${algorithm.name}`)).toBeVisible({ timeout: 60_000 })
                await page.getByRole('button', { name: 'Confirm' }).click()

                const encryptResult = await encryptRun.done
                expect(encryptResult.json.kind).toBe('revaulter/1')
                expect(encryptResult.json.keyLabel).toBe('disk-key')
                expect(typeof encryptResult.json.value).toBe('string')
            } finally {
                await passkey.dispose()
            }
        })
    })
}

test('registration fails when the server does not offer the credential algorithm', async ({ page }) => {
    // ES256K is registered with COSE but is not on any algorithm list the server offers, so the authenticator has nothing it may mint
    const passkey = await installSoftwareAuthenticator(page, { algorithm: 'es256k' })

    try {
        await page.goto('/')
        await page.getByRole('button', { name: 'Create a new account' }).click()
        await page.getByLabel('Display name (optional)').fill('Unsupported Algorithm User')
        await page.getByRole('button', { name: 'Create account with passkey' }).click()
        await expect(page.getByText(/did not offer/)).toBeVisible()
    } finally {
        await passkey.dispose()
    }
})
