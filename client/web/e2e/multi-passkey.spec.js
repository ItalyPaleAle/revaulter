import { expect, test } from '@playwright/test'

import {
    addPasskeyThroughSettings,
    createPasskeyManager,
    readSession,
    registerWithManager,
    resetBrowserState,
    resetState,
    setPasswordThroughSettings,
    signInWithAuthenticator,
    signOutThroughUI,
    skipPasswordSetup,
    startCLIRequest,
    unlockWithPassword,
    waitForListStream,
} from './helpers.mjs'

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

// Helper that drives a full CLI encrypt/decrypt round-trip through the UI
// The caller is expected to already be on the ready view when each half is invoked
async function runEncryptThroughUI(page, requestKey, plaintext, noteSuffix) {
    await waitForListStream(page)
    const encryptRun = startCLIRequest({
        operation: 'encrypt',
        requestKey,
        keyLabel: 'multi-passkey',
        algorithm: 'aes-gcm-256',
        note: `multi-passkey encrypt ${noteSuffix}`,
        value: plaintext,
    })

    await expect(page.getByText(`multi-passkey encrypt ${noteSuffix}`)).toBeVisible()
    await page.getByRole('button', { name: 'Confirm' }).click()

    const result = await encryptRun.done
    expect(result.json.operation).toBe('encrypt')
    return result.json
}

async function runDecryptThroughUI(page, requestKey, encryptOutput, noteSuffix) {
    await waitForListStream(page)
    const decryptRun = startCLIRequest({
        operation: 'decrypt',
        requestKey,
        keyLabel: 'multi-passkey',
        algorithm: 'aes-gcm-256',
        note: `multi-passkey decrypt ${noteSuffix}`,
        value: encryptOutput.value,
        nonce: encryptOutput.nonce,
        tag: encryptOutput.tag,
        aad: encryptOutput.additionalData,
    })

    await expect(page.getByText(`multi-passkey decrypt ${noteSuffix}`)).toBeVisible()
    await page.getByRole('button', { name: 'Confirm' }).click()

    const result = await decryptRun.done
    expect(result.json.operation).toBe('decrypt')
    return result.json
}

test('two passkeys without a password can each sign in and share the primary key', async ({ page }) => {
    const manager = await createPasskeyManager(page)

    try {
        // Register the first passkey and skip password setup so the account is purely passkey-gated
        const firstId = await registerWithManager(page, manager, 'Multi Passkey User')
        await skipPasswordSetup(page)

        // Add a second passkey while signed in; the helper expects the manager to already have the desired authenticator active
        const secondId = await manager.addAuthenticator({ active: false })
        await manager.setActive(secondId)
        await addPasskeyThroughSettings(page, manager, 'Second Passkey')

        // Sign out and sign back in with the first passkey, then encrypt a message via the CLI
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, firstId)
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const firstSession = await readSession(page)
        const encrypted = await runEncryptThroughUI(page, firstSession.requestKey, 'hello world', 'pk1')

        // Sign out again and verify the second passkey can unlock the same primary key by decrypting the message
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, secondId)
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const secondSession = await readSession(page)
        expect(secondSession.userId).toBe(firstSession.userId)
        const decrypted = await runDecryptThroughUI(page, secondSession.requestKey, encrypted, 'pk2')
        expect(decrypted.decodedValue).toBe('hello world')
    } finally {
        await manager.dispose()
    }
})

test('two passkeys with a password set before the second passkey share the primary key', async ({ page }) => {
    const manager = await createPasskeyManager(page)

    try {
        // Register the first passkey and set a password at signup time so both passkeys are wrapped with the same password
        const firstId = await registerWithManager(page, manager, 'Multi Passkey With Password')
        const password = 'hunter2'
        await page.getByLabel('Password', { exact: true }).fill(password)
        await page.getByLabel('Confirm password').fill(password)
        await page.getByRole('button', { name: 'Save password' }).click()
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()

        // Add the second passkey; doAddPasskey reuses the in-memory session password to wrap the new credential's primary key
        const secondId = await manager.addAuthenticator({ active: false })
        await manager.setActive(secondId)
        await addPasskeyThroughSettings(page, manager, 'Second Passkey')

        // Sign out and sign back in with the first passkey, unlocking with the password before encrypting
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, firstId)
        await expect(page.getByRole('heading', { name: 'Unlock with your password' })).toBeVisible()
        await unlockWithPassword(page, password)
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const firstSession = await readSession(page)
        const encrypted = await runEncryptThroughUI(page, firstSession.requestKey, 'hello world', 'pk1')

        // Sign in with the second passkey using the same password; both credentials must unwrap to the same primary key
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, secondId)
        await expect(page.getByRole('heading', { name: 'Unlock with your password' })).toBeVisible()
        await unlockWithPassword(page, password)
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const secondSession = await readSession(page)
        expect(secondSession.userId).toBe(firstSession.userId)
        const decrypted = await runDecryptThroughUI(page, secondSession.requestKey, encrypted, 'pk2')
        expect(decrypted.decodedValue).toBe('hello world')
    } finally {
        await manager.dispose()
    }
})

test('changing the password on one passkey leaves the other on the old password until it is refreshed', async ({
    page,
}) => {
    const manager = await createPasskeyManager(page)

    try {
        // Register the first passkey with an initial password so both credentials start on the same wrapping epoch
        const firstId = await registerWithManager(page, manager, 'Multi Passkey Password Rotation')
        const oldPassword = 'hunter2'
        await page.getByLabel('Password', { exact: true }).fill(oldPassword)
        await page.getByLabel('Confirm password').fill(oldPassword)
        await page.getByRole('button', { name: 'Save password' }).click()
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()

        // Add a second passkey while the first password is still active so both passkeys initially use the same password
        const secondId = await manager.addAuthenticator({ active: false })
        await manager.setActive(secondId)
        await addPasskeyThroughSettings(page, manager, 'Second Passkey')

        // Change the password while signed in with the first passkey; that should only update this credential immediately
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, firstId)
        await expect(page.getByRole('heading', { name: 'Unlock with your password' })).toBeVisible()
        await unlockWithPassword(page, oldPassword)
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()

        const newPassword = 'hunter3'
        await setPasswordThroughSettings(page, newPassword)

        // The second passkey should still be on the old password until it logs in and refreshes its wrapper
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, secondId)
        await expect(page.getByRole('heading', { name: 'Unlock with your password' })).toBeVisible()

        await unlockWithPassword(page, newPassword)
        await expect(page.getByText('Incorrect password')).toBeVisible()
        await expect(page.getByRole('heading', { name: 'Unlock with your password' })).toBeVisible()

        await unlockWithPassword(page, oldPassword)
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const secondSession = await readSession(page)
        const encrypted = await runEncryptThroughUI(page, secondSession.requestKey, 'hello world', 'pk2-old-password')

        // The first passkey should also have moved to the new password because it was the one used to initiate the change
        await signOutThroughUI(page)
        await signInWithAuthenticator(page, manager, firstId)
        await expect(page.getByRole('heading', { name: 'Unlock with your password' })).toBeVisible()
        await unlockWithPassword(page, newPassword)
        await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible()
        const firstSession = await readSession(page)
        expect(firstSession.userId).toBe(secondSession.userId)
        const decrypted = await runDecryptThroughUI(page, firstSession.requestKey, encrypted, 'pk1-new-password')
        expect(decrypted.decodedValue).toBe('hello world')
    } finally {
        await manager.dispose()
    }
})
