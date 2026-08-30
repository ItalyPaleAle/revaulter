import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { expect, test } from '@playwright/test'

import { openSettingsTab, registerAndReachReady, resetBrowserState, resetState, waitForListStream } from './helpers.mjs'
import {
    listSshAgentKeys,
    runCLITrust,
    startLocalSshServer,
    startSshAgent,
    startSshCommand,
    stopProcess,
} from './ssh-agent-helpers.mjs'

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

test('ssh-agent serves the public key and approves SSH auth through Revaulter', { tag: '@requeststream' }, async ({
    page,
}) => {
    const auth = await registerAndReachReady(page, 'SSH Agent User')
    const tmpRoot = mkdtempSync(join(tmpdir(), 'revaulter-e2e-ssh-agent-'))
    const trustStorePath = join(tmpRoot, 'trust.json')
    const socketPath = join(tmpRoot, 'agent.sock')
    const keyLabel = 'ssh-e2e'
    let agentRun
    let serverRun
    let sshProcess

    try {
        // Create the signing key and publish it
        // Publishing attaches the anchor-signed proof the agent requires before it will advertise the key
        await openSettingsTab(page, 'Signing keys')
        await page.locator('input#signing-key-label').fill(keyLabel)
        await page.getByRole('button', { name: 'Derive key' }).click()
        await expect(page.getByText('Derived key')).toBeVisible()
        // Publish from the stored-keys row: its accessible name is unambiguous
        await page.getByRole('button', { name: 'Publish key' }).click()
        await expect(page.getByText(`Signing key "${keyLabel}" published.`)).toBeVisible()
        await page.getByRole('button', { name: 'Close settings' }).click()
        await waitForListStream(page)

        // Trust the anchor key locally
        await runCLITrust({
            requestKey: auth.session.requestKey,
            trustStorePath,
        })

        // Start the SSH agent
        agentRun = await startSshAgent({
            keyLabel,
            requestKey: auth.session.requestKey,
            socketPath,
            trustStorePath,
        })

        // List the public key which is the authorized_key
        const exportedKeys = await listSshAgentKeys(socketPath)
        expect(exportedKeys).toHaveLength(1)
        expect(exportedKeys[0]).toContain('ecdsa-sha2-nistp256')
        expect(exportedKeys[0]).toContain(`revaulter/${keyLabel}`)

        // Start a local SSH test server
        serverRun = await startLocalSshServer({
            authorizedKey: exportedKeys[0],
        })

        // Connect via SSH
        sshProcess = startSshCommand({
            address: serverRun.address,
            socketPath,
        })

        // Approve the request via Revaulter
        await expect(page.getByText('SSH auth', { exact: true })).toBeVisible()
        await expect(page.getByText(keyLabel)).toBeVisible()
        await page.getByRole('button', { name: 'Confirm' }).click()

        const sshResult = await sshProcess.done
        expect(sshResult.stdout).toContain('hello from revaulter ssh e2e')
        expect(agentRun.output().stderr).toContain('Waiting for browser confirmation')
    } finally {
        await stopProcess(sshProcess)
        await stopProcess(serverRun)
        if (serverRun) {
            serverRun.cleanup()
        }
        await stopProcess(agentRun)
        rmSync(tmpRoot, { recursive: true, force: true })
        await auth.passkey.dispose()
    }
})

test('ssh-agent refuses to advertise a signing key that has not been published', async ({ page }) => {
    // An auto-stored or merely derived key carries no anchor-signed publication proof
    // Advertising it anyway would let a compromised server hand back a key of its own, which the user would then copy into authorized_keys
    const auth = await registerAndReachReady(page, 'SSH Agent Unpublished User')
    const tmpRoot = mkdtempSync(join(tmpdir(), 'revaulter-e2e-ssh-agent-unpublished-'))
    const trustStorePath = join(tmpRoot, 'trust.json')
    const socketPath = join(tmpRoot, 'agent.sock')
    const keyLabel = 'ssh-e2e-unpublished'
    let agentRun

    try {
        // Derive the signing key but deliberately leave it unpublished
        await openSettingsTab(page, 'Signing keys')
        await page.locator('input#signing-key-label').fill(keyLabel)
        await page.getByRole('button', { name: 'Derive key' }).click()
        await expect(page.getByText('Derived key')).toBeVisible()
        await page.getByRole('button', { name: 'Close settings' }).click()
        await waitForListStream(page)

        await runCLITrust({
            requestKey: auth.session.requestKey,
            trustStorePath,
        })

        // The agent starts fine: the key is only fetched when a client asks for it
        agentRun = await startSshAgent({
            keyLabel,
            requestKey: auth.session.requestKey,
            socketPath,
            trustStorePath,
        })

        await expect(listSshAgentKeys(socketPath)).rejects.toThrow()
        expect(agentRun.output().stderr).toContain('no publication proof')
    } finally {
        await stopProcess(agentRun)
        rmSync(tmpRoot, { recursive: true, force: true })
        await auth.passkey.dispose()
    }
})
