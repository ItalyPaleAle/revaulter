import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { expect, test } from '@playwright/test'

import {
    openSettingsTab,
    registerAndReachReady,
    resetBrowserState,
    resetState,
    waitForListStream,
} from './helpers.mjs'
import {
    listSshAgentKeys,
    runCLITrust,
    startCLISshAgent,
    startLocalSSHServer,
    startSSHCommand,
    stopProcess,
} from './ssh-agent-helpers.mjs'

test.beforeEach(async ({ page, request }) => {
    await resetState(request)
    await resetBrowserState(page)
})

test('ssh-agent serves the public key and approves SSH auth through Revaulter', async ({ page }) => {
    const auth = await registerAndReachReady(page, 'SSH Agent User')
    const tmpRoot = mkdtempSync(join(tmpdir(), 'revaulter-e2e-ssh-agent-'))
    const trustStorePath = join(tmpRoot, 'trust.json')
    const socketPath = join(tmpRoot, 'agent.sock')
    const keyLabel = 'ssh-e2e'
    let agentRun
    let serverRun
    let sshRun

    try {
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

        agentRun = await startCLISshAgent({
            keyLabel,
            requestKey: auth.session.requestKey,
            socketPath,
            trustStorePath,
        })

        const exportedKeys = await listSshAgentKeys(socketPath)
        expect(exportedKeys).toHaveLength(1)
        expect(exportedKeys[0]).toContain('ecdsa-sha2-nistp256')
        expect(exportedKeys[0]).toContain(`revaulter/${keyLabel}`)

        serverRun = await startLocalSSHServer({
            authorizedKey: exportedKeys[0],
        })

        sshRun = startSSHCommand({
            address: serverRun.address,
            socketPath,
        })

        await expect(page.getByText('SSH auth', { exact: true })).toBeVisible()
        await expect(page.getByText(keyLabel)).toBeVisible()
        await page.getByRole('button', { name: 'Confirm' }).click()

        const sshResult = await sshRun.done
        expect(sshResult.stdout).toContain('hello from revaulter ssh e2e')
        expect(agentRun.output().stderr).toContain('Waiting for browser confirmation')
    } finally {
        await stopProcess(sshRun)
        await stopProcess(serverRun)
        if (serverRun) {
            serverRun.cleanup()
        }
        await stopProcess(agentRun)
        rmSync(tmpRoot, { recursive: true, force: true })
        await auth.passkey.dispose()
    }
})
