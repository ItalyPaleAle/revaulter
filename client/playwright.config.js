import { defineConfig, devices } from '@playwright/test'
import process from 'node:process'

const port = 41741
const baseURL = `http://localhost:${port}`
const e2eToken = process.env.REVAULTER_E2E_TOKEN || 'playwright-e2e-token-fixed'

export default defineConfig({
    testDir: './e2e',
    fullyParallel: false,
    workers: 1,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    reporter: 'list',
    use: {
        baseURL,
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
    },
    projects: [
        {
            name: 'chromium',
            use: {
                ...devices['Desktop Chrome'],
                headless: true,
            },
        },
    ],
    webServer: {
        command: `REVAULTER_E2E_TOKEN=${e2eToken} node ./e2e/start-revaulter.mjs --port=${port}`,
        url: `${baseURL}/healthz`,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
    },
})
