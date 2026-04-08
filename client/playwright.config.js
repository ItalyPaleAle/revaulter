import { defineConfig, devices } from '@playwright/test'

const port = 41741
const baseURL = `http://localhost:${port}`

export default defineConfig({
    testDir: './e2e',
    fullyParallel: false,
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
        command: `node ./e2e/start-revaulter.mjs --port=${port}`,
        url: `${baseURL}/healthz`,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
    },
})
