import process from 'node:process'
import { defineConfig, devices } from '@playwright/test'

import { resolveBrowsers } from './e2e/browsers.mjs'

const port = 41741
const baseURL = `http://localhost:${port}`
const e2eToken = process.env.REVAULTER_E2E_TOKEN || 'playwright-e2e-token-fixed'

const browserProjects = {
    chromium: {
        name: 'chromium',
        use: {
            ...devices['Desktop Chrome'],
            headless: true,
        },
    },
    firefox: {
        name: 'firefox',
        use: {
            ...devices['Desktop Firefox'],
            headless: true,
        },
    },
    webkit: {
        name: 'webkit',
        use: {
            ...devices['Desktop Safari'],
            headless: true,
        },
        // Playwright's WebKit build surfaces only the first ~128 bytes of a streaming response body, holding the rest until the next write or until the response ends
        // A pending request arriving on the otherwise idle list stream is therefore never delivered as a whole line, so tests that wait for one to appear cannot pass here
        // This is a limitation of the test browser: the same server response streams correctly in Safari on macOS and iOS
        grepInvert: /@requeststream/,
    },
}

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
    projects: resolveBrowsers().map((name) => browserProjects[name]),
    webServer: {
        command: `REVAULTER_E2E_TOKEN=${e2eToken} node ./e2e/start-revaulter.mjs --port=${port}`,
        url: `${baseURL}/healthz`,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
    },
})
