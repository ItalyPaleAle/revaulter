import { spawnSync } from 'node:child_process'
import process from 'node:process'

import { resolveBrowsers } from './browsers.mjs'

// Installs only the browsers the suite is configured to run, so the default local setup does not download engines it never uses
const browsers = resolveBrowsers()
const result = spawnSync('playwright', ['install', '--with-deps', ...browsers], { stdio: 'inherit' })

if (result.error) {
    console.error(`Failed to run playwright install: ${result.error.message}`)
    process.exit(1)
}

process.exit(result.status ?? 1)
