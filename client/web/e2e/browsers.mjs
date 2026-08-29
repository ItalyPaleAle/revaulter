import process from 'node:process'

// Every browser engine the E2E suite can run against
export const SUPPORTED_BROWSERS = ['chromium', 'firefox', 'webkit']

// Resolves which engines to run, from the E2E_BROWSERS environment variable
// The default is chromium alone so a local `make test-e2e` stays fast, and the other engines are opt-in
// Accepts a comma-separated list of engine names, or "all"
export function resolveBrowsers(value = process.env.E2E_BROWSERS) {
    const raw = (value ?? '').trim().toLowerCase()
    if (raw === '') {
        return ['chromium']
    }
    if (raw === 'all') {
        return [...SUPPORTED_BROWSERS]
    }

    const names = raw
        .split(',')
        .map((name) => name.trim())
        .filter((name) => name !== '')
    const unsupported = names.filter((name) => !SUPPORTED_BROWSERS.includes(name))
    if (unsupported.length > 0) {
        throw new Error(
            `Unsupported E2E_BROWSERS value ${unsupported.join(', ')}: expected "all" or a comma-separated list of ${SUPPORTED_BROWSERS.join(', ')}`
        )
    }
    if (names.length === 0) {
        return ['chromium']
    }

    // Preserve the canonical order so reports read the same however the variable was written
    return SUPPORTED_BROWSERS.filter((name) => names.includes(name))
}
