import { installSoftwareAuthenticators } from './software-authenticator.mjs'

// Manages virtual authenticators for tests that need a passkey
// These are backed by the software authenticator in ./software-authenticator.mjs rather than Chrome's built-in virtual authenticator (which is only reachable over CDP and so only works on Chromium, plus it doesn't support any algorithm except ECDSA)
// Every engine Playwright drives runs the same passkey ceremonies this way

// Creates a page's authenticator holding a single passkey
export async function createVirtualPasskey(page, options = {}) {
    const manager = await createVirtualPasskeyManager(page)
    const authenticatorId = await manager.addAuthenticator({ ...options, active: true })
    await manager.setActive(authenticatorId)
    return {
        authenticatorId,
        async dispose() {
            await manager.dispose()
        },
    }
}

// Returns a manager that can host multiple virtual authenticators on the same page
// The caller can add more authenticators on demand and toggle which one is active for ceremonies that need a specific credential
export async function createVirtualPasskeyManager(page) {
    const set = await installSoftwareAuthenticators(page)

    // hasPrf mirrors the option Chrome's virtual authenticator took, and algorithm picks the credential algorithm the passkey is minted with
    async function addAuthenticator(options = {}) {
        const authenticator = set.add({
            algorithm: options.algorithm,
            supportsPrf: options.hasPrf ?? true,
            transports: options.transport ? [options.transport] : undefined,
            active: !!options.active,
        })
        return authenticator.id
    }

    // Makes the specified authenticator the only one that responds to WebAuthn ceremonies
    async function setActive(activeId) {
        set.setActive(activeId)
    }

    // Silences every authenticator so no WebAuthn call succeeds until one is explicitly reactivated
    async function silenceAll() {
        set.silenceAll()
    }

    async function dispose() {
        set.enabled = false
    }

    return {
        addAuthenticator,
        setActive,
        silenceAll,
        dispose,
        get authenticatorIds() {
            return set.authenticators.map((authenticator) => authenticator.id)
        },
    }
}
