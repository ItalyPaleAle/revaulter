// Manages virtual WebAuthn authenticators in Chrome for tests that need a single passkey
// The returned object owns a CDP session that lives for the lifetime of the test
export async function createVirtualPasskey(page) {
    const manager = await createVirtualPasskeyManager(page)
    await manager.addAuthenticator()
    return {
        async dispose() {
            await manager.dispose()
        },
    }
}

// Returns a manager that can host multiple virtual authenticators on the same page
// The caller can add more authenticators on demand and toggle which one is active for ceremonies that need a specific credential
export async function createVirtualPasskeyManager(page) {
    const cdpSession = await page.context().newCDPSession(page)
    await cdpSession.send('WebAuthn.enable')

    const authenticatorIds = []

    async function addAuthenticator(options = {}) {
        // Chrome limits the environment to a single "internal" virtual authenticator, so only the first authenticator uses it
        // Subsequent authenticators default to "usb" which still supports resident keys, PRF, and user verification in the virtual authenticator
        const transport = options.transport ?? (authenticatorIds.length === 0 ? 'internal' : 'usb')
        const result = await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
            options: {
                protocol: 'ctap2',
                ctap2Version: 'ctap2_1',
                transport,
                hasResidentKey: true,
                hasUserVerification: true,
                hasPrf: true,
                isUserVerified: true,
                automaticPresenceSimulation: !!options.active,
            },
        })
        authenticatorIds.push(result.authenticatorId)
        return result.authenticatorId
    }

    // Toggles the automatic presence simulation so only the specified authenticator responds to WebAuthn ceremonies
    // All other authenticators are silenced, which in practice forces Chrome to use the active one
    async function setActive(activeId) {
        for (const id of authenticatorIds) {
            await cdpSession.send('WebAuthn.setAutomaticPresenceSimulation', {
                authenticatorId: id,
                enabled: id === activeId,
            })
        }
    }

    // Silences every authenticator so no WebAuthn call succeeds until one is explicitly reactivated
    async function silenceAll() {
        for (const id of authenticatorIds) {
            await cdpSession.send('WebAuthn.setAutomaticPresenceSimulation', {
                authenticatorId: id,
                enabled: false,
            })
        }
    }

    async function dispose() {
        try {
            for (const id of authenticatorIds) {
                // Ignore errors
                await cdpSession.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: id }).catch(() => null)
            }
        } finally {
            await cdpSession.send('WebAuthn.disable').catch(() => null)
        }
    }

    return {
        addAuthenticator,
        setActive,
        silenceAll,
        dispose,
        get authenticatorIds() {
            return [...authenticatorIds]
        },
    }
}
