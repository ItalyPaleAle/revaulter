export async function createVirtualPasskey(page) {
    const cdpSession = await page.context().newCDPSession(page)
    await cdpSession.send('WebAuthn.enable')

    const result = await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: 'ctap2',
            ctap2Version: 'ctap2_1',
            transport: 'internal',
            hasResidentKey: true,
            hasUserVerification: true,
            hasPrf: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    })
    const authenticatorId = result.authenticatorId

    return {
        async dispose() {
            try {
                await cdpSession.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId })
            } finally {
                await cdpSession.send('WebAuthn.disable')
            }
        },
    }
}
