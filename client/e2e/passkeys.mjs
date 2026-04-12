export async function createVirtualPasskey(page) {
    const cdpSession = await page.context().newCDPSession(page)
    await cdpSession.send('WebAuthn.enable')

    const existing = await cdpSession
        .send('WebAuthn.getCredentials', {
            authenticatorId: undefined,
        })
        .catch(() => null)
    if (existing && Array.isArray(existing.credentials)) {
        for (const credential of existing.credentials) {
            if (!credential.authenticatorId) {
                continue
            }

            await cdpSession
                .send('WebAuthn.removeCredential', {
                    authenticatorId: credential.authenticatorId,
                    credentialId: credential.credentialId,
                })
                .catch(() => null)
        }
    }

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
