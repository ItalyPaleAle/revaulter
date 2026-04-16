<script lang="ts">
import { onMount } from 'svelte'

import AuthAccessView from '$components/AuthAccessView.svelte'
import AuthSetupView from '$components/AuthSetupView.svelte'
import ReadyView from '$components/ReadyView.svelte'

import {
    deriveRequestEncKeyPair,
    deriveRequestEncMlkemKeyPair,
    deriveWrappingKey,
    generatePrimaryKey,
    parseWrappedPrimaryKeyEnvelope,
    unwrapPrimaryKey,
    wrapPrimaryKey,
} from '$lib/crypto'
import { ResponseNotOkError } from '$lib/request'
import { base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import {
    v2AddCredentialBegin,
    v2AddCredentialFinish,
    v2DeleteCredential,
    v2FinalizeSignup,
    v2ListCredentials,
    v2ListStream,
    v2LoginBegin,
    v2LoginFinish,
    v2Logout,
    v2RegenerateRequestKey,
    v2RegisterBegin,
    v2RegisterFinish,
    v2RenameCredential,
    v2Session,
    v2SetAllowedIPs,
    v2UpdateDisplayName,
    v2UpdateWrappedKey,
} from '$lib/v2-api'
import type { V2AuthSessionInfo, V2CredentialItem, V2PendingRequestItem, V2SessionResponse } from '$lib/v2-types'
import { webauthnLoginWithPrf, webauthnRegister } from '$lib/webauthn'

type UIState = 'boot' | 'signin' | 'signup' | 'password-login' | 'password-setup' | 'ready'

let uiState = $state<UIState>('boot')
let authBusy = $state(false)
let authError = $state<string | null>(null)
let pageError = $state<string | null>(null)
let signupDisabled = $state(false)

let displayName = $state('')
let passwordInput = $state('')
let loginWrappedPrimaryKey = $state<string | null>(null)
// The credential ID (base64url) of the currently signed-in passkey
let sessionCredentialId = $state<string | null>(null)
let sessionCredentialWrappedKeyEpoch = $state<number>(1)
let loginWrappedKeyStale = $state(false)
// The plaintext password is kept in memory while the session is active adding passkeys and the changing password can wrap new keys without re-prompting
let sessionPassword = $state<string | null>(null)
let allowedIpsText = $state('')
let settingsBusy = $state(false)
let settingsError = $state<string | null>(null)
let settingsSuccess = $state<string | null>(null)
let credentials = $state<V2CredentialItem[]>([])
let hasPassword = $state(false)

let session = $state<V2SessionResponse | null>(null)
let prfSecret = $state<Uint8Array | null>(null)
let primaryKey = $state<Uint8Array | null>(null)

let items = $state<Record<string, V2PendingRequestItem>>({})
let listConnected = $state(false)
let stopStream: (() => void) | null = null

onMount(() => {
    void initialize()
    return () => {
        teardownListStream()
    }
})

async function initialize() {
    authError = null
    pageError = null

    try {
        await v2Session()

        // Sessions survive page reloads, but the PRF secret is intentionally kept in memory only.
        clearLocalAuthState()
        authError = 'Session exists but local key material is missing. Sign in again to continue.'
        uiState = 'signin'
    } catch (err) {
        if (err instanceof ResponseNotOkError) {
            if (err.statusCode === 401) {
                uiState = 'signin'
                return
            }
        }

        pageError = err instanceof Error ? err.message : String(err)
        uiState = 'signin'
    }
}

function toSessionResponse(authSession: V2AuthSessionInfo): V2SessionResponse {
    return {
        authenticated: true,
        userId: authSession.userId,
        displayName: authSession.displayName,
        requestKey: authSession.requestKey,
        wrappedKeyEpoch: authSession.wrappedKeyEpoch,
        allowedIps: authSession.allowedIps,
        ttl: authSession.ttl,
    }
}

function setPrfSecret(v: Uint8Array) {
    prfSecret = v
}

function teardownListStream() {
    stopStream?.()
    stopStream = null
    listConnected = false
}

function clearLocalAuthState() {
    teardownListStream()
    session = null
    prfSecret = null
    primaryKey = null
    loginWrappedPrimaryKey = null
    sessionCredentialId = null
    sessionCredentialWrappedKeyEpoch = 1
    loginWrappedKeyStale = false
    sessionPassword = null
    allowedIpsText = ''
    settingsError = null
    settingsSuccess = null
}

function enterReadyView() {
    uiState = 'ready'
    passwordInput = ''
    authError = null
    settingsError = null
    settingsSuccess = null
    allowedIpsText = session?.allowedIps.join('\n') ?? ''
    startListStream()
    void doLoadCredentials()
}

function openSignIn() {
    authError = null
    passwordInput = ''
    loginWrappedPrimaryKey = null
    uiState = 'signin'
}

function openSignup() {
    authError = null
    passwordInput = ''
    loginWrappedPrimaryKey = null
    uiState = 'signup'
}

async function returnToSignIn() {
    if (session) {
        await doLogout()
        return
    }
    openSignIn()
}

function sessionLabel() {
    if (!session) {
        return ''
    }
    return session.displayName.trim() || session.userId
}

async function beginPasskeyLoginStep(): Promise<'authenticated' | 'password-required'> {
    const begin = await v2LoginBegin()
    const assertion = await webauthnLoginWithPrf({
        challenge: begin.challenge,
        prfSalt: base64UrlToBytes(begin.basePrfSalt),
        options: begin.options,
    })
    const finish = await v2LoginFinish({
        challengeId: begin.challengeId,
        credential: (assertion.raw as { credential?: unknown })?.credential ?? {
            id: assertion.id,
            signCount: assertion.signCount,
        },
    })

    if (!finish.authenticated || !finish.session) {
        throw new Error('Login did not complete')
    }
    if (!assertion.prfSecret || assertion.prfSecret.length === 0) {
        throw new Error('Authenticator did not return PRF output')
    }

    session = toSessionResponse(finish.session)
    setPrfSecret(assertion.prfSecret)
    sessionCredentialId = assertion.id
    sessionCredentialWrappedKeyEpoch = finish.credentialWrappedKeyEpoch ?? finish.session.wrappedKeyEpoch
    loginWrappedPrimaryKey = finish.wrappedPrimaryKey ?? null
    loginWrappedKeyStale = finish.wrappedKeyStale

    if (finish.wrappedPrimaryKey) {
        // Parse the envelope to determine whether a password is needed
        const envelope = parseWrappedPrimaryKeyEnvelope(finish.wrappedPrimaryKey)
        hasPassword = envelope.passwordRequired
        if (envelope.passwordRequired) {
            return 'password-required'
        }

        // No password required — unwrap immediately with PRF only
        const { wrappingKeyBytes } = await deriveWrappingKey({
            prfSecret: assertion.prfSecret,
            userId: finish.session.userId,
        })
        primaryKey = await unwrapPrimaryKey({
            wrapped: finish.wrappedPrimaryKey,
            wrappingKeyBytes,
            userId: finish.session.userId,
        })
        loginWrappedPrimaryKey = null
    } else {
        hasPassword = false
    }
    return 'authenticated'
}

async function unlockWithPassword(password: string) {
    if (!loginWrappedPrimaryKey) {
        throw new Error('Password unlock is not active')
    }
    if (!prfSecret || !session) {
        throw new Error('Missing local key material')
    }

    // Note: we are not trimming or otherwise normalizing the password as we must accept it as-is to ensure consistent key derivation
    if (password === '') {
        throw new Error('Password is required')
    }

    // Parse Argon2id params from the wrapped-key envelope
    const envelope = parseWrappedPrimaryKeyEnvelope(loginWrappedPrimaryKey)
    if (!envelope.argon2id) {
        throw new Error('Wrapped key envelope is missing Argon2id parameters')
    }

    const argon2idSalt = base64UrlToBytes(envelope.argon2id.salt)

    // Derive the wrapping key using Argon2id-stretched password as HKDF salt
    const { wrappingKeyBytes } = await deriveWrappingKey({
        prfSecret,
        userId: session.userId,
        password,
        argon2idSalt,
    })

    // Unwrap — success proves the password is correct (replaces canary)
    primaryKey = await unwrapPrimaryKey({
        wrapped: loginWrappedPrimaryKey,
        wrappingKeyBytes,
        userId: session.userId,
    })

    if (loginWrappedKeyStale) {
        const { wrappingKeyBytes: updatedWrappingKeyBytes, argon2idSalt } = await deriveWrappingKey({
            prfSecret,
            userId: session.userId,
            password,
        })

        const updatedWrapped = await wrapPrimaryKey({
            primaryKey,
            wrappingKeyBytes: updatedWrappingKeyBytes,
            userId: session.userId,
            passwordRequired: true,
            argon2idSalt,
        })

        if (!sessionCredentialId) {
            throw new Error('Missing session credential')
        }

        await v2UpdateWrappedKey(sessionCredentialId, updatedWrapped)
        sessionCredentialWrappedKeyEpoch = session.wrappedKeyEpoch
        loginWrappedKeyStale = false
    }

    loginWrappedPrimaryKey = null

    // Keep the password in memory for the rest of the session so we can re-wrap the primary key when adding new passkeys or changing credentials without re-prompting
    sessionPassword = password
}

async function doLogin() {
    authBusy = true
    authError = null
    pageError = null

    try {
        const outcome = await beginPasskeyLoginStep()
        if (outcome === 'password-required') {
            passwordInput = ''
            uiState = 'password-login'
            return
        }

        enterReadyView()
    } catch (err) {
        clearLocalAuthState()
        authError = err instanceof Error ? err.message : String(err)
        uiState = 'signin'
    } finally {
        authBusy = false
    }
}

async function doRegister() {
    authBusy = true
    authError = null
    pageError = null

    try {
        const begin = await v2RegisterBegin(displayName)
        const cred = await webauthnRegister({
            displayName,
            challenge: begin.challenge,
            options: begin.options,
        })
        await v2RegisterFinish({
            challengeId: begin.challengeId,
            credential: (cred.raw as { credential?: unknown })?.credential ?? cred,
        })

        const outcome = await beginPasskeyLoginStep()
        if (outcome === 'password-required') {
            passwordInput = ''
            uiState = 'password-login'
            return
        }

        passwordInput = ''
        uiState = 'password-setup'
    } catch (err) {
        clearLocalAuthState()
        if (err instanceof ResponseNotOkError && err.statusCode === 403) {
            signupDisabled = true
            authError = err.message || 'Account creation is disabled on this server.'
            uiState = 'signin'
        } else {
            authError = err instanceof Error ? err.message : String(err)
        }
    } finally {
        authBusy = false
    }
}

async function doFinishPasswordLogin() {
    authBusy = true
    authError = null

    try {
        await unlockWithPassword(passwordInput)
        enterReadyView()
    } catch {
        authError = 'Incorrect password'
    } finally {
        authBusy = false
    }
}

async function doSetPassword() {
    // This method can be invoked with an empty password too
    if (!prfSecret || !session) {
        clearLocalAuthState()
        authError = 'Missing local key material. Sign in again to continue.'
        uiState = 'signin'
        return
    }

    authBusy = true
    authError = null

    try {
        // Generate a random primary key
        const pk = await generatePrimaryKey()

        // Derive wrapping key (with optional Argon2id if password is set)
        const { wrappingKeyBytes, argon2idSalt } = await deriveWrappingKey({
            prfSecret,
            userId: session.userId,
            password: passwordInput || undefined,
        })

        // Wrap the primary key
        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: session.userId,
            passwordRequired: !!passwordInput,
            argon2idSalt,
        })

        // Derive request encryption keys from the primary key
        const { publicKeyJwk } = await deriveRequestEncKeyPair({
            userId: session.userId,
            primaryKey: pk,
        })
        const { encapsulationKeyB64 } = await deriveRequestEncMlkemKeyPair({
            userId: session.userId,
            primaryKey: pk,
        })

        await v2FinalizeSignup(publicKeyJwk, encapsulationKeyB64, wrapped)
        primaryKey = pk
        hasPassword = !!passwordInput

        // Remember the password used during signup so subsequent add-passkey operations can wrap the new credential with the same password
        sessionPassword = passwordInput || null
        loginWrappedPrimaryKey = null
        enterReadyView()
    } catch (err) {
        authError = err instanceof Error ? err.message : String(err)
    } finally {
        authBusy = false
    }
}

async function doLogout() {
    teardownListStream()
    try {
        await v2Logout()
    } catch {
        // Ignore logout failures and still clear the local session state.
    }

    clearLocalAuthState()
    items = {}
    passwordInput = ''
    authError = null
    uiState = 'signin'
}

const parseAllowedIpsInput = (raw: string) =>
    raw
        .split(/[\n,]/)
        .map((entry) => entry.trim())
        .filter((entry) => entry !== '')

async function doUpdateAllowedIps() {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2SetAllowedIPs(parseAllowedIpsInput(allowedIpsText))
        if (session) {
            session = { ...session, allowedIps: res.allowedIps }
        }
        allowedIpsText = res.allowedIps.join('\n')
        settingsSuccess = res.allowedIps.length === 0 ? 'Allowed IP restrictions removed' : 'Allowed IPs updated'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doRegenerateRequestKey() {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2RegenerateRequestKey()
        if (session) {
            session = { ...session, requestKey: res.requestKey }
        }
        settingsSuccess = 'Request key regenerated.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doLoadCredentials() {
    try {
        credentials = (await v2ListCredentials()) ?? []
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    }
}

async function doUpdateDisplayName(name: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2UpdateDisplayName(name)
        if (session) {
            session = { ...session, displayName: res.displayName }
        }
        settingsSuccess = 'Display name updated.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doAddPasskey(name: string) {
    if (!session || !primaryKey) {
        settingsError = 'Missing local key material'
        return
    }

    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const begin = await v2AddCredentialBegin(name)
        const cred = await webauthnRegister({
            displayName: name,
            challenge: begin.challenge,
            options: begin.options,
        })

        // The new credential has its own unique PRF secret, so we must perform a PRF assertion with the newly created credential to derive its wrapping key
        // Use a client-generated random challenge since this ceremony is only used to evaluate PRF locally and is not sent back to the server
        const prfChallenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)))
        const prfAssertion = await webauthnLoginWithPrf({
            challenge: prfChallenge,
            prfSalt: base64UrlToBytes(begin.basePrfSalt),
            options: {
                publicKey: {
                    allowCredentials: [{ type: 'public-key', id: cred.id }],
                    userVerification: 'preferred',
                },
            },
        })
        if (!prfAssertion.prfSecret || prfAssertion.prfSecret.length === 0) {
            throw new Error('Authenticator did not return PRF output for the new credential')
        }

        // Derive the wrapping key for the new credential, re-using the current session password (if any) so all passkeys added while signed in share the same password gate
        const password = sessionPassword ?? undefined
        const { wrappingKeyBytes, argon2idSalt } = await deriveWrappingKey({
            prfSecret: prfAssertion.prfSecret,
            userId: session.userId,
            password,
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey,
            wrappingKeyBytes,
            userId: session.userId,
            passwordRequired: !!password,
            argon2idSalt,
        })

        await v2AddCredentialFinish({
            challengeId: begin.challengeId,
            credential: (cred.raw as { credential?: unknown })?.credential ?? cred,
            credentialName: name,
            wrappedPrimaryKey: wrapped,
        })
        await doLoadCredentials()
        settingsSuccess = 'Passkey added.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doRenamePasskey(id: string, name: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2RenameCredential(id, name)
        await doLoadCredentials()
        settingsSuccess = 'Passkey renamed.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doDeletePasskey(id: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2DeleteCredential(id)
        await doLoadCredentials()
        settingsSuccess = 'Passkey deleted.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doChangePassword(password: string) {
    if (!prfSecret || !session || !primaryKey || !sessionCredentialId) {
        settingsError = 'Missing local key material'
        return
    }

    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const currentEpoch = session.wrappedKeyEpoch
        session = { ...session, wrappedKeyEpoch: currentEpoch + 1 }

        const { wrappingKeyBytes, argon2idSalt } = await deriveWrappingKey({
            prfSecret,
            userId: session.userId,
            password: password || undefined,
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey,
            wrappingKeyBytes,
            userId: session.userId,
            passwordRequired: !!password,
            argon2idSalt,
        })

        // The wrapped primary key lives on the specific credential that signed us in, not on the user record
        await v2UpdateWrappedKey(sessionCredentialId, wrapped)
        sessionCredentialWrappedKeyEpoch = currentEpoch + 1
        hasPassword = !!password

        // Keep the new password in memory so subsequent add-passkey calls wrap with it (or clear it when removed)
        sessionPassword = password || null
        settingsSuccess = password
            ? 'Password updated for this passkey. Other passkeys will ask to refresh on next use.'
            : 'Password removed for this passkey. Other passkeys will refresh on next use.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doRemovePassword() {
    await doChangePassword('')
}

function startListStream() {
    if (stopStream) {
        return
    }

    let stopped = false
    stopStream = () => {
        stopped = true
        stopStream = null
        listConnected = false
    }

    void (async () => {
        listConnected = false
        try {
            for await (const item of v2ListStream()) {
                if (stopped) {
                    return
                }
                listConnected = true
                if (!item) {
                    continue
                }
                if (item.status === 'removed') {
                    delete items[item.state]
                    items = { ...items }
                    continue
                }
                items = {
                    ...items,
                    [item.state]: item,
                }
            }
        } catch (err) {
            if (stopped) {
                return
            }

            const msg = err instanceof Error ? err.message : String(err)
            if (msg.includes('401')) {
                clearLocalAuthState()
                items = {}
                authError = 'Session expired. Sign in again.'
                uiState = 'signin'
                return
            }
            pageError = msg
        } finally {
            if (!stopped) {
                stopStream = null
                listConnected = false
                if (uiState === 'ready') {
                    setTimeout(() => {
                        if (uiState === 'ready' && !stopStream) {
                            startListStream()
                        }
                    }, 500)
                }
            }
        }
    })()
}

function removeItem(state: string) {
    delete items[state]
    items = { ...items }
}

function sortedItems() {
    return Object.values(items).sort((a, b) => a.date - b.date)
}
</script>

<div class="min-h-screen">
    {#if uiState === 'ready'}
        <ReadyView
            allowedIpsText={allowedIpsText}
            {credentials}
            displayName={session?.displayName ?? ''}
            {hasPassword}
            listConnected={listConnected}
            onAddPasskey={doAddPasskey}
            onAllowedIpsTextInput={(value) => {
                allowedIpsText = value
            }}
            onChangePassword={doChangePassword}
            onDeletePasskey={doDeletePasskey}
            onLogout={doLogout}
            onRegenerateRequestKey={doRegenerateRequestKey}
            onRemoveItem={removeItem}
            onRemovePassword={doRemovePassword}
            onRenamePasskey={doRenamePasskey}
            onUpdateAllowedIps={doUpdateAllowedIps}
            onUpdateDisplayName={doUpdateDisplayName}
            pageError={pageError}
            pendingItems={sortedItems()}
            {primaryKey}
            requestKey={session?.requestKey ?? ''}
            sessionLabel={sessionLabel()}
            settingsBusy={settingsBusy}
            settingsError={settingsError}
            settingsSuccess={settingsSuccess}
            userId={session?.userId ?? ''}
        />
    {:else if uiState === 'signup' || uiState === 'password-setup'}
        <AuthSetupView
            authBusy={authBusy}
            authError={authError}
            displayName={displayName}
            onDisplayNameInput={(value) => {
                displayName = value
            }}
            onPasswordInput={(value) => {
                passwordInput = value
            }}
            onRegister={doRegister}
            onReturnToSignIn={returnToSignIn}
            onSetPassword={doSetPassword}
            onSkipPassword={doSetPassword}
            pageError={pageError}
            passwordInput={passwordInput}
            uiState={uiState}
        />
    {:else}
        <AuthAccessView
            authBusy={authBusy}
            authError={authError}
            loginWrappedPrimaryKey={loginWrappedPrimaryKey}
            onFinishPasswordLogin={doFinishPasswordLogin}
            onLogin={doLogin}
            onOpenSignup={openSignup}
            onPasswordInput={(value) => {
                passwordInput = value
            }}
            onReturnToSignIn={returnToSignIn}
            pageError={pageError}
            passwordInput={passwordInput}
            sessionLabel={sessionLabel()}
            signupDisabled={signupDisabled}
            uiState={uiState}
        />
    {/if}
</div>
