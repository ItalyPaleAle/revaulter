<script lang="ts">
import { onMount } from 'svelte'

import AuthAccessView from '$components/AuthAccessView.svelte'
import AuthSetupView from '$components/AuthSetupView.svelte'
import ReadyView from '$components/ReadyView.svelte'

import { encryptPasswordCanary, verifyPasswordCanary } from '$lib/crypto'
import { ResponseNotOkError } from '$lib/request'
import { base64UrlToBytes } from '$lib/utils'
import {
    v2ListStream,
    v2LoginBegin,
    v2LoginFinish,
    v2Logout,
    v2RegenerateRequestKey,
    v2RegisterBegin,
    v2RegisterFinish,
    v2SetAllowedIPs,
    v2Session,
    v2SetPasswordCanary,
} from '$lib/v2-api'
import type { V2AuthSessionInfo, V2PendingRequestItem, V2SessionResponse } from '$lib/v2-types'
import { webauthnLoginWithPrf, webauthnRegister } from '$lib/webauthn'

type UIState = 'boot' | 'signin' | 'signup' | 'password-login' | 'password-setup' | 'ready'

let uiState = $state<UIState>('boot')
let authBusy = $state(false)
let authError = $state<string | null>(null)
let pageError = $state<string | null>(null)
let signupDisabled = $state(false)

let displayName = $state('')
let passwordInput = $state('')
let activePassword = $state('')
let loginPasswordCanary = $state<string | null>(null)
let allowedIpsText = $state('')
let settingsBusy = $state(false)
let settingsError = $state<string | null>(null)
let settingsSuccess = $state<string | null>(null)
let allowedIpsModalOpen = $state(false)

let session = $state<V2SessionResponse | null>(null)
let prfSecret = $state<Uint8Array | null>(null)

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
    activePassword = ''
    loginPasswordCanary = null
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
}

function openSignIn() {
    authError = null
    passwordInput = ''
    loginPasswordCanary = null
    uiState = 'signin'
}

function openSignup() {
    authError = null
    passwordInput = ''
    loginPasswordCanary = null
    uiState = 'signup'
}

function openAllowedIpsModal() {
    settingsError = null
    settingsSuccess = null
    allowedIpsModalOpen = true
}

function closeAllowedIpsModal() {
    settingsError = null
    settingsSuccess = null
    allowedIpsModalOpen = false
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
    activePassword = ''
    loginPasswordCanary = finish.passwordCanary ?? null

    if (finish.passwordCanary) {
        return 'password-required'
    }
    return 'authenticated'
}

async function unlockWithPassword(password: string) {
    const trimmedPassword = password.trim()
    if (!loginPasswordCanary) {
        throw new Error('Password unlock is not active')
    }
    if (trimmedPassword === '') {
        throw new Error('Password is required')
    }

    const passwordMatches = await verifyPasswordCanary(trimmedPassword, loginPasswordCanary)
    if (!passwordMatches) {
        throw new Error('Incorrect password')
    }

    activePassword = trimmedPassword
    loginPasswordCanary = null
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
    } catch (err) {
        authError = err instanceof Error ? err.message : String(err)
    } finally {
        authBusy = false
    }
}

async function doSetPassword() {
    const trimmedPassword = passwordInput.trim()

    if (!prfSecret) {
        clearLocalAuthState()
        authError = 'Missing local key material. Sign in again to continue.'
        uiState = 'signin'
        return
    }

    if (trimmedPassword === '') {
        activePassword = ''
        enterReadyView()
        return
    }

    authBusy = true
    authError = null

    try {
        const canary = await encryptPasswordCanary(trimmedPassword)
        await v2SetPasswordCanary(canary)
        activePassword = trimmedPassword
        loginPasswordCanary = null
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

function allowedIpsSummary() {
    const count = session?.allowedIps.length ?? 0
    if (count === 0) {
        return 'No IP restrictions configured'
    }
    if (count === 1) {
        return '1 allowed IP configured'
    }
    return `${count} allowed IPs configured`
}
</script>

<div class="min-h-screen">
    {#if uiState === 'ready'}
        <ReadyView
            activePassword={activePassword}
            allowedIpsModalOpen={allowedIpsModalOpen}
            allowedIpsSummary={allowedIpsSummary()}
            allowedIpsText={allowedIpsText}
            listConnected={listConnected}
            onAllowedIpsTextInput={(value) => {
                allowedIpsText = value
            }}
            onCloseAllowedIpsModal={closeAllowedIpsModal}
            onLogout={doLogout}
            onOpenAllowedIpsModal={openAllowedIpsModal}
            onRegenerateRequestKey={doRegenerateRequestKey}
            onRemoveItem={removeItem}
            onUpdateAllowedIps={doUpdateAllowedIps}
            pageError={pageError}
            pendingItems={sortedItems()}
            {prfSecret}
            requestKey={session?.requestKey ?? ''}
            sessionLabel={sessionLabel()}
            settingsBusy={settingsBusy}
            settingsError={settingsError}
            settingsSuccess={settingsSuccess}
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
            onSkipPassword={() => {
                activePassword = ''
                enterReadyView()
            }}
            pageError={pageError}
            passwordInput={passwordInput}
            uiState={uiState}
        />
    {:else}
        <AuthAccessView
            authBusy={authBusy}
            authError={authError}
            loginPasswordCanary={loginPasswordCanary}
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
