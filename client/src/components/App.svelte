<script lang="ts">
import { onMount } from 'svelte'

import Button from '$components/Button.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'
import Modal from '$components/Modal.svelte'
import PendingItem from '$components/PendingItem.svelte'
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

function authHeadline() {
    switch (uiState) {
        case 'signup':
            return 'Create a new account'
        case 'password-login':
            return 'Unlock with your password'
        case 'password-setup':
            return 'Add a password'
        default:
            return 'Sign in with your passkey'
    }
}

function authBodyCopy() {
    switch (uiState) {
        case 'signup':
            return 'Register a new Revaulter user with a resident passkey. You can add an optional password after registration.'
        case 'password-login':
            return 'Your session is active. Enter the password to unlock local cryptographic operations in this browser.'
        case 'password-setup':
            return 'Passwords are optional. If you set one now, Revaulter will ask for it after future passkey sign-ins before unlocking local keys.'
        default:
            return ''
    }
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

<div class="min-h-screen bg-[radial-gradient(circle_at_top,rgba(14,165,233,0.12),transparent_28%),linear-gradient(180deg,#f8fafc_0%,#eef2ff_44%,#ffffff_100%)] dark:bg-[radial-gradient(circle_at_top,rgba(56,189,248,0.15),transparent_24%),linear-gradient(180deg,#020617_0%,#0f172a_48%,#020617_100%)]">
    {#if uiState === 'ready'}
        <div class="mx-auto flex min-h-screen w-full max-w-6xl flex-col gap-6 px-4 py-6 md:px-6 md:py-8">
            <header class="rounded-4xl border border-white/70 bg-white/75 p-5 shadow-[0_30px_80px_-40px_rgba(15,23,42,0.45)] backdrop-blur dark:border-slate-800 dark:bg-slate-950/70">
                <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                    <div class="space-y-3">
                        <div class="space-y-2">
                            <h1 class="font-serif text-3xl text-slate-950 dark:text-white md:text-4xl">Pending approvals</h1>
                            <p class="max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-300">
                                Review inbound encrypt and decrypt operations for <span class="font-mono text-slate-900 dark:text-slate-100">{sessionLabel()}</span>.
                            </p>
                        </div>
                    </div>

                    <div class="flex flex-col items-start gap-3 rounded-3xl border border-slate-200/80 bg-white/80 px-4 py-3 text-sm text-slate-700 shadow-sm dark:border-slate-800 dark:bg-slate-900/80 dark:text-slate-200">
                        <div>
                            Signed in as <span class="font-mono text-slate-950 dark:text-white">{sessionLabel()}</span>
                        </div>
                        <Button variant="outline" onclick={doLogout}>
                            Sign out
                        </Button>
                    </div>
                </div>
            </header>

            {#if pageError}
                <div class="rounded-3xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {pageError}
                </div>
            {/if}

            <section class="rounded-4xl border border-white/70 bg-white/80 p-5 shadow-[0_30px_80px_-40px_rgba(15,23,42,0.45)] backdrop-blur dark:border-slate-800 dark:bg-slate-950/70">
                <div class="mb-5 flex flex-col gap-3 rounded-3xl border border-slate-200/80 bg-slate-50/80 p-4 dark:border-slate-800 dark:bg-slate-900/70 md:flex-row md:items-center md:justify-between">
                    <div>
                        <div class="text-sm font-medium text-slate-900 dark:text-white">Assigned requests</div>
                        <div class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                            Requests stream to this page in real time. Confirm only if the input, key label, and requester look correct.
                        </div>
                    </div>
                    <div class="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300">
                        {#if listConnected}Live stream connected{:else}Connecting…{/if}
                    </div>
                </div>

                {#if sortedItems().length === 0}
                    <div class="rounded-3xl border border-dashed border-slate-300/90 bg-white/70 px-6 py-12 text-center dark:border-slate-700 dark:bg-slate-950/40">
                        {#if listConnected}
                            <div class="text-base font-medium text-slate-900 dark:text-white">No pending requests</div>
                            <div class="mt-2 text-sm text-slate-500 dark:text-slate-400">New approvals will appear here as soon as they are assigned to you.</div>
                        {:else}
                            <div class="flex items-center justify-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                                <LoadingSpinner size="1rem" />
                                Waiting for updates…
                            </div>
                        {/if}
                    </div>
                {:else}
                    <div class="space-y-3">
                        {#each sortedItems() as item (item.state)}
                            {#if prfSecret}
                                <PendingItem
                                    {item}
                                    {prfSecret}
                                    password={activePassword}
                                    onRemoved={removeItem}
                                />
                            {/if}
                        {/each}
                    </div>
                {/if}

                <div class="mt-5 grid gap-4 lg:grid-cols-[1.2fr_1fr]">
                    <div class="rounded-3xl border border-slate-200/80 bg-white/70 p-4 dark:border-slate-800 dark:bg-slate-950/40">
                        <div class="text-sm font-medium text-slate-900 dark:text-white">Request key</div>
                        <div class="mt-3 flex flex-col gap-3 xl:flex-row xl:items-center">
                            <div class="min-w-0 flex-1 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 font-mono text-sm text-slate-900 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100">
                                <div class="overflow-x-auto whitespace-nowrap">{session?.requestKey}</div>
                            </div>
                            <Button
                                variant="outline"
                                onclick={doRegenerateRequestKey}
                                disabled={settingsBusy}
                            >
                                Regenerate request key
                            </Button>
                        </div>
                    </div>

                    <div class="rounded-3xl border border-slate-200/80 bg-white/70 p-4 dark:border-slate-800 dark:bg-slate-950/40">
                        <div class="text-sm font-medium text-slate-900 dark:text-white">Allowed IPs</div>
                        <div class="mt-3 flex flex-col gap-3 xl:flex-row xl:items-center">
                            <p class="min-w-0 flex-1 text-sm text-slate-600 dark:text-slate-300">
                                {allowedIpsSummary()}
                            </p>
                            <Button
                                variant="neutral"
                                onclick={openAllowedIpsModal}
                                disabled={settingsBusy}
                            >
                                View allowed IPs
                            </Button>
                        </div>
                    </div>
                </div>

                {#if !allowedIpsModalOpen && settingsError}
                    <div class="mt-5 rounded-3xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                        {settingsError}
                    </div>
                {:else if !allowedIpsModalOpen && settingsSuccess}
                    <div class="mt-5 rounded-3xl border border-emerald-200 bg-emerald-50/90 px-4 py-3 text-sm text-emerald-800 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-200">
                        {settingsSuccess}
                    </div>
                {/if}
            </section>

            {#if allowedIpsModalOpen}
                <Modal
                    title="Allowed IPs"
                    ariaLabel="Close allowed IPs modal"
                    onClose={closeAllowedIpsModal}
                >
                    <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                        One IP or CIDR per line. Leave empty to allow requests from any IP.
                    </p>

                    <textarea
                        class="mt-4 min-h-40 w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 font-mono text-sm text-slate-950 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-sky-400 dark:focus:ring-sky-950"
                        bind:value={allowedIpsText}
                        disabled={settingsBusy}
                    ></textarea>

                    {#if settingsError}
                        <div class="mt-4 rounded-2xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                            {settingsError}
                        </div>
                    {:else if settingsSuccess}
                        <div class="mt-4 rounded-2xl border border-emerald-200 bg-emerald-50/90 px-4 py-3 text-sm text-emerald-800 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-200">
                            {settingsSuccess}
                        </div>
                    {/if}

                    <div class="mt-5 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
                        <Button
                            variant="outline"
                            type="button"
                            onclick={closeAllowedIpsModal}
                        >
                            Close
                        </Button>
                        <Button
                            variant="neutral"
                            type="button"
                            onclick={doUpdateAllowedIps}
                            disabled={settingsBusy}
                        >
                            Save allowed IPs
                        </Button>
                    </div>
                </Modal>
            {/if}
        </div>
    {:else}
        <div class="mx-auto flex min-h-screen w-full max-w-5xl items-center justify-center px-4 py-10 md:px-6">
            <section class="mx-auto flex w-full max-w-md flex-col items-stretch justify-center">
                <div class="rounded-4xl border border-white/80 bg-white/85 p-6 shadow-[0_35px_90px_-45px_rgba(15,23,42,0.55)] backdrop-blur dark:border-slate-800 dark:bg-slate-950/80 md:p-8">
                    <div class="mb-6 space-y-3">
                        <div class="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-500 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300 lg:hidden">
                            Revaulter v2
                        </div>
                        <div class="space-y-2">
                            <h2 class="font-serif text-3xl text-slate-950 dark:text-white">{authHeadline()}</h2>
                            {#if authBodyCopy()}
                                <p class="text-sm leading-6 text-slate-600 dark:text-slate-300">{authBodyCopy()}</p>
                            {/if}
                        </div>
                    </div>

                    {#if pageError}
                        <div class="mb-4 rounded-2xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                            {pageError}
                        </div>
                    {/if}

                    {#if authError}
                        <div class="mb-4 rounded-2xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                            {authError}
                        </div>
                    {/if}

                    {#if uiState === 'boot'}
                        <div class="flex items-center gap-3 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4 text-sm text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200">
                            <LoadingSpinner size="1rem" />
                            Initializing…
                        </div>
                    {:else if uiState === 'signup'}
                        <form
                            class="space-y-4"
                            onsubmit={(e) => {
                                e.preventDefault()
                                if (!authBusy && !signupDisabled) void doRegister()
                            }}
                        >
                            <div class="space-y-2">
                                <label class="block text-sm font-medium text-slate-800 dark:text-slate-100" for="v2-displayname">Display name (optional)</label>
                                <input
                                    id="v2-displayname"
                                    class="w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 text-slate-950 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-sky-400 dark:focus:ring-sky-950"
                                    bind:value={displayName}
                                />
                            </div>

                            <Button
                                type="submit"
                                variant="neutral"
                                size="lg"
                                width="full"
                                disabled={authBusy || signupDisabled}
                            >
                                {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                                Create account with passkey
                            </Button>
                        </form>
                    {:else if uiState === 'password-login' && loginPasswordCanary}
                        <form
                            class="space-y-4"
                            onsubmit={(e) => {
                                e.preventDefault()
                                if (!authBusy) void doFinishPasswordLogin()
                            }}
                        >
                            <div class="rounded-2xl border border-slate-200 bg-slate-50/80 px-4 py-3 text-sm text-slate-600 dark:border-slate-800 dark:bg-slate-900/80 dark:text-slate-300">
                                Unlocking local keys for <span class="font-mono text-slate-950 dark:text-white">{sessionLabel()}</span>
                            </div>

                            <div class="space-y-2">
                                <label class="block text-sm font-medium text-slate-800 dark:text-slate-100" for="v2-password-login">Password</label>
                                <input
                                    id="v2-password-login"
                                    type="password"
                                    class="w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 text-slate-950 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-sky-400 dark:focus:ring-sky-950"
                                    bind:value={passwordInput}
                                    required
                                />
                            </div>

                            <Button
                                type="submit"
                                variant="primary"
                                size="lg"
                                width="full"
                                disabled={authBusy}
                            >
                                {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                                Unlock local keys
                            </Button>
                        </form>
                    {:else if uiState === 'password-setup'}
                        <form
                            class="space-y-4"
                            onsubmit={(e) => {
                                e.preventDefault()
                                if (!authBusy) void doSetPassword()
                            }}
                        >
                            <div class="space-y-2">
                                <label class="block text-sm font-medium text-slate-800 dark:text-slate-100" for="v2-password-setup">Password</label>
                                <input
                                    id="v2-password-setup"
                                    type="password"
                                    class="w-full rounded-2xl border border-slate-300 bg-white px-4 py-3 text-slate-950 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-slate-700 dark:bg-slate-900 dark:text-white dark:focus:border-sky-400 dark:focus:ring-sky-950"
                                    bind:value={passwordInput}
                                />
                            </div>

                            <div class="flex flex-col gap-3 sm:flex-row">
                                <Button
                                    type="submit"
                                    class="flex-1"
                                    variant="primary"
                                    size="lg"
                                    disabled={authBusy}
                                >
                                    {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                                    Save password
                                </Button>
                                <Button
                                    type="button"
                                    class="flex-1"
                                    variant="outline"
                                    size="lg"
                                    onclick={() => {
                                        activePassword = ''
                                        enterReadyView()
                                    }}
                                >
                                    Skip password
                                </Button>
                            </div>
                        </form>
                    {:else}
                        <div class="space-y-4">
                            <Button
                                type="button"
                                variant="primary"
                                size="lg"
                                width="full"
                                disabled={authBusy}
                                onclick={() => {
                                    if (!authBusy) void doLogin()
                                }}
                            >
                                {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                                Continue with passkey
                            </Button>

                            {#if signupDisabled}
                                <div class="rounded-2xl border border-amber-200 bg-amber-50/90 px-4 py-3 text-sm text-amber-800 dark:border-amber-900/70 dark:bg-amber-950/40 dark:text-amber-200">
                                    Account creation is disabled on this server.
                                </div>
                            {/if}
                        </div>
                    {/if}
                </div>

                {#if uiState === 'signin' && !signupDisabled}
                    <Button
                        type="button"
                        class="mt-4"
                        variant="surface"
                        size="lg"
                        onclick={openSignup}
                    >
                        Create a new account
                    </Button>
                {:else if uiState !== 'signin'}
                    <Button
                        type="button"
                        class="mt-4"
                        variant="surface"
                        size="lg"
                        onclick={() => {
                            void returnToSignIn()
                        }}
                    >
                        Back to sign in
                    </Button>
                {/if}
            </section>
        </div>
    {/if}
</div>
