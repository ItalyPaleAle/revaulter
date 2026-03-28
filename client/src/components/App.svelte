<script lang="ts">
import { onMount } from 'svelte'

import { ResponseNotOkError } from '../lib/request'
import {
    v2AdminRegisterBegin,
    v2AdminRegisterFinish,
    v2AuthStatus,
    v2ListStream,
    v2LoginBegin,
    v2LoginFinish,
    v2Logout,
    v2RegisterBegin,
    v2RegisterFinish,
    v2Session,
    v2SetPasswordCanary,
} from '../lib/v2-api'
import type { V2PendingRequestItem, V2SessionResponse } from '../lib/v2-types'
import { bytesToB64url, b64urlToBytes, encryptPasswordCanary, verifyPasswordCanary } from '../lib/v2-crypto'
import { webauthnLoginWithPrfPlaceholder, webauthnRegisterPlaceholder } from '../lib/v2-webauthn'
import LoadingSpinner from './LoadingSpinner.svelte'
import V2PendingItem from './V2PendingItem.svelte'

type UIState = 'boot' | 'auth' | 'setup' | 'password' | 'ready'

const sessionStoragePrfKey = 'revaulter:v2:prf'

let uiState = $state<UIState>('boot')
let authBusy = $state(false)
let authError = $state<string | null>(null)
let pageError = $state<string | null>(null)

let username = $state('')
let displayName = $state('')
let password = $state('')
let newAdminUsername = $state('')
let newAdminDisplayName = $state('')
let newAdminBusy = $state(false)
let newAdminError = $state<string | null>(null)
let newAdminSuccess = $state<string | null>(null)

let session = $state<V2SessionResponse | null>(null)
let prfSecret = $state<Uint8Array | null>(null)
let pendingCanary = $state<string | null>(null)
let items = $state<Record<string, V2PendingRequestItem>>({})
let listConnected = $state(false)
let stopStream: (() => void) | null = null

onMount(() => {
    void initialize()
    return () => {
        stopStream?.()
        stopStream = null
    }
})

async function initialize() {
    authError = null
    pageError = null

    try {
        const status = await v2AuthStatus()
        if (status.setupNeeded) {
            uiState = 'setup'
            return
        }
    } catch {
        // If status check fails, continue with normal session flow
    }

    try {
        const sess = await v2Session()
        session = sess
        const stored = sessionStorage.getItem(sessionStoragePrfKey)
        if (stored) {
            prfSecret = b64urlToBytes(stored)
            uiState = 'ready'
            startListStream()
            return
        }
        uiState = 'auth'
        authError = 'Session exists but local PRF material is missing. Sign in again to continue.'
    } catch (err) {
        if (err instanceof ResponseNotOkError) {
            if (err.statusCode === 401) {
                uiState = 'auth'
                return
            }
            if (err.statusCode === 503) {
                pageError = 'v2 is not configured on this server.'
                uiState = 'auth'
                return
            }
        }
        pageError = err instanceof Error ? err.message : String(err)
        uiState = 'auth'
    }
}

function setPrfSecret(v: Uint8Array) {
    prfSecret = v
    sessionStorage.setItem(sessionStoragePrfKey, bytesToB64url(v))
}

async function doRegister() {
    authBusy = true
    authError = null
    pageError = null
    try {
        const begin = await v2RegisterBegin(username, displayName)
        const cred = await webauthnRegisterPlaceholder({
            username: begin.username,
            displayName: begin.displayName,
            challenge: begin.challenge,
            options: begin.options,
        })
        await v2RegisterFinish({
            username: begin.username,
            displayName: begin.displayName,
            challengeId: begin.challengeId,
            credential: (cred.raw as { credential?: unknown })?.credential ?? cred,
        })
        // Re-login to collect PRF material (registration attestation does not yield PRF output).
        await doLogin(true)
    } catch (err) {
        if (err instanceof ResponseNotOkError && err.statusCode === 409) {
            authError = err.message || 'Registration is closed; use login'
        } else {
            authError = err instanceof Error ? err.message : String(err)
        }
    } finally {
        authBusy = false
    }
}

async function doLogin(internalCall = false) {
    if (!internalCall) {
        authBusy = true
        authError = null
    }
    try {
        const begin = await v2LoginBegin()
        const assertion = await webauthnLoginWithPrfPlaceholder({
            challenge: begin.challenge,
            prfSalt: begin.prfSalt ? b64urlToBytes(begin.prfSalt) : undefined,
            options: begin.options,
        })
        const finish = await v2LoginFinish({
            challengeId: begin.challengeId,
            credential: (assertion.raw as { credential?: unknown })?.credential ?? {
                id: assertion.id,
                signCount: assertion.signCount,
            },
        })
        session = finish.session
        if (!assertion.prfSecret || assertion.prfSecret.length === 0) {
            throw new Error('Authenticator did not return PRF output')
        }
        setPrfSecret(assertion.prfSecret)
        authError = null
        const canary = (finish as Record<string, unknown>).passwordCanary as string | undefined
        if (canary) {
            pendingCanary = canary
            uiState = 'password'
        } else if (internalCall) {
            // First registration — prompt to set a password
            uiState = 'password'
        } else {
            uiState = 'ready'
            startListStream()
        }
    } catch (err) {
        authError = err instanceof Error ? err.message : String(err)
        uiState = 'auth'
    } finally {
        if (!internalCall) {
            authBusy = false
        }
    }
}

async function doPasswordVerify() {
    if (!prfSecret) {
        return
    }
    authBusy = true
    authError = null
    try {
        if (pendingCanary) {
            // Verify existing canary
            const ok = await verifyPasswordCanary(prfSecret, password, pendingCanary)
            if (!ok) {
                authError = 'Incorrect password.'
                return
            }
        } else if (password.trim() !== '') {
            // First time setting a password — create and store canary
            const canary = await encryptPasswordCanary(prfSecret, password)
            await v2SetPasswordCanary(canary)
        }
        pendingCanary = null
        uiState = 'ready'
        startListStream()
    } catch (err) {
        authError = err instanceof Error ? err.message : String(err)
    } finally {
        authBusy = false
        // Reset the password in the UI
        password = ''
    }
}

async function doLogout() {
    stopStream?.()
    stopStream = null
    try {
        await v2Logout()
    } catch {
        // Ignore and clear local state anyway.
    }
    sessionStorage.removeItem(sessionStoragePrfKey)
    session = null
    prfSecret = null
    items = {}
    listConnected = false
    uiState = 'auth'
}

async function doAdminRegister() {
    newAdminBusy = true
    newAdminError = null
    newAdminSuccess = null
    try {
        const begin = await v2AdminRegisterBegin(newAdminUsername, newAdminDisplayName)
        const cred = await webauthnRegisterPlaceholder({
            username: begin.username,
            displayName: begin.displayName,
            challenge: begin.challenge,
            options: begin.options,
        })
        const finish = await v2AdminRegisterFinish({
            username: begin.username,
            displayName: begin.displayName,
            challengeId: begin.challengeId,
            credential: (cred.raw as { credential?: unknown })?.credential ?? cred,
        })
        if (!finish.registered) {
            throw new Error('Admin registration failed')
        }
        newAdminSuccess = `Admin ${finish.username} registered`
        newAdminUsername = ''
        newAdminDisplayName = ''
    } catch (err) {
        newAdminError = err instanceof Error ? err.message : String(err)
    } finally {
        newAdminBusy = false
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
                sessionStorage.removeItem(sessionStoragePrfKey)
                prfSecret = null
                session = null
                uiState = 'auth'

                authError = 'Session expired. Sign in again.'
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

<div class="max-w-5xl mx-auto p-4 md:p-6">
    <div class="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/90 dark:bg-slate-900/70 shadow-sm">
        <div class="border-b border-slate-200 dark:border-slate-700 px-5 py-4 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div>
                <h1 class="text-xl font-semibold text-slate-900 dark:text-white">Revaulter v2</h1>
                <p class="text-sm text-slate-600 dark:text-slate-300">WebAuthn + browser crypto confirmation console</p>
            </div>
            {#if session}
                <div class="flex flex-col items-start gap-2 md:items-end">
                    <div class="text-sm text-slate-700 dark:text-slate-200">
                        Signed in as <span class="font-mono">{session.username}</span>
                    </div>
                    <button class="rounded border border-slate-300 dark:border-slate-600 px-3 py-1.5 text-sm hover:bg-slate-50 dark:hover:bg-slate-800" onclick={doLogout}>
                        Sign out
                    </button>
                </div>
            {/if}
        </div>

        <div class="p-5 space-y-4">
            {#if pageError}
                <div class="rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
                    {pageError}
                </div>
            {/if}

            {#if uiState === 'boot'}
                <div class="text-sm text-slate-700 dark:text-slate-200"><LoadingSpinner /> Initializing…</div>
            {:else if uiState === 'setup'}
                <div class="grid gap-4 lg:grid-cols-[1fr_1.1fr]">
                    <div class="rounded-xl border border-slate-200 dark:border-slate-700 p-4 bg-slate-50 dark:bg-slate-950/30">
                        <h2 class="font-semibold text-slate-900 dark:text-white">Initial Setup</h2>
                        <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                            Register the first admin account. You will need a passkey-capable authenticator (e.g. Touch ID, Windows Hello, or a security key).
                        </p>
                        {#if authError}
                            <div class="mt-4 rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
                                {authError}
                            </div>
                        {/if}
                    </div>

                    <form
                        class="rounded-xl border border-slate-200 dark:border-slate-700 p-4 space-y-3"
                        onsubmit={(e) => {
                            e.preventDefault()
                            if (!authBusy) void doRegister()
                        }}
                    >
                        <div>
                            <label class="block text-sm font-medium text-slate-800 dark:text-slate-200 mb-1" for="v2-username">Username</label>
                            <input id="v2-username" class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2" bind:value={username} required />
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-slate-800 dark:text-slate-200 mb-1" for="v2-displayname">Display name</label>
                            <input id="v2-displayname" class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2" bind:value={displayName} required />
                        </div>
                        <button type="submit" class="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50" disabled={authBusy}>
                            {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                            Register and Sign In
                        </button>
                    </form>
                </div>
            {:else if uiState === 'auth' || !prfSecret}
                <div class="rounded-xl border border-slate-200 dark:border-slate-700 p-4 bg-slate-50 dark:bg-slate-950/30 space-y-4">
                    <div>
                        <h2 class="font-semibold text-slate-900 dark:text-white">Admin Session</h2>
                        <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                            Sign in with your passkey to continue.
                        </p>
                    </div>
                    {#if authError}
                        <div class="rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
                            {authError}
                        </div>
                    {/if}
                    <button
                        type="button"
                        class="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
                        disabled={authBusy}
                        onclick={() => { if (!authBusy) void doLogin() }}
                    >
                        {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                        Sign In with Passkey
                    </button>
                </div>
            {:else if uiState === 'password'}
                <div class="rounded-xl border border-slate-200 dark:border-slate-700 p-4 bg-slate-50 dark:bg-slate-950/30 space-y-4">
                    <div>
                        <h2 class="font-semibold text-slate-900 dark:text-white">
                            {pendingCanary ? 'Enter Password' : 'Set a Password (Optional)'}
                        </h2>
                        <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                            {#if pendingCanary}
                                Enter your password to unlock operations.
                            {:else}
                                Optionally set a password to add a second factor for encrypt/decrypt operations. You can skip this step.
                            {/if}
                        </p>
                    </div>
                    {#if authError}
                        <div class="rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
                            {authError}
                        </div>
                    {/if}
                    <form
                        class="space-y-3"
                        onsubmit={(e) => {
                            e.preventDefault()
                            if (!authBusy) {
                                doPasswordVerify()
                            }
                        }}
                    >
                        <div>
                            <label class="block text-sm font-medium text-slate-800 dark:text-slate-200 mb-1" for="v2-password">Password</label>
                            <input id="v2-password" type="password" class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2" bind:value={password} />
                        </div>
                        <div class="flex gap-2">
                            <button type="submit" class="rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50" disabled={authBusy}>
                                {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                                {pendingCanary ? 'Unlock' : 'Set Password'}
                            </button>
                            {#if !pendingCanary}
                                <button
                                    type="button"
                                    class="rounded border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm hover:bg-slate-50 dark:hover:bg-slate-800"
                                    onclick={() => { uiState = 'ready'; startListStream() }}
                                >
                                    Skip
                                </button>
                            {/if}
                        </div>
                    </form>
                </div>
            {:else}
                <div class="space-y-4">
                    <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between rounded-xl border border-slate-200 dark:border-slate-700 p-3">
                        <div class="text-sm text-slate-700 dark:text-slate-200">
                            Pending requests for <span class="font-mono">{session?.username}</span>
                        </div>
                        <div class="text-xs text-slate-500 dark:text-slate-400">
                            {#if listConnected}Live stream connected{:else}Connecting…{/if}
                        </div>
                    </div>

                    <form
                        class="rounded-xl border border-slate-200 dark:border-slate-700 p-4 space-y-3"
                        onsubmit={(e) => {
                            e.preventDefault()
                            if (!newAdminBusy) void doAdminRegister()
                        }}
                    >
                        <div class="flex items-center justify-between gap-3">
                            <div>
                                <h2 class="text-sm font-semibold text-slate-900 dark:text-white">Register Additional Admin</h2>
                                <p class="text-xs text-slate-500 dark:text-slate-400">Creates another admin account using a new WebAuthn credential on this device/browser.</p>
                            </div>
                        </div>
                        {#if newAdminError}
                            <div class="rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
                                {newAdminError}
                            </div>
                        {/if}
                        {#if newAdminSuccess}
                            <div class="rounded border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200">
                                {newAdminSuccess}
                            </div>
                        {/if}
                        <div class="grid gap-3 md:grid-cols-2">
                            <div>
                                <label class="block text-sm font-medium text-slate-800 dark:text-slate-200 mb-1" for="v2-new-admin-username">Username</label>
                                <input id="v2-new-admin-username" class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2" bind:value={newAdminUsername} required />
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-slate-800 dark:text-slate-200 mb-1" for="v2-new-admin-displayname">Display name</label>
                                <input id="v2-new-admin-displayname" class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2" bind:value={newAdminDisplayName} required />
                            </div>
                        </div>
                        <div class="flex justify-end">
                            <button type="submit" class="rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-white disabled:opacity-50" disabled={newAdminBusy}>
                                {#if newAdminBusy}<LoadingSpinner size="1rem" />{/if}
                                Register Admin
                            </button>
                        </div>
                    </form>

                    {#if sortedItems().length === 0}
                        <div class="rounded-xl border border-slate-200 dark:border-slate-700 p-6 text-sm text-slate-600 dark:text-slate-300">
                            {#if listConnected}
                                No pending requests assigned to you.
                            {:else}
                                <LoadingSpinner size="1rem" /> Waiting for updates…
                            {/if}
                        </div>
                    {:else}
                        <div class="space-y-3">
                            {#each sortedItems() as item (item.state)}
                                <V2PendingItem
                                    {item}
                                    {prfSecret}
                                    {password}
                                    onRemoved={removeItem}
                                />
                            {/each}
                        </div>
                    {/if}
                </div>
            {/if}
        </div>
    </div>
</div>
