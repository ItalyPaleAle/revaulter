<script lang="ts">
import { onMount } from 'svelte'

import { ResponseNotOkError } from '../lib/request'
import {
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
import {
    bytesToB64url,
    b64urlToBytes,
    computePrfSalt,
    encryptPasswordCanary,
    verifyPasswordCanary,
} from '../lib/v2-crypto'
import { webauthnLoginWithPrf, webauthnRegister } from '../lib/webauthn'
import LoadingSpinner from './LoadingSpinner.svelte'
import V2PendingItem from './V2PendingItem.svelte'

type UIState = 'boot' | 'auth' | 'password' | 'ready'

const sessionStoragePrfKey = 'revaulter:v2:prf'

let uiState = $state<UIState>('boot')
let authBusy = $state(false)
let authError = $state<string | null>(null)
let pageError = $state<string | null>(null)
let signupDisabled = $state(false)

let username = $state('')
let displayName = $state('')
let password = $state('')

let session = $state<V2SessionResponse | null>(null)
let prfSecret = $state<Uint8Array | null>(null)
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
        const cred = await webauthnRegister({
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
        if (err instanceof ResponseNotOkError && err.statusCode === 403) {
            signupDisabled = true
        }
        if (err instanceof ResponseNotOkError && err.statusCode === 409) {
            authError = err.message || 'Username already exists'
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
        const prfSalt = await computePrfSalt(b64urlToBytes(begin.basePrfSalt), password.trim() || undefined)
        const assertion = await webauthnLoginWithPrf({
            challenge: begin.challenge,
            prfSalt,
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

        // If user has a canary, verify the password is correct
        const canary = (finish as Record<string, unknown>).passwordCanary as string | undefined
        if (canary) {
            const ok = await verifyPasswordCanary(password, canary)
            if (!ok) {
                throw new Error('Incorrect password')
            }
        }
        setPrfSecret(assertion.prfSecret)
        authError = null
        if (internalCall) {
            // After first registration — prompt to set a password
            uiState = 'password'
        } else {
            uiState = 'ready'
            startListStream()
        }
    } catch (err) {
        authError = err instanceof Error ? err.message : String(err)
        if (!internalCall) {
            uiState = 'auth'
        }
    } finally {
        if (!internalCall) {
            authBusy = false
        }
    }
}

async function doSetPassword() {
    if (!prfSecret || password.trim() === '') {
        // Skip — go straight to ready
        uiState = 'ready'
        startListStream()
        return
    }
    authBusy = true
    authError = null
    try {
        // Create canary so future logins can verify the password
        const canary = await encryptPasswordCanary(password)
        await v2SetPasswordCanary(canary)
        // Re-login with the password baked into the PRF salt so prfSecret is correct
        await doLogin(true)
        if (uiState === 'password') {
            // doLogin(true) would set uiState='password' again — override to ready
            uiState = 'ready'
            startListStream()
        }
    } catch (err) {
        authError = err instanceof Error ? err.message : String(err)
    } finally {
        authBusy = false
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
            {:else if uiState === 'auth' || !prfSecret}
                <div class="space-y-4">
                    {#if authError}
                        <div class="rounded border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
                            {authError}
                        </div>
                    {/if}
                    <div class="grid gap-4 lg:grid-cols-2">
                        <form
                            class="rounded-xl border border-slate-200 dark:border-slate-700 p-4 bg-slate-50 dark:bg-slate-950/30 space-y-3"
                            onsubmit={(e) => {
                                e.preventDefault()
                                if (!authBusy) void doLogin()
                            }}
                        >
                            <div>
                                <h2 class="font-semibold text-slate-900 dark:text-white">Sign In</h2>
                                <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                                    Use your passkey to open this account on the current device/browser.
                                </p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-slate-800 dark:text-slate-200 mb-1" for="v2-password-login">Password (if set)</label>
                                <input id="v2-password-login" type="password" class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2" bind:value={password} />
                                <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">Leave empty if you haven't set a password.</p>
                            </div>
                            <button type="submit" class="w-full rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50" disabled={authBusy}>
                                {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                                Sign In with Passkey
                            </button>
                        </form>

                        <form
                            class="rounded-xl border border-slate-200 dark:border-slate-700 p-4 space-y-3"
                            onsubmit={(e) => {
                                e.preventDefault()
                                if (!authBusy && !signupDisabled) void doRegister()
                            }}
                        >
                            <div>
                                <h2 class="font-semibold text-slate-900 dark:text-white">Create Account</h2>
                                <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                                    Register a new account with a passkey. This is disabled when the server sets <span class="font-mono">disableSignup</span>.
                                </p>
                            </div>
                            {#if signupDisabled}
                                <div class="rounded border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
                                    Account creation is disabled on this server.
                                </div>
                            {/if}
                            <div>
                                <label class="block text-sm font-medium text-slate-800 dark:text-slate-200 mb-1" for="v2-username">Username</label>
                                <input id="v2-username" class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2" bind:value={username} required />
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-slate-800 dark:text-slate-200 mb-1" for="v2-displayname">Display name</label>
                                <input id="v2-displayname" class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2" bind:value={displayName} required />
                            </div>
                            <button type="submit" class="w-full rounded bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-white disabled:opacity-50" disabled={authBusy || signupDisabled}>
                                {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                                Create Account
                            </button>
                        </form>
                    </div>
                </div>
            {:else if uiState === 'password'}
                <div class="rounded-xl border border-slate-200 dark:border-slate-700 p-4 bg-slate-50 dark:bg-slate-950/30 space-y-4">
                    <div>
                        <h2 class="font-semibold text-slate-900 dark:text-white">Set a Password (Optional)</h2>
                        <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                            Optionally set a password to add a second factor for encrypt/decrypt operations. You can skip this step.
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
                            if (!authBusy) void doSetPassword()
                        }}
                    >
                        <div>
                            <label class="block text-sm font-medium text-slate-800 dark:text-slate-200 mb-1" for="v2-password">Password</label>
                            <input id="v2-password" type="password" class="w-full rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 px-3 py-2" bind:value={password} />
                        </div>
                        <div class="flex gap-2">
                            <button type="submit" class="rounded bg-sky-600 px-3 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50" disabled={authBusy}>
                                {#if authBusy}<LoadingSpinner size="1rem" />{/if}
                                Set Password and Continue
                            </button>
                            <button
                                type="button"
                                class="rounded border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm hover:bg-slate-50 dark:hover:bg-slate-800"
                                onclick={() => { uiState = 'ready'; startListStream() }}
                            >
                                Skip
                            </button>
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
