<script lang="ts">
import { formatDistanceToNowStrict } from 'date-fns'

import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import TextField from '$components/TextField.svelte'

import type { DerivedSigningKey, V2CredentialItem, V2PublishedSigningKey } from '$lib/v2-types'

type SettingsTab = 'user' | 'ip-restrictions' | 'password' | 'passkeys' | 'signing-keys'

interface Props {
    userId: string
    displayName: string
    requestKey: string
    allowedIpsText: string
    hasPassword: boolean
    credentials: V2CredentialItem[]
    signingKeys: V2PublishedSigningKey[]
    busy: boolean
    error: string | null
    success: string | null
    onClose: () => void
    onUpdateDisplayName: (name: string) => Promise<void>
    onRegenerateRequestKey: () => Promise<void>
    onAllowedIpsTextInput: (value: string) => void
    onUpdateAllowedIps: () => Promise<void>
    onChangePassword: (password: string) => Promise<void>
    onRemovePassword: () => Promise<void>
    onAddPasskey: (name: string) => Promise<void>
    onRenamePasskey: (id: string, name: string) => Promise<void>
    onDeletePasskey: (id: string) => Promise<void>
    onDeriveSigningKey: (keyLabel: string, algorithm: string) => Promise<DerivedSigningKey>
    onPublishSigningKey: (derived: DerivedSigningKey) => Promise<void>
    onUnpublishSigningKey: (id: string) => Promise<void>
    onDeleteSigningKey: (id: string) => Promise<void>
}

let {
    userId,
    displayName,
    requestKey,
    allowedIpsText,
    hasPassword,
    credentials,
    signingKeys,
    busy,
    error,
    success,
    onClose,
    onUpdateDisplayName,
    onRegenerateRequestKey,
    onAllowedIpsTextInput,
    onUpdateAllowedIps,
    onChangePassword,
    onRemovePassword,
    onAddPasskey,
    onRenamePasskey,
    onDeletePasskey,
    onDeriveSigningKey,
    onPublishSigningKey,
    onUnpublishSigningKey,
    onDeleteSigningKey,
}: Props = $props()

let activeTab = $state<SettingsTab>('user')

let editingDisplayName = $state(false)
let editDisplayNameValue = $state('')
let copied = $state(false)
let confirmingRegenerate = $state(false)

let passwordInput = $state('')
let passwordConfirm = $state('')
let passwordError = $state<string | null>(null)

let confirmingRemovePassword = $state(false)

let renamingCredentialId = $state<string | null>(null)
let renameValue = $state('')
let addPasskeyName = $state('')
let showAddPasskey = $state(false)

const SIGNING_ALGORITHMS = ['ES256'] as const
let derivingKey = $state(false)
let deriveLabel = $state('')
let deriveAlgorithm = $state<string>(SIGNING_ALGORITHMS[0])
let derivedKey = $state<DerivedSigningKey | null>(null)
let deriveError = $state<string | null>(null)
let copiedFetchId = $state<string | null>(null)
let confirmingDeleteId = $state<string | null>(null)
let publishingStoredId = $state<string | null>(null)

$effect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
        if (event.key === 'Escape') {
            onClose()
        }
    }

    document.addEventListener('keydown', handleKeyDown)

    return () => {
        document.removeEventListener('keydown', handleKeyDown)
    }
})

function setActiveTab(val: SettingsTab) {
    activeTab = val
    error = null
    success = null
}

function copyRequestKey() {
    navigator.clipboard.writeText(requestKey).then(() => {
        copied = true
        setTimeout(() => {
            copied = false
        }, 2000)
    })
}

function promptRegenerate() {
    confirmingRegenerate = true
}

function cancelRegenerate() {
    confirmingRegenerate = false
}

async function handleRegenerate() {
    confirmingRegenerate = false
    await onRegenerateRequestKey()
}

function startEditDisplayName() {
    editDisplayNameValue = displayName
    editingDisplayName = true
}

function cancelEditDisplayName() {
    editingDisplayName = false
}

async function saveDisplayName() {
    await onUpdateDisplayName(editDisplayNameValue)
    editingDisplayName = false
}

async function handleChangePassword() {
    passwordError = null
    if (passwordInput === '') {
        passwordError = 'Password is required'
        return
    }
    if (passwordInput !== passwordConfirm) {
        passwordError = 'Passwords do not match'
        return
    }
    await onChangePassword(passwordInput)
    passwordInput = ''
    passwordConfirm = ''
}

function promptRemovePassword() {
    confirmingRemovePassword = true
}

function cancelRemovePassword() {
    confirmingRemovePassword = false
}

async function handleRemovePassword() {
    confirmingRemovePassword = false
    await onRemovePassword()
}

function startRenameCredential(id: string, currentName: string) {
    renamingCredentialId = id
    renameValue = currentName
}

function cancelRenameCredential() {
    renamingCredentialId = null
}

async function saveRenameCredential(id: string) {
    await onRenamePasskey(id, renameValue)
    renamingCredentialId = null
}

async function handleAddPasskey() {
    await onAddPasskey(addPasskeyName)
    addPasskeyName = ''
    showAddPasskey = false
}

function formatTimestamp(value: number | string): string {
    if (!value) {
        return 'Never'
    }

    const date = typeof value === 'string' ? new Date(value) : new Date(value * 1000)
    if (Number.isNaN(date.getTime())) {
        return 'Never'
    }

    return formatDistanceToNowStrict(date, { addSuffix: true })
}

function shortenId(id: string): string {
    if (id.length <= 16) {
        return id
    }
    return `${id.slice(0, 8)}…${id.slice(-8)}`
}

function publicFetchUrl(id: string, kind: 'jwk' | 'pem'): string {
    const origin = typeof window !== 'undefined' ? window.location.origin : ''
    return `${origin}/v2/signing-keys/${id}.${kind}`
}

function triggerDownload(filename: string, contents: string, mimeType: string) {
    const blob = new Blob([contents], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    setTimeout(() => URL.revokeObjectURL(url), 2000)
}

async function handleDeriveSigningKey() {
    deriveError = null
    if (deriveLabel.trim() === '') {
        deriveError = 'Key label is required'
        return
    }

    derivingKey = true
    try {
        derivedKey = await onDeriveSigningKey(deriveLabel.trim(), deriveAlgorithm)
    } catch (err) {
        deriveError = err instanceof Error ? err.message : String(err)
        derivedKey = null
    } finally {
        derivingKey = false
    }
}

function downloadDerivedJwk() {
    if (!derivedKey) {
        return
    }

    triggerDownload(
        `${derivedKey.keyLabel}-${derivedKey.algorithm}.jwk.json`,
        JSON.stringify(derivedKey.jwk, null, 2),
        'application/json'
    )
}

function downloadDerivedPem() {
    if (!derivedKey) {
        return
    }
    triggerDownload(`${derivedKey.keyLabel}-${derivedKey.algorithm}.pem`, derivedKey.pem, 'application/x-pem-file')
}

async function handlePublishDerived() {
    if (!derivedKey) {
        return
    }
    await onPublishSigningKey(derivedKey)
}

async function handleUnpublish(id: string) {
    await onUnpublishSigningKey(id)
}

async function handleDelete(id: string) {
    confirmingDeleteId = null
    await onDeleteSigningKey(id)
}

async function handlePublishStored(sk: V2PublishedSigningKey) {
    publishingStoredId = sk.id
    try {
        const derived = await onDeriveSigningKey(sk.keyLabel, sk.algorithm)
        await onPublishSigningKey(derived)
    } finally {
        publishingStoredId = null
    }
}

async function copyFetchUrl(id: string, kind: 'jwk' | 'pem') {
    await navigator.clipboard.writeText(publicFetchUrl(id, kind))
    copiedFetchId = `${id}/${kind}`
    setTimeout(() => {
        if (copiedFetchId === `${id}/${kind}`) {
            copiedFetchId = null
        }
    }, 2000)
}

function isDerivedPublished(): boolean {
    if (!derivedKey) {
        return false
    }
    return signingKeys.some((k) => k.id === derivedKey?.id && k.published)
}

const tabs: { id: SettingsTab; label: string; icon: string }[] = [
    { id: 'user', label: 'User', icon: 'user' },
    { id: 'ip-restrictions', label: 'IP', icon: 'shield' },
    { id: 'password', label: 'Password', icon: 'lock-closed' },
    { id: 'passkeys', label: 'Passkeys', icon: 'fingerprint' },
    { id: 'signing-keys', label: 'Signing keys', icon: 'lock-keyhole' },
]
</script>

<div class="fixed inset-0 z-40 bg-neutral-950/50 backdrop-blur-sm"></div>
<section class="fixed inset-0 z-50 flex items-center justify-center px-4 py-6">
    <div class="flex max-h-[88vh] w-full max-w-180 flex-col overflow-hidden rounded-2xl border border-neutral-200 bg-white shadow-2xl dark:border-neutral-800 dark:bg-neutral-900">
        <!-- Header -->
        <div class="flex items-center justify-between gap-4 border-b border-neutral-200 px-5 py-4 dark:border-neutral-800">
            <div class="flex items-center gap-2 text-sm font-semibold text-neutral-900 dark:text-neutral-50">
                <Icon icon="settings" title="Settings" size="4" />
                Settings
            </div>
            <Button
                variant="icon"
                size="icon"
                ariaLabel="Close settings"
                onclick={onClose}
            >
                <Icon icon="x" title="Close" size="4" />
            </Button>
        </div>

        <!-- Horizontal tabs -->
        <nav class="flex shrink-0 gap-1 overflow-x-auto border-b border-neutral-200 px-3 py-2 dark:border-neutral-800">
            {#each tabs as tab}
                <button
                    type="button"
                    class="flex cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-[13px] font-medium transition {activeTab === tab.id ? 'bg-neutral-100 text-neutral-900 dark:bg-neutral-800 dark:text-neutral-50' : 'text-neutral-500 hover:bg-neutral-50 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-800/60 dark:hover:text-neutral-50'}"
                    onclick={() => setActiveTab(tab.id)}
                >
                    <Icon icon={tab.icon} title={tab.label} size="3.5" />
                    {tab.label}
                </button>
            {/each}
        </nav>

        <!-- Content area -->
        <div class="flex-1 overflow-y-auto px-5 py-5">
            {#if activeTab === 'user'}
                <!-- User tab -->
                <div class="space-y-6">
                    <!-- Display name -->
                    <div class="space-y-2">
                        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Display name</div>
                        {#if editingDisplayName}
                            <div class="flex items-center gap-2">
                                <div class="flex-1">
                                    <TextField
                                        type="text"
                                        placeholder="Display name"
                                        bind:value={editDisplayNameValue}
                                        disabled={busy}
                                    />
                                </div>
                                <Button variant="primary" onclick={saveDisplayName} disabled={busy}>Save</Button>
                                <Button variant="secondary" onclick={cancelEditDisplayName}>Cancel</Button>
                            </div>
                        {:else}
                            <div class="flex items-center gap-2">
                                <span class="text-sm text-neutral-700 dark:text-neutral-300">{displayName || userId}</span>
                                <Button variant="icon" size="icon" ariaLabel="Edit display name" onclick={startEditDisplayName}>
                                    <Icon icon="pencil" title="Edit" size="3.5" />
                                </Button>
                            </div>
                        {/if}
                    </div>

                    <!-- User ID -->
                    <div class="space-y-2">
                        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">User ID</div>
                        <div class="mono text-sm text-neutral-600 dark:text-neutral-400">{userId}</div>
                    </div>

                    <!-- Request key -->
                    <div class="space-y-2">
                        <div class="flex items-center gap-1.5 text-sm font-medium text-neutral-900 dark:text-neutral-50">
                            <Icon icon="key-round" title="Request key" size="4" />
                            Request key
                        </div>
                        <div class="flex items-center gap-2">
                            <div class="flex min-w-0 flex-1 items-center rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950/40">
                                <div class="mono min-w-0 flex-1 overflow-x-auto whitespace-nowrap px-3 py-2 text-sm text-neutral-900 dark:text-neutral-100">{requestKey}</div>
                                <button
                                    type="button"
                                    class="flex shrink-0 cursor-pointer items-center justify-center rounded-r-lg border-l border-neutral-200 px-2.5 py-2 text-neutral-500 transition hover:bg-neutral-100 hover:text-neutral-900 dark:border-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-50"
                                    aria-label="Copy to clipboard"
                                    onclick={copyRequestKey}
                                >
                                    {#if copied}
                                        <Icon icon="check" title="Copied" size="4" />
                                    {:else}
                                        <Icon icon="copy" title="Copy to clipboard" size="4" />
                                    {/if}
                                </button>
                            </div>
                            <Button
                                variant="secondary"
                                onclick={promptRegenerate}
                                disabled={busy || confirmingRegenerate}
                            >
                                <Icon icon="refresh-cw" title="Regenerate" size="3.5" />
                                Regenerate
                            </Button>
                        </div>
                        {#if confirmingRegenerate}
                            <div class="rounded-lg border border-amber-200 bg-amber-50 px-3.5 py-3 dark:border-amber-900/70 dark:bg-amber-950/40">
                                <p class="text-sm font-medium text-amber-800 dark:text-amber-200">Are you sure?</p>
                                <p class="mt-1 text-sm text-amber-700 dark:text-amber-300">This will invalidate the existing Request key.</p>
                                <div class="mt-3 flex gap-2">
                                    <Button variant="danger" onclick={handleRegenerate} disabled={busy}>
                                        Yes, regenerate
                                    </Button>
                                    <Button variant="secondary" onclick={cancelRegenerate}>
                                        Cancel
                                    </Button>
                                </div>
                            </div>
                        {/if}
                    </div>
                </div>
            {:else if activeTab === 'ip-restrictions'}
                <!-- IP Restrictions tab -->
                <div class="space-y-4">
                    <div>
                        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Allowed IPs</div>
                        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                            One IP or CIDR per line. Leave empty to allow requests from any IP.
                        </p>
                    </div>

                    <textarea
                        class="mono min-h-40 w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm text-neutral-950 outline-none transition focus:border-neutral-900 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-50 dark:focus:border-neutral-300"
                        value={allowedIpsText}
                        oninput={(event) => {
                            onAllowedIpsTextInput((event.currentTarget as HTMLTextAreaElement).value)
                        }}
                        disabled={busy}
                    ></textarea>

                    <div class="flex justify-end">
                        <Button
                            variant="primary"
                            onclick={onUpdateAllowedIps}
                            disabled={busy}
                        >
                            Save allowed IPs
                        </Button>
                    </div>
                </div>
            {:else if activeTab === 'password'}
                <!-- Password tab -->
                <div class="space-y-6">
                    {#if hasPassword}
                        <div>
                            <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Change password</div>
                            <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                                Your primary key will be re-wrapped with the new password.
                            </p>
                        </div>

                        <div class="max-w-sm space-y-3">
                            <div class="space-y-1.5">
                                <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="settings-new-password">New password</label>
                                <TextField
                                    id="settings-new-password"
                                    type="password"
                                    placeholder="Enter new password"
                                    bind:value={passwordInput}
                                    disabled={busy}
                                />
                            </div>
                            <div class="space-y-1.5">
                                <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="settings-confirm-password">Confirm new password</label>
                                <TextField
                                    id="settings-confirm-password"
                                    type="password"
                                    placeholder="Confirm new password"
                                    bind:value={passwordConfirm}
                                    disabled={busy}
                                />
                            </div>
                        </div>

                        {#if passwordError}
                            <div class="rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                                {passwordError}
                            </div>
                        {/if}

                        <div class="flex gap-3">
                            <Button variant="primary" onclick={handleChangePassword} disabled={busy}>
                                Change password
                            </Button>
                        </div>

                        <div class="border-t border-neutral-200 pt-6 dark:border-neutral-800">
                            <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Remove password</div>
                            <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                                Your primary key will be protected only by your passkey's PRF output.
                            </p>
                            <div class="mt-3">
                                {#if confirmingRemovePassword}
                                    <div class="rounded-lg border border-amber-200 bg-amber-50 px-3.5 py-3 dark:border-amber-900/70 dark:bg-amber-950/40">
                                        <p class="text-sm font-medium text-amber-800 dark:text-amber-200">Are you sure you want to remove your password?</p>
                                        <p class="mt-1 text-sm text-amber-700 dark:text-amber-300">This will re-wrap your primary key without password protection.</p>
                                        <div class="mt-3 flex gap-2">
                                            <Button variant="danger" onclick={handleRemovePassword} disabled={busy}>
                                                Yes, remove password
                                            </Button>
                                            <Button variant="secondary" onclick={cancelRemovePassword}>
                                                Cancel
                                            </Button>
                                        </div>
                                    </div>
                                {:else}
                                    <Button variant="danger" onclick={promptRemovePassword} disabled={busy}>
                                        Remove password
                                    </Button>
                                {/if}
                            </div>
                        </div>
                    {:else}
                        <div>
                            <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Set a password</div>
                            <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                                No password is currently set. Adding a password provides an extra layer of protection for your primary key.
                            </p>
                        </div>

                        <div class="max-w-sm space-y-3">
                            <div class="space-y-1.5">
                                <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="settings-set-password">Password</label>
                                <TextField
                                    id="settings-set-password"
                                    type="password"
                                    placeholder="Enter password"
                                    bind:value={passwordInput}
                                    disabled={busy}
                                />
                            </div>
                            <div class="space-y-1.5">
                                <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="settings-set-confirm">Confirm password</label>
                                <TextField
                                    id="settings-set-confirm"
                                    type="password"
                                    placeholder="Confirm password"
                                    bind:value={passwordConfirm}
                                    disabled={busy}
                                />
                            </div>
                        </div>

                        {#if passwordError}
                            <div class="rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                                {passwordError}
                            </div>
                        {/if}

                        <Button variant="primary" onclick={handleChangePassword} disabled={busy}>
                            Set password
                        </Button>
                    {/if}
                </div>
            {:else if activeTab === 'passkeys'}
                <!-- Passkeys tab -->
                <div class="space-y-4">
                    <div>
                        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Registered passkeys</div>
                        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                            Manage the passkeys used to authenticate with this account. At least one passkey must remain.
                        </p>
                    </div>

                    {#if credentials.length === 0}
                        <div class="rounded-lg border border-dashed border-neutral-300 bg-white px-6 py-8 text-center text-sm text-neutral-500 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-400">
                            No credentials found.
                        </div>
                    {:else}
                        <div class="divide-y divide-neutral-200 overflow-hidden rounded-lg border border-neutral-200 dark:divide-neutral-800 dark:border-neutral-800">
                            {#each credentials as cred (cred.id)}
                                <div class="flex items-center gap-3 px-4 py-3">
                                    <div class="min-w-0 flex-1">
                                        {#if renamingCredentialId === cred.id}
                                            <div class="flex items-center gap-2">
                                                <div class="flex-1">
                                                    <TextField
                                                        type="text"
                                                        placeholder="Passkey name"
                                                        bind:value={renameValue}
                                                        disabled={busy}
                                                    />
                                                </div>
                                                <Button variant="primary" size="sm" onclick={() => saveRenameCredential(cred.id)} disabled={busy}>Save</Button>
                                                <Button variant="secondary" size="sm" onclick={cancelRenameCredential}>Cancel</Button>
                                            </div>
                                        {:else}
                                            <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">
                                                {cred.displayName || 'Passkey'}
                                            </div>
                                            <div class="mt-0.5 text-xs text-neutral-500 dark:text-neutral-400">
                                                Created {formatTimestamp(cred.createdAt)} · Last used {formatTimestamp(cred.lastUsedAt)}
                                            </div>
                                        {/if}
                                    </div>
                                    {#if renamingCredentialId !== cred.id}
                                        <div class="flex shrink-0 items-center gap-1">
                                            <Button variant="icon" size="icon" ariaLabel="Rename passkey" onclick={() => startRenameCredential(cred.id, cred.displayName)}>
                                                <Icon icon="pencil" title="Rename" size="3.5" />
                                            </Button>
                                            <Button
                                                variant="icon"
                                                size="icon"
                                                ariaLabel="Delete passkey"
                                                onclick={() => onDeletePasskey(cred.id)}
                                                disabled={credentials.length <= 1 || busy}
                                            >
                                                <Icon icon="trash" title="Delete" size="3.5" />
                                            </Button>
                                        </div>
                                    {/if}
                                </div>
                            {/each}
                        </div>
                    {/if}

                    {#if showAddPasskey}
                        <div class="rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
                            <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Add a passkey</div>
                            <div class="mt-3 max-w-sm space-y-1.5">
                                <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="settings-passkey-name">Passkey name (optional)</label>
                                <TextField
                                    id="settings-passkey-name"
                                    type="text"
                                    placeholder="e.g. MacBook Pro"
                                    bind:value={addPasskeyName}
                                    disabled={busy}
                                />
                            </div>
                            <div class="mt-3 flex gap-2">
                                <Button variant="primary" onclick={handleAddPasskey} disabled={busy}>
                                    Register passkey
                                </Button>
                                <Button
                                    variant="secondary"
                                    onclick={() => {
                                        showAddPasskey = false
                                        addPasskeyName = ''
                                    }}
                                >
                                    Cancel
                                </Button>
                            </div>
                        </div>
                    {:else}
                        <Button
                            variant="secondary"
                            onclick={() => {
                                showAddPasskey = true
                            }}
                        >
                            <Icon icon="plus" title="Add passkey" size="4" />
                            Add passkey
                        </Button>
                    {/if}
                </div>
            {:else if activeTab === 'signing-keys'}
                <!-- Signing keys tab -->
                <div class="space-y-6">
                    <div>
                        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Signing keys</div>
                        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                            Signing keys are derived deterministically from your primary key. Publishing a key makes its public half retrievable without authentication so verifiers can check signatures.
                        </p>
                    </div>

                    <!-- Derive key form -->
                    <div class="rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
                        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Derive a signing key</div>
                        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                            Same key label and algorithm always produce the same key.
                        </p>

                        <div class="mt-3 grid gap-3 md:grid-cols-2">
                            <div class="space-y-1.5">
                                <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="signing-key-label">Key label</label>
                                <TextField
                                    id="signing-key-label"
                                    type="text"
                                    placeholder="e.g. prod-signing"
                                    bind:value={deriveLabel}
                                    disabled={busy || derivingKey}
                                />
                            </div>
                            <div class="space-y-1.5">
                                <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="signing-key-algorithm">Algorithm</label>
                                <select
                                    id="signing-key-algorithm"
                                    bind:value={deriveAlgorithm}
                                    disabled={busy || derivingKey}
                                    class="h-10.5 w-full rounded-lg border border-neutral-300 bg-white px-3 text-sm text-neutral-950 outline-none transition focus:border-neutral-900 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-50 dark:focus:border-neutral-300"
                                >
                                    {#each SIGNING_ALGORITHMS as alg}
                                        <option value={alg}>{alg}</option>
                                    {/each}
                                </select>
                            </div>
                        </div>

                        {#if deriveError}
                            <div class="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                                {deriveError}
                            </div>
                        {/if}

                        <div class="mt-3 flex gap-2">
                            <Button variant="primary" onclick={handleDeriveSigningKey} disabled={busy || derivingKey}>
                                <Icon icon="key" title="Derive" size="3.5" />
                                Derive key
                            </Button>
                        </div>

                        {#if derivedKey}
                            <div class="mt-4 space-y-3 rounded-lg border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-950/40">
                                <div>
                                    <div class="text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Derived key</div>
                                    <div class="mt-1 text-sm text-neutral-900 dark:text-neutral-50">
                                        <span class="font-medium">{derivedKey.keyLabel}</span>
                                        <span class="mono ml-2 text-xs text-neutral-500 dark:text-neutral-400">{derivedKey.algorithm}</span>
                                    </div>
                                </div>
                                <div>
                                    <div class="text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Key ID</div>
                                    <div class="mono mt-1 break-all text-xs text-neutral-700 dark:text-neutral-300">{derivedKey.id}</div>
                                </div>

                                <div class="flex flex-wrap gap-2">
                                    <Button variant="secondary" size="sm" onclick={downloadDerivedJwk} disabled={busy}>
                                        <Icon icon="download" title="Download JWK" size="3.5" />
                                        Download JWK
                                    </Button>
                                    <Button variant="secondary" size="sm" onclick={downloadDerivedPem} disabled={busy}>
                                        <Icon icon="download" title="Download PEM" size="3.5" />
                                        Download PEM
                                    </Button>
                                    {#if !isDerivedPublished()}
                                        <Button variant="primary" size="sm" onclick={handlePublishDerived} disabled={busy}>
                                            <Icon icon="upload-cloud" title="Publish" size="3.5" />
                                            Publish
                                        </Button>
                                    {:else}
                                        <span class="inline-flex items-center gap-1 rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300">
                                            <Icon icon="check" title="Published" size="3" />
                                            Already published
                                        </span>
                                    {/if}
                                </div>
                            </div>
                        {/if}
                    </div>

                    <!-- Known keys list -->
                    <div>
                        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Signing keys</div>
                        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                            Public keys used to fulfill a sign request are automatically stored here. Publishing a key makes its public part retrievable without authentication at the URLs shown.
                        </p>

                        {#if signingKeys.length === 0}
                            <div class="mt-3 rounded-lg border border-dashed border-neutral-300 bg-white px-6 py-8 text-center text-sm text-neutral-500 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-400">
                                No signing keys yet.
                            </div>
                        {:else}
                            <div class="mt-3 space-y-3">
                                {#each signingKeys as sk (sk.id)}
                                    <div class="rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
                                        <div class="flex flex-wrap items-start justify-between gap-3">
                                            <div class="min-w-0">
                                                <div class="flex items-center gap-2 text-sm font-medium text-neutral-900 dark:text-neutral-50">
                                                    <span>{sk.keyLabel}</span>
                                                    <span class="mono text-xs font-normal text-neutral-500 dark:text-neutral-400">{sk.algorithm}</span>
                                                    {#if sk.published}
                                                        <span class="inline-flex items-center rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300">
                                                            Published
                                                        </span>
                                                    {:else}
                                                        <span class="inline-flex items-center rounded-full bg-neutral-100 px-2 py-0.5 text-xs font-medium text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">
                                                            Stored
                                                        </span>
                                                    {/if}
                                                </div>
                                                <div class="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                                                    {sk.published ? 'Published' : 'Stored'} {formatTimestamp(sk.createdAt)}
                                                    {#if sk.updatedAt && sk.updatedAt !== sk.createdAt}
                                                        · Updated {formatTimestamp(sk.updatedAt)}
                                                    {/if}
                                                </div>
                                                <div class="mono mt-1 break-all text-xs text-neutral-600 dark:text-neutral-400" title={sk.id}>
                                                    {shortenId(sk.id)}
                                                </div>
                                            </div>
                                            <div class="flex shrink-0 items-center gap-1">
                                                {#if !sk.published}
                                                    <Button variant="primary" size="sm" onclick={() => handlePublishStored(sk)} disabled={busy || publishingStoredId === sk.id}>
                                                        <Icon icon="upload-cloud" title="Publish" size="3.5" />
                                                        Publish
                                                    </Button>
                                                {:else}
                                                    <Button
                                                        variant="secondary"
                                                        size="sm"
                                                        ariaLabel="Unpublish key"
                                                        onclick={() => handleUnpublish(sk.id)}
                                                        disabled={busy}
                                                    >
                                                        Unpublish
                                                    </Button>
                                                {/if}
                                                <Button
                                                    variant="icon"
                                                    size="icon"
                                                    ariaLabel="Delete key"
                                                    onclick={() => {
                                                        confirmingDeleteId = sk.id
                                                    }}
                                                    disabled={busy}
                                                >
                                                    <Icon icon="trash" title="Delete" size="3.5" />
                                                </Button>
                                            </div>
                                        </div>

                                        {#if confirmingDeleteId === sk.id}
                                            <div class="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3.5 py-3 dark:border-amber-900/70 dark:bg-amber-950/40">
                                                <p class="text-sm font-medium text-amber-800 dark:text-amber-200">Delete this signing key?</p>
                                                <p class="mt-1 text-sm text-amber-700 dark:text-amber-300">
                                                    The row will be removed from the server. The same key can be re-derived from your primary key, but any existing published URL will stop resolving until it is re-derived and published again.
                                                </p>
                                                <div class="mt-3 flex gap-2">
                                                    <Button variant="danger" size="sm" onclick={() => handleDelete(sk.id)} disabled={busy}>
                                                        Yes, delete
                                                    </Button>
                                                    <Button
                                                        variant="secondary"
                                                        size="sm"
                                                        onclick={() => {
                                                            confirmingDeleteId = null
                                                        }}
                                                    >
                                                        Cancel
                                                    </Button>
                                                </div>
                                            </div>
                                        {/if}

                                        {#if sk.published}
                                            <div class="mt-3 space-y-2">
                                                {#each ['jwk', 'pem'] as const as kind}
                                                    <div class="flex items-center gap-2">
                                                        <div class="w-10 shrink-0 text-xs font-medium uppercase text-neutral-500 dark:text-neutral-400">{kind}</div>
                                                        <div class="flex min-w-0 flex-1 items-center rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950/40">
                                                            <div class="mono min-w-0 flex-1 overflow-x-auto whitespace-nowrap px-3 py-1.5 text-xs text-neutral-900 dark:text-neutral-100">{publicFetchUrl(sk.id, kind)}</div>
                                                            <button
                                                                type="button"
                                                                class="flex shrink-0 cursor-pointer items-center justify-center rounded-r-lg border-l border-neutral-200 px-2 py-1.5 text-neutral-500 transition hover:bg-neutral-100 hover:text-neutral-900 dark:border-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-50"
                                                                aria-label="Copy to clipboard"
                                                                onclick={() => copyFetchUrl(sk.id, kind)}
                                                            >
                                                                {#if copiedFetchId === `${sk.id}/${kind}`}
                                                                    <Icon icon="check" title="Copied" size="3.5" />
                                                                {:else}
                                                                    <Icon icon="copy" title="Copy to clipboard" size="3.5" />
                                                                {/if}
                                                            </button>
                                                        </div>
                                                    </div>
                                                {/each}
                                            </div>
                                        {/if}
                                    </div>
                                {/each}
                            </div>
                        {/if}
                    </div>
                </div>
            {/if}

            <!-- Status messages -->
            {#if error}
                <div class="mt-6 rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {error}
                </div>
            {:else if success}
                <div class="mt-6 rounded-lg border border-emerald-200 bg-emerald-50 px-3.5 py-2.5 text-sm text-emerald-800 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-200">
                    {success}
                </div>
            {/if}
        </div>
    </div>
</section>
