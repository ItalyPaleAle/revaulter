<script lang="ts">
import { formatDistanceToNowStrict } from 'date-fns'
import { tick } from 'svelte'

import AuditLogTab from '$components/AuditLogTab.svelte'
import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import SigningKeysTab from '$components/SigningKeysTab.svelte'
import TextField from '$components/TextField.svelte'

import type { DerivedSigningKey, V2CredentialItem, V2PublishedSigningKey } from '$lib/v2-types'

type SettingsTab = 'user' | 'ip-restrictions' | 'password' | 'passkeys' | 'signing-keys' | 'audit-log'

interface Props {
    userId: string
    displayName: string
    requestKey: string
    anchorFingerprint: string
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
    anchorFingerprint,
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

let dialogElement: HTMLElement | undefined = $state()
let closeButton: HTMLButtonElement | undefined = $state()

const focusableSelector = [
    'a[href]',
    'button:not([disabled])',
    'textarea:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
].join(',')

$effect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
        if (event.key === 'Escape') {
            onClose()
            return
        }

        if (event.key !== 'Tab' || !dialogElement) {
            return
        }

        const focusable = Array.from(dialogElement.querySelectorAll<HTMLElement>(focusableSelector)).filter(
            (element) => {
                return element.offsetParent !== null || element === document.activeElement
            }
        )
        if (focusable.length === 0) {
            event.preventDefault()
            dialogElement.focus()
            return
        }

        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault()
            last.focus()
            return
        }
        if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault()
            first.focus()
        }
    }

    document.addEventListener('keydown', handleKeyDown)

    return () => {
        document.removeEventListener('keydown', handleKeyDown)
    }
})

$effect(() => {
    void (async () => {
        await tick()
        closeButton?.focus()
    })()
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

function formatFingerprint(fp: string): string {
    const upper = fp.toUpperCase()
    const groups: string[] = []
    for (let i = 0; i < upper.length; i += 4) {
        groups.push(upper.slice(i, i + 4))
    }

    const lines: string[] = []
    for (let i = 0; i < groups.length; i += 4) {
        lines.push(groups.slice(i, i + 4).join(' '))
    }

    return lines.join('\n')
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

const tabs: { id: SettingsTab; label: string; icon: string }[] = [
    { id: 'user', label: 'User', icon: 'user' },
    { id: 'ip-restrictions', label: 'Firewall', icon: 'brick-wall-shield' },
    { id: 'password', label: 'Password', icon: 'lock-closed' },
    { id: 'passkeys', label: 'Passkeys', icon: 'shield' },
    { id: 'signing-keys', label: 'Signing keys', icon: 'lock-keyhole' },
    { id: 'audit-log', label: 'Audit log', icon: 'scroll-text' },
]
</script>

<div class="fixed inset-0 z-40 bg-neutral-950/50 backdrop-blur-sm"></div>
<section class="fixed inset-0 z-50 flex items-center justify-center px-4 py-6">
    <div
        bind:this={dialogElement}
        class="flex h-[95vh] md:h-[88vh] w-[95vw] md:w-[88vw] flex-col overflow-hidden rounded-2xl border border-neutral-200 bg-white shadow-2xl dark:border-neutral-800 dark:bg-neutral-900"
        role="dialog"
        aria-modal="true"
        aria-labelledby="settings-title"
        tabindex="-1"
    >
        <!-- Header -->
        <div class="flex items-center justify-between gap-4 border-b border-neutral-200 px-5 py-4 dark:border-neutral-800">
            <div id="settings-title" class="flex items-center gap-2 text-sm font-semibold text-neutral-900 dark:text-neutral-50">
                <Icon icon="settings" title="Settings" size="4" />
                Settings
            </div>
            <Button
                bind:ref={closeButton}
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
                            <div class="flex min-w-0 flex-1 items-center rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950/40 max-w-80">
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

                    {#if anchorFingerprint}
                        <!-- Anchor fingerprint -->
                        <div class="space-y-2">
                            <div class="flex items-center gap-1.5 text-sm font-medium text-neutral-900 dark:text-neutral-50">
                                <Icon icon="fingerprint" title="Anchor fingerprint" size="4" />
                                Anchor fingerprint
                            </div>
                            <pre class="mono rounded-lg border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm text-neutral-900 dark:border-neutral-800 dark:bg-neutral-950/40 dark:text-neutral-100 whitespace-pre inline-block">{formatFingerprint(anchorFingerprint)}</pre>
                            <p class="text-xs text-neutral-500 dark:text-neutral-400">
                                Verify this matches the fingerprint shown by the CLI on first contact
                            </p>
                        </div>
                    {/if}
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
                <SigningKeysTab
                    {signingKeys}
                    {busy}
                    {onDeriveSigningKey}
                    {onPublishSigningKey}
                    {onUnpublishSigningKey}
                    {onDeleteSigningKey}
                />
            {:else if activeTab === 'audit-log'}
                <AuditLogTab />
            {/if}
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
