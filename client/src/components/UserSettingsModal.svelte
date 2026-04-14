<script lang="ts">
import { formatDistanceToNowStrict } from 'date-fns'

import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import TextField from '$components/TextField.svelte'

import type { V2CredentialItem } from '$lib/v2-types'

type SettingsTab = 'user' | 'ip-restrictions' | 'password' | 'passkeys'

interface Props {
    userId: string
    displayName: string
    requestKey: string
    allowedIpsText: string
    hasPassword: boolean
    credentials: V2CredentialItem[]
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
    onLogout: () => void
}

let {
    userId,
    displayName,
    requestKey,
    allowedIpsText,
    hasPassword,
    credentials,
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
    onLogout,
}: Props = $props()

let activeTab = $state<SettingsTab>('user')

// User tab state
let editingDisplayName = $state(false)
let editDisplayNameValue = $state('')
let copied = $state(false)

// Password tab state
let passwordInput = $state('')
let passwordConfirm = $state('')
let passwordError = $state<string | null>(null)

let confirmingRemovePassword = $state(false)

// Passkeys tab state
let renamingCredentialId = $state<string | null>(null)
let renameValue = $state('')
let addPasskeyName = $state('')
let showAddPasskey = $state(false)

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

function formatTimestamp(unix: number): string {
    if (!unix) {
        return 'Never'
    }
    return formatDistanceToNowStrict(new Date(unix * 1000), { addSuffix: true })
}

const tabs: { id: SettingsTab; label: string; icon: string }[] = [
    { id: 'user', label: 'User', icon: 'user' },
    { id: 'ip-restrictions', label: 'IP Restrictions', icon: 'shield' },
    { id: 'password', label: 'Password', icon: 'lock-closed' },
    { id: 'passkeys', label: 'Passkeys', icon: 'fingerprint' },
]
</script>

<div class="fixed inset-0 z-40 bg-slate-950/32 backdrop-blur-sm dark:bg-slate-950/58"></div>
<section class="fixed inset-0 z-50 flex items-center justify-center px-4 py-4">
    <div class="flex h-[92vh] w-[92vw] max-w-5xl flex-col overflow-hidden rounded-4xl border border-white/90 bg-white shadow-[0_14px_40px_-28px_rgba(15,23,42,0.28)] dark:border-white/10 dark:bg-slate-950/96">
        <!-- Header -->
        <div class="flex items-center justify-between gap-4 border-b border-slate-200/80 p-5 dark:border-white/10 md:p-6">
            <div>
                <div class="flex items-center gap-2 text-sm font-medium uppercase tracking-[0.18em] text-slate-700 dark:text-slate-200">
                    <Icon icon="settings" title="User settings" size="4" />
                    User settings
                </div>
            </div>
            <Button
                variant="icon"
                size="icon"
                ariaLabel="Close user settings"
                onclick={onClose}
            >
                <Icon icon="x" title="Close user settings" size="5" />
            </Button>
        </div>

        <!-- Body: tabs + content -->
        <div class="flex min-h-0 flex-1 flex-col lg:flex-row">
            <!-- Tab sidebar (vertical on lg, horizontal on mobile) -->
            <nav class="flex shrink-0 gap-1 overflow-x-auto border-b border-slate-200/80 p-3 dark:border-white/10 lg:w-52 lg:flex-col lg:overflow-x-visible lg:border-b-0 lg:border-r lg:p-4">
                {#each tabs as tab}
                    <button
                        type="button"
                        class="flex cursor-pointer items-center gap-2 whitespace-nowrap rounded-xl px-3 py-2 text-left text-sm font-medium transition {activeTab === tab.id ? 'bg-slate-100 text-slate-900 dark:bg-white/10 dark:text-white' : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-white/6 dark:hover:text-white'}"
                        onclick={() => setActiveTab(tab.id)}
                    >
                        <Icon icon={tab.icon} title={tab.label} size="4" />
                        {tab.label}
                    </button>
                {/each}

                <div class="mt-auto hidden pt-4 lg:block">
                    <Button
                        variant="outline"
                        onclick={onLogout}
                    >
                        <Icon icon="log-out" title="Sign out" size="4" />
                        Sign out
                    </Button>
                </div>
            </nav>

            <!-- Content area -->
            <div class="flex-1 overflow-y-auto p-5 md:p-6">
                {#if activeTab === 'user'}
                    <!-- User tab -->
                    <div class="space-y-6">
                        <!-- Display name -->
                        <div class="space-y-2">
                            <div class="text-sm font-medium text-slate-900 dark:text-white">Display name</div>
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
                                    <Button variant="neutral" onclick={saveDisplayName} disabled={busy}>Save</Button>
                                    <Button variant="outline" onclick={cancelEditDisplayName}>Cancel</Button>
                                </div>
                            {:else}
                                <div class="flex items-center gap-2">
                                    <span class="text-sm text-slate-700 dark:text-slate-300">{displayName || userId}</span>
                                    <Button variant="icon" size="icon" ariaLabel="Edit display name" onclick={startEditDisplayName}>
                                        <Icon icon="pencil" title="Edit" size="3.5" />
                                    </Button>
                                </div>
                            {/if}
                        </div>

                        <!-- User ID -->
                        <div class="space-y-2">
                            <div class="text-sm font-medium text-slate-900 dark:text-white">User ID</div>
                            <div class="font-mono text-sm text-slate-600 dark:text-slate-400">{userId}</div>
                        </div>

                        <!-- Request key -->
                        <div class="space-y-2">
                            <div class="flex items-center gap-2 text-sm font-medium text-slate-900 dark:text-white">
                                <Icon icon="key-round" title="Request key" size="4" />
                                Request key (API key)
                            </div>
                            <div class="flex items-center gap-2">
                                <div class="flex min-w-0 flex-1 items-center rounded-[1.2rem] bg-slate-50/90 ring-1 ring-slate-200/80 dark:bg-white/6 dark:ring-white/10">
                                    <div class="min-w-0 flex-1 overflow-x-auto whitespace-nowrap px-4 py-3 font-mono text-sm text-slate-900 dark:text-slate-100">{requestKey}</div>
                                    <button
                                        type="button"
                                        class="flex shrink-0 cursor-pointer items-center justify-center rounded-r-[1.2rem] border-l border-slate-200/80 px-2 py-2 text-slate-500 transition hover:bg-slate-100/80 hover:text-slate-700 dark:border-white/10 dark:text-slate-400 dark:hover:bg-white/8 dark:hover:text-slate-200"
                                        aria-label="Copy to clipboard"
                                        onclick={copyRequestKey}
                                    >
                                        {#if copied}
                                            <Icon icon="check" title="Copied" size="4" />
                                        {:else}
                                            <Icon icon="clipboard-copy" title="Copy to clipboard" size="4" />
                                        {/if}
                                    </button>
                                </div>
                                <Button
                                    variant="outline"
                                    onclick={onRegenerateRequestKey}
                                    disabled={busy}
                                >
                                    <Icon icon="refresh-cw" title="Regenerate" size="4" />
                                    Regenerate
                                </Button>
                            </div>
                        </div>
                    </div>
                {:else if activeTab === 'ip-restrictions'}
                    <!-- IP Restrictions tab -->
                    <div class="space-y-4">
                        <div>
                            <div class="text-sm font-medium text-slate-900 dark:text-white">Allowed IPs</div>
                            <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                                One IP or CIDR per line. Leave empty to allow requests from any IP.
                            </p>
                        </div>

                        <textarea
                            class="min-h-40 w-full rounded-[1.35rem] border border-white/70 bg-white/80 px-4 py-3 font-mono text-sm text-slate-950 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-white/10 dark:bg-slate-950/70 dark:text-white dark:focus:border-sky-400 dark:focus:ring-sky-950"
                            value={allowedIpsText}
                            oninput={(event) => {
                                onAllowedIpsTextInput((event.currentTarget as HTMLTextAreaElement).value)
                            }}
                            disabled={busy}
                        ></textarea>

                        <div class="flex justify-end">
                            <Button
                                variant="neutral"
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
                                <div class="text-sm font-medium text-slate-900 dark:text-white">Change password</div>
                                <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                                    Your primary key will be re-wrapped with the new password.
                                </p>
                            </div>

                            <div class="max-w-sm space-y-3">
                                <div class="space-y-1">
                                    <label class="block text-xs font-medium text-slate-600 dark:text-slate-400" for="settings-new-password">New password</label>
                                    <TextField
                                        id="settings-new-password"
                                        type="password"
                                        placeholder="Enter new password"
                                        bind:value={passwordInput}
                                        disabled={busy}
                                    />
                                </div>
                                <div class="space-y-1">
                                    <label class="block text-xs font-medium text-slate-600 dark:text-slate-400" for="settings-confirm-password">Confirm new password</label>
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
                                <div class="rounded-2xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                                    {passwordError}
                                </div>
                            {/if}

                            <div class="flex gap-3">
                                <Button variant="neutral" onclick={handleChangePassword} disabled={busy}>
                                    Change password
                                </Button>
                            </div>

                            <div class="border-t border-slate-200/80 pt-6 dark:border-white/10">
                                <div class="text-sm font-medium text-slate-900 dark:text-white">Remove password</div>
                                <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                                    Your primary key will be protected only by your passkey's PRF output.
                                </p>
                                <div class="mt-3">
                                    {#if confirmingRemovePassword}
                                        <div class="rounded-2xl border border-amber-200 bg-amber-50/90 px-4 py-3 dark:border-amber-900/70 dark:bg-amber-950/40">
                                            <p class="text-sm font-medium text-amber-800 dark:text-amber-200">Are you sure you want to remove your password?</p>
                                            <p class="mt-1 text-sm text-amber-700 dark:text-amber-300">This will re-wrap your primary key without password protection.</p>
                                            <div class="mt-3 flex gap-2">
                                                <Button variant="danger" onclick={handleRemovePassword} disabled={busy}>
                                                    Yes, remove password
                                                </Button>
                                                <Button variant="outline" onclick={cancelRemovePassword}>
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
                                <div class="text-sm font-medium text-slate-900 dark:text-white">Set a password</div>
                                <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                                    No password is currently set. Adding a password provides an extra layer of protection for your primary key.
                                </p>
                            </div>

                            <div class="max-w-sm space-y-3">
                                <div class="space-y-1">
                                    <label class="block text-xs font-medium text-slate-600 dark:text-slate-400" for="settings-set-password">Password</label>
                                    <TextField
                                        id="settings-set-password"
                                        type="password"
                                        placeholder="Enter password"
                                        bind:value={passwordInput}
                                        disabled={busy}
                                    />
                                </div>
                                <div class="space-y-1">
                                    <label class="block text-xs font-medium text-slate-600 dark:text-slate-400" for="settings-set-confirm">Confirm password</label>
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
                                <div class="rounded-2xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                                    {passwordError}
                                </div>
                            {/if}

                            <Button variant="neutral" onclick={handleChangePassword} disabled={busy}>
                                Set password
                            </Button>
                        {/if}
                    </div>
                {:else if activeTab === 'passkeys'}
                    <!-- Passkeys tab -->
                    <div class="space-y-4">
                        <div>
                            <div class="text-sm font-medium text-slate-900 dark:text-white">Registered passkeys</div>
                            <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                                Manage the passkeys used to authenticate with this account. At least one passkey must remain.
                            </p>
                        </div>

                        {#if credentials.length === 0}
                            <div class="rounded-2xl border border-dashed border-slate-300/90 bg-white/25 px-6 py-8 text-center text-sm text-slate-500 dark:border-white/12 dark:bg-white/4 dark:text-slate-400">
                                No credentials found.
                            </div>
                        {:else}
                            <div class="divide-y divide-slate-200/80 rounded-2xl border border-slate-200/80 dark:divide-white/10 dark:border-white/10">
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
                                                    <Button variant="neutral" size="sm" onclick={() => saveRenameCredential(cred.id)} disabled={busy}>Save</Button>
                                                    <Button variant="outline" size="sm" onclick={cancelRenameCredential}>Cancel</Button>
                                                </div>
                                            {:else}
                                                <div class="text-sm font-medium text-slate-900 dark:text-white">
                                                    {cred.displayName || 'Passkey'}
                                                </div>
                                                <div class="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
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
                            <div class="rounded-2xl border border-slate-200/80 p-4 dark:border-white/10">
                                <div class="text-sm font-medium text-slate-900 dark:text-white">Add a passkey</div>
                                <div class="mt-3 max-w-sm space-y-1">
                                    <label class="block text-xs font-medium text-slate-600 dark:text-slate-400" for="settings-passkey-name">Passkey name (optional)</label>
                                    <TextField
                                        id="settings-passkey-name"
                                        type="text"
                                        placeholder="e.g. MacBook Pro"
                                        bind:value={addPasskeyName}
                                        disabled={busy}
                                    />
                                </div>
                                <div class="mt-3 flex gap-2">
                                    <Button variant="neutral" onclick={handleAddPasskey} disabled={busy}>
                                        Register passkey
                                    </Button>
                                    <Button variant="outline" onclick={() => { showAddPasskey = false; addPasskeyName = '' }}>
                                        Cancel
                                    </Button>
                                </div>
                            </div>
                        {:else}
                            <Button variant="outline" onclick={() => { showAddPasskey = true }}>
                                <Icon icon="plus" title="Add passkey" size="4" />
                                Add passkey
                            </Button>
                        {/if}
                    </div>
                {/if}

                <!-- Status messages -->
                {#if error}
                    <div class="mt-6 rounded-2xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                        {error}
                    </div>
                {:else if success}
                    <div class="mt-6 rounded-2xl border border-emerald-200 bg-emerald-50/90 px-4 py-3 text-sm text-emerald-800 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-200">
                        {success}
                    </div>
                {/if}

                <!-- Mobile sign out -->
                <div class="mt-6 border-t border-slate-200/80 pt-6 dark:border-white/10 lg:hidden">
                    <Button variant="outline" onclick={onLogout}>
                        <Icon icon="log-out" title="Sign out" size="4" />
                        Sign out
                    </Button>
                </div>
            </div>
        </div>
    </div>
</section>
