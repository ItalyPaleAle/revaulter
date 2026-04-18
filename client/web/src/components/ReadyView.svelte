<script lang="ts">
import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'
import PendingItem from '$components/PendingItem.svelte'
import UserSettingsModal from '$components/UserSettingsModal.svelte'

import type { DerivedSigningKey, V2CredentialItem, V2PendingRequestItem, V2PublishedSigningKey } from '$lib/v2-types'

interface Props {
    allowedIpsText: string
    credentials: V2CredentialItem[]
    displayName: string
    hasPassword: boolean
    listConnected: boolean
    onAddPasskey: (name: string) => Promise<void>
    onAllowedIpsTextInput: (value: string) => void
    onChangePassword: (password: string) => Promise<void>
    onDeletePasskey: (id: string) => Promise<void>
    onDeriveSigningKey: (keyLabel: string, algorithm: string) => Promise<DerivedSigningKey>
    onLogout: () => Promise<void>
    onPublishSigningKey: (derived: DerivedSigningKey) => Promise<void>
    onRegenerateRequestKey: () => Promise<void>
    onRemoveItem: (state: string) => void
    onRemovePassword: () => Promise<void>
    onRenamePasskey: (id: string, name: string) => Promise<void>
    onUnpublishSigningKey: (id: string) => Promise<void>
    onUpdateAllowedIps: () => Promise<void>
    onUpdateDisplayName: (name: string) => Promise<void>
    pageError: string | null
    pendingItems: V2PendingRequestItem[]
    primaryKey: Uint8Array | null
    requestKey: string
    sessionLabel: string
    settingsBusy: boolean
    settingsError: string | null
    settingsSuccess: string | null
    signingKeys: V2PublishedSigningKey[]
    userId: string
}

let {
    allowedIpsText,
    credentials,
    displayName,
    hasPassword,
    listConnected,
    onAddPasskey,
    onAllowedIpsTextInput,
    onChangePassword,
    onDeletePasskey,
    onDeriveSigningKey,
    onLogout,
    onPublishSigningKey,
    onRegenerateRequestKey,
    onRemoveItem,
    onRemovePassword,
    onRenamePasskey,
    onUnpublishSigningKey,
    onUpdateAllowedIps,
    onUpdateDisplayName,
    pageError,
    pendingItems,
    primaryKey,
    requestKey,
    sessionLabel,
    settingsBusy,
    settingsError,
    settingsSuccess,
    signingKeys,
    userId,
}: Props = $props()

let settingsModalOpen = $state(false)

function toggleSettingsModal() {
    settingsModalOpen = !settingsModalOpen
}

function closeSettingsModal() {
    settingsModalOpen = false
}

function logoutFromSettings() {
    closeSettingsModal()
    void onLogout()
}
</script>

<div class="mx-auto flex min-h-screen w-full max-w-6xl flex-col gap-8 px-4 py-6 md:px-6 md:py-8">
    <header class="rounded-4xl border border-white/85 bg-white/92 p-5 shadow-[0_8px_26px_-20px_rgba(15,23,42,0.22)] dark:border-white/10 dark:bg-slate-950/88">
        <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div class="space-y-3">
                <div class="space-y-2">
                    <h1 class="text-3xl text-slate-950 dark:text-white md:text-4xl" data-display="serif">Pending approvals</h1>
                    <p class="max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-300">
                        Review inbound encrypt and decrypt operations for <span class="font-mono text-slate-900 dark:text-slate-100">{sessionLabel}</span>.
                    </p>
                </div>
            </div>

            <div class="relative flex justify-end lg:justify-start">
                <Button
                    variant="icon"
                    size="icon"
                    ariaLabel="Open user settings"
                    onclick={toggleSettingsModal}
                >
                    <Icon icon="settings" title="User settings" size="5" />
                </Button>
            </div>
        </div>
    </header>

    {#if pageError}
        <div class="rounded-3xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
            {pageError}
        </div>
    {/if}

    <section class="rounded-4xl border border-white/85 bg-white/92 p-5 shadow-[0_8px_26px_-20px_rgba(15,23,42,0.22)] dark:border-white/10 dark:bg-slate-950/88">
        <div class="mb-5 flex flex-col gap-3 border-b border-slate-200/80 pb-4 dark:border-white/10 md:flex-row md:items-center md:justify-between">
            <div>
                <div class="text-sm font-medium uppercase tracking-[0.18em] text-slate-700 dark:text-slate-200">Assigned requests</div>
                <div class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                    Requests stream to this page in real time. Confirm only if the input, key label, and requester look correct.
                </div>
            </div>
            <div class="rounded-full bg-white/68 px-3 py-1 text-xs font-medium text-slate-500 ring-1 ring-slate-200/80 dark:bg-white/6 dark:text-slate-300 dark:ring-white/10">
                {#if listConnected}Live stream connected{:else}Connecting…{/if}
            </div>
        </div>

        {#if pendingItems.length === 0}
            <div class="border border-dashed border-slate-300/90 bg-white/25 px-6 py-12 text-center dark:border-white/12 dark:bg-white/4">
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
                {#each pendingItems as item (item.state)}
                    {#if primaryKey}
                        <PendingItem
                            {item}
                            {primaryKey}
                            onRemoved={onRemoveItem}
                        />
                    {/if}
                {/each}
            </div>
        {/if}
    </section>

    {#if settingsModalOpen}
        <UserSettingsModal
            {userId}
            {displayName}
            {requestKey}
            {allowedIpsText}
            {hasPassword}
            {credentials}
            {signingKeys}
            busy={settingsBusy}
            error={settingsError}
            success={settingsSuccess}
            onClose={closeSettingsModal}
            {onUpdateDisplayName}
            {onRegenerateRequestKey}
            {onAllowedIpsTextInput}
            {onUpdateAllowedIps}
            {onChangePassword}
            {onRemovePassword}
            {onAddPasskey}
            {onRenamePasskey}
            {onDeletePasskey}
            {onDeriveSigningKey}
            {onPublishSigningKey}
            {onUnpublishSigningKey}
            onLogout={logoutFromSettings}
        />
    {/if}
</div>
