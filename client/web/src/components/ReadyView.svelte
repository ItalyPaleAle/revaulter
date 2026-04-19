<script lang="ts">
import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import Logo from '$components/Logo.svelte'
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
</script>

<div class="mx-auto w-full max-w-230 px-6 pt-12 pb-32">
    <!-- Header -->
    <div class="mb-10 flex items-start justify-between gap-4">
        <div>
            <div class="mb-4 inline-flex items-center gap-2.5">
                <Logo size={28} radius={7} />
                <span class="text-sm font-semibold tracking-tight text-neutral-900 dark:text-neutral-50">Revaulter</span>
            </div>
            <h1 class="mb-1.5 text-[30px] font-semibold leading-tight tracking-tight text-neutral-950 dark:text-neutral-50">
                Pending approvals
            </h1>
            <p class="text-sm text-neutral-500 dark:text-neutral-400">
                Review inbound encrypt, decrypt, and signing requests for
                <span class="mono text-neutral-900 dark:text-neutral-100">{sessionLabel}</span>.
            </p>
        </div>

        <div class="flex items-center gap-2">
            <span class="group relative">
                <Button
                    variant="icon"
                    size="icon"
                    ariaLabel="Open settings"
                    onclick={toggleSettingsModal}
                >
                    <Icon icon="settings" title="Settings" size="4" />
                </Button>
                <span class="pointer-events-none absolute top-full left-1/2 z-10 mt-2 -translate-x-1/2 scale-95 whitespace-nowrap rounded-md bg-neutral-900 px-2 py-1 text-xs font-medium text-white opacity-0 shadow-md transition duration-150 group-hover:scale-100 group-hover:opacity-100 dark:bg-neutral-100 dark:text-neutral-900">
                    Settings
                </span>
            </span>
            <span class="group relative">
                <Button
                    variant="icon"
                    size="icon"
                    ariaLabel="Sign out"
                    onclick={() => void onLogout()}
                >
                    <Icon icon="log-out" title="Sign out" size="4" />
                </Button>
                <span class="pointer-events-none absolute top-full right-0 z-10 mt-2 scale-95 whitespace-nowrap rounded-md bg-neutral-900 px-2 py-1 text-xs font-medium text-white opacity-0 shadow-md transition duration-150 group-hover:scale-100 group-hover:opacity-100 dark:bg-neutral-100 dark:text-neutral-900">
                    Sign out
                </span>
            </span>
        </div>
    </div>

    {#if pageError}
        <div class="mb-4 rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
            {pageError}
        </div>
    {/if}

    <!-- Live status -->
    <div class="mb-3 flex items-center justify-end">
        <div class="inline-flex items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
            {#if listConnected}
                <span class="h-1.5 w-1.5 rounded-full bg-emerald-500 live-dot"></span>
                Live
            {:else}
                <span class="h-1.5 w-1.5 rounded-full bg-neutral-400 dark:bg-neutral-600"></span>
                Connecting…
            {/if}
        </div>
    </div>

    <!-- Message list -->
    {#if pendingItems.length === 0}
        <div class="rounded-xl border border-dashed border-neutral-300 bg-white px-6 py-20 text-center dark:border-neutral-700 dark:bg-neutral-900">
            <div class="mx-auto mb-4 inline-flex h-11 w-11 items-center justify-center rounded-[11px] bg-neutral-100 text-neutral-500 dark:bg-neutral-800 dark:text-neutral-400">
                <Icon icon="check" title="" size="5" />
            </div>
            <div class="mb-1 text-[15px] font-medium text-neutral-900 dark:text-neutral-50">All clear</div>
            <div class="mx-auto max-w-xs text-sm text-neutral-500 dark:text-neutral-400">
                New approvals will appear here as soon as they are assigned to you.
            </div>
        </div>
    {:else}
        <div class="overflow-hidden rounded-xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900">
            {#each pendingItems as item, idx (item.state)}
                {#if primaryKey}
                    <div class={idx === 0 ? '' : 'border-t border-neutral-200 dark:border-neutral-800'}>
                        <PendingItem
                            {item}
                            {primaryKey}
                            onRemoved={onRemoveItem}
                        />
                    </div>
                {/if}
            {/each}
        </div>
    {/if}

    <p class="mt-6 text-center text-xs text-neutral-400 dark:text-neutral-500">
        Requests stream in real time. Confirm only if the input, key label, and requester look correct.
    </p>

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
        />
    {/if}
</div>

<style>
    .live-dot {
        animation: pulse-ring 2s ease-in-out infinite;
    }
</style>
