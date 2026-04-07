<script lang="ts">
import Button from '$components/Button.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'
import Modal from '$components/Modal.svelte'
import PendingItem from '$components/PendingItem.svelte'

import type { V2PendingRequestItem } from '$lib/v2-types'

interface Props {
    activePassword: string
    allowedIpsModalOpen: boolean
    allowedIpsSummary: string
    allowedIpsText: string
    listConnected: boolean
    onAllowedIpsTextInput: (value: string) => void
    onCloseAllowedIpsModal: () => void
    onLogout: () => Promise<void>
    onOpenAllowedIpsModal: () => void
    onRegenerateRequestKey: () => Promise<void>
    onRemoveItem: (state: string) => void
    onUpdateAllowedIps: () => Promise<void>
    pageError: string | null
    pendingItems: V2PendingRequestItem[]
    prfSecret: Uint8Array | null
    requestKey: string
    sessionLabel: string
    settingsBusy: boolean
    settingsError: string | null
    settingsSuccess: string | null
}

let {
    activePassword,
    allowedIpsModalOpen,
    allowedIpsSummary,
    allowedIpsText,
    listConnected,
    onAllowedIpsTextInput,
    onCloseAllowedIpsModal,
    onLogout,
    onOpenAllowedIpsModal,
    onRegenerateRequestKey,
    onRemoveItem,
    onUpdateAllowedIps,
    pageError,
    pendingItems,
    prfSecret,
    requestKey,
    sessionLabel,
    settingsBusy,
    settingsError,
    settingsSuccess,
}: Props = $props()
</script>

<div class="mx-auto flex min-h-screen w-full max-w-6xl flex-col gap-8 px-4 py-6 md:px-6 md:py-8">
    <header class="relative overflow-hidden rounded-[2rem] border border-white/65 bg-white/48 p-5 shadow-[0_8px_26px_-20px_rgba(15,23,42,0.22)] backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/42">
        <div class="pointer-events-none absolute inset-x-0 top-0 h-24 bg-[linear-gradient(90deg,rgba(251,191,36,0.18),rgba(14,165,233,0.16),rgba(244,114,182,0.16))] opacity-90 blur-2xl dark:opacity-60"></div>
        <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div class="space-y-3">
                <div class="space-y-2">
                    <h1 class="text-3xl text-slate-950 dark:text-white md:text-4xl" data-display="serif">Pending approvals</h1>
                    <p class="max-w-2xl text-sm leading-6 text-slate-600 dark:text-slate-300">
                        Review inbound encrypt and decrypt operations for <span class="font-mono text-slate-900 dark:text-slate-100">{sessionLabel}</span>.
                    </p>
                </div>
            </div>

            <div class="flex flex-col items-start gap-3 border-l border-slate-200/80 pl-0 text-sm text-slate-700 dark:border-white/10 dark:text-slate-200 lg:pl-6">
                <div>
                    Signed in as <span class="font-mono text-slate-950 dark:text-white">{sessionLabel}</span>
                </div>
                <Button variant="outline" onclick={onLogout}>
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

    <section class="relative overflow-hidden rounded-[2rem] border border-white/65 bg-white/46 p-5 shadow-[0_8px_26px_-20px_rgba(15,23,42,0.22)] backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/42">
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
                    {#if prfSecret}
                        <PendingItem
                            {item}
                            {prfSecret}
                            password={activePassword}
                            onRemoved={onRemoveItem}
                        />
                    {/if}
                {/each}
            </div>
        {/if}
    </section>

    <section class="relative overflow-hidden rounded-[2rem] border border-white/65 bg-white/46 p-5 shadow-[0_8px_26px_-20px_rgba(15,23,42,0.22)] backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/42">
        <div class="mb-4 border-b border-slate-200/80 pb-4 dark:border-white/10">
            <div class="text-sm font-medium uppercase tracking-[0.18em] text-slate-700 dark:text-slate-200">Security settings</div>
        </div>
        <div class="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
            <div class="space-y-3">
                <div class="text-sm font-medium text-slate-900 dark:text-white">Request key</div>
                <div class="mt-3 flex flex-col gap-3 xl:flex-row xl:items-center">
                    <div class="min-w-0 flex-1 rounded-[1.35rem] bg-white/60 px-4 py-3 font-mono text-sm text-slate-900 ring-1 ring-slate-200/80 dark:bg-white/6 dark:text-slate-100 dark:ring-white/10">
                        <div class="overflow-x-auto whitespace-nowrap">{requestKey}</div>
                    </div>
                    <Button
                        variant="outline"
                        onclick={onRegenerateRequestKey}
                        disabled={settingsBusy}
                    >
                        Regenerate request key
                    </Button>
                </div>
            </div>

            <div class="space-y-3 border-t border-slate-200/80 pt-6 dark:border-white/10 lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0">
                <div class="text-sm font-medium text-slate-900 dark:text-white">Allowed IPs</div>
                <div class="mt-3 flex flex-col gap-3 xl:flex-row xl:items-center">
                    <p class="min-w-0 flex-1 text-sm text-slate-600 dark:text-slate-300">
                        {allowedIpsSummary}
                    </p>
                    <Button
                        variant="neutral"
                        onclick={onOpenAllowedIpsModal}
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
            onClose={onCloseAllowedIpsModal}
        >
            <p class="mt-1 text-sm text-slate-600 dark:text-slate-300">
                One IP or CIDR per line. Leave empty to allow requests from any IP.
            </p>

            <textarea
                class="mt-4 min-h-40 w-full rounded-[1.35rem] border border-white/70 bg-white/80 px-4 py-3 font-mono text-sm text-slate-950 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-white/10 dark:bg-slate-950/70 dark:text-white dark:focus:border-sky-400 dark:focus:ring-sky-950"
                value={allowedIpsText}
                oninput={(event) => {
                    onAllowedIpsTextInput((event.currentTarget as HTMLTextAreaElement).value)
                }}
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
                    onclick={onCloseAllowedIpsModal}
                >
                    Close
                </Button>
                <Button
                    variant="neutral"
                    type="button"
                    onclick={onUpdateAllowedIps}
                    disabled={settingsBusy}
                >
                    Save allowed IPs
                </Button>
            </div>
        </Modal>
    {/if}
</div>
