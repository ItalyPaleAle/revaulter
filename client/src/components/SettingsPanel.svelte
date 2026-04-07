<script lang="ts">
import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'

interface Props {
    allowedIpsModalOpen: boolean
    allowedIpsSummary: string
    onClose: () => void
    onLogout: () => void
    onOpenAllowedIps: () => void
    onRegenerateRequestKey: () => Promise<void>
    requestKey: string
    settingsBusy: boolean
    settingsError: string | null
    settingsSuccess: string | null
}

let {
    allowedIpsModalOpen,
    allowedIpsSummary,
    onClose,
    onLogout,
    onOpenAllowedIps,
    onRegenerateRequestKey,
    requestKey,
    settingsBusy,
    settingsError,
    settingsSuccess,
}: Props = $props()
</script>

<div class="fixed inset-0 z-40 bg-slate-950/32 backdrop-blur-sm dark:bg-slate-950/58"></div>
<section class="fixed inset-0 z-50 overflow-y-auto px-4 py-4 md:px-6 md:py-6">
    <div class="mx-auto min-h-full max-w-5xl">
        <div class="rounded-4xl border border-white/90 bg-white p-5 shadow-[0_14px_40px_-28px_rgba(15,23,42,0.28)] dark:border-white/10 dark:bg-slate-950/96 md:p-6">
            <div class="relative flex items-start justify-between gap-4 border-b border-slate-200/80 pb-4 dark:border-white/10">
                <div>
                    <div class="flex items-center gap-2 text-sm font-medium uppercase tracking-[0.18em] text-slate-700 dark:text-slate-200">
                        <Icon icon="settings" title="Security settings" size="4" />
                        Security settings
                    </div>
                    <p class="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        Manage your request key, allowed IP restrictions, and session controls.
                    </p>
                </div>
                <Button
                    variant="icon"
                    size="icon"
                    ariaLabel="Close security settings"
                    onclick={onClose}
                >
                    <Icon icon="x" title="Close security settings" size="5" />
                </Button>
            </div>

            <div class="relative mt-6 grid gap-6 lg:grid-cols-[1.2fr_1fr]">
                <div class="space-y-3">
                    <div class="flex items-center gap-2 text-sm font-medium text-slate-900 dark:text-white">
                        <Icon icon="key-round" title="Request key" size="4" />
                        Request key
                    </div>
                    <div class="rounded-[1.2rem] bg-slate-50/90 px-4 py-3 font-mono text-sm text-slate-900 ring-1 ring-slate-200/80 dark:bg-white/6 dark:text-slate-100 dark:ring-white/10">
                        <div class="overflow-x-auto whitespace-nowrap">{requestKey}</div>
                    </div>
                    <Button
                        variant="outline"
                        onclick={onRegenerateRequestKey}
                        disabled={settingsBusy}
                    >
                        <Icon icon="refresh-cw" title="Regenerate request key" size="4" />
                        Regenerate request key
                    </Button>
                </div>

                <div class="space-y-3 border-t border-slate-200/80 pt-6 dark:border-white/10 lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0">
                    <div class="flex items-center gap-2 text-sm font-medium text-slate-900 dark:text-white">
                        <Icon icon="shield" title="Allowed IPs" size="4" />
                        Allowed IPs
                    </div>
                    <p class="text-sm text-slate-600 dark:text-slate-300">
                        {allowedIpsSummary}
                    </p>
                    <Button
                        variant="neutral"
                        onclick={onOpenAllowedIps}
                        disabled={settingsBusy}
                    >
                        Configure allowed IPs
                    </Button>
                </div>
            </div>

            {#if !allowedIpsModalOpen && settingsError}
                <div class="relative mt-6 rounded-2xl border border-rose-200 bg-rose-50/90 px-4 py-3 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {settingsError}
                </div>
            {:else if !allowedIpsModalOpen && settingsSuccess}
                <div class="relative mt-6 rounded-2xl border border-emerald-200 bg-emerald-50/90 px-4 py-3 text-sm text-emerald-800 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-200">
                    {settingsSuccess}
                </div>
            {/if}

            <div class="relative mt-6 border-t border-slate-200/80 pt-6 dark:border-white/10">
                <Button
                    variant="outline"
                    onclick={onLogout}
                >
                    <Icon icon="log-out" title="Sign out" size="4" />
                    Sign out
                </Button>
            </div>
        </div>
    </div>
</section>
