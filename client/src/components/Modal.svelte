<script lang="ts">
import type { Snippet } from 'svelte'

import Button from '$components/Button.svelte'

interface Props {
    ariaLabel?: string
    children?: Snippet
    class?: string
    onClose: () => void
    title?: string
}

let { ariaLabel = 'Close modal', children, class: className = '', onClose, title = '' }: Props = $props()
</script>

<div class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/45 px-4 py-6 backdrop-blur-md" role="presentation">
    <Button
        class="absolute inset-0 block rounded-none"
        type="button"
        size="none"
        variant="unstyled"
        ariaLabel={ariaLabel}
        onclick={onClose}
    />

    <div class={`relative z-10 w-full max-w-xl overflow-hidden rounded-[2rem] border border-white/70 bg-white/88 p-5 shadow-[0_10px_30px_-22px_rgba(15,23,42,0.24)] backdrop-blur-xl dark:border-white/10 dark:bg-slate-950/88 ${className}`}>
        <div class="pointer-events-none absolute inset-x-0 top-0 h-18 bg-[linear-gradient(90deg,rgba(251,191,36,0.15),rgba(14,165,233,0.12),rgba(244,114,182,0.12))] blur-2xl dark:opacity-60"></div>
        <div class="flex items-start justify-between gap-4">
            <div>
                {#if title}
                    <h2 class="text-lg font-semibold text-slate-950 dark:text-white">{title}</h2>
                {/if}
            </div>
            <Button
                size="icon"
                variant="icon"
                type="button"
                ariaLabel="Close"
                onclick={onClose}
            >
                ×
            </Button>
        </div>

        {@render children?.()}
    </div>
</div>
