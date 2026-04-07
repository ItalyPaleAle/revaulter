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

<div class="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/55 px-4 py-6 backdrop-blur-sm" role="presentation">
    <Button
        class="absolute inset-0 block rounded-none"
        type="button"
        size="none"
        variant="unstyled"
        ariaLabel={ariaLabel}
        onclick={onClose}
    />

    <div class={`relative z-10 w-full max-w-xl rounded-4xl border border-white/70 bg-white/95 p-5 shadow-[0_30px_90px_-35px_rgba(15,23,42,0.65)] dark:border-slate-800 dark:bg-slate-950/95 ${className}`}>
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
