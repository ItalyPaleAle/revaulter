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

    <div class={`relative z-10 w-full max-w-xl rounded-4xl border border-white/90 bg-white p-5 shadow-[0_10px_30px_-22px_rgba(15,23,42,0.24)] dark:border-white/10 dark:bg-slate-950/94 ${className}`}>
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
