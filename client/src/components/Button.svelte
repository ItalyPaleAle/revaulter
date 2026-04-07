<script lang="ts">
import type { Snippet } from 'svelte'

interface Props {
    ariaLabel?: string
    children?: Snippet
    class?: string
    disabled?: boolean
    onclick?: (event: MouseEvent) => void
    size?: 'sm' | 'md' | 'lg' | 'icon' | 'none'
    type?: 'button' | 'submit' | 'reset'
    variant?: 'primary' | 'neutral' | 'outline' | 'surface' | 'danger' | 'success' | 'icon' | 'unstyled'
    width?: 'auto' | 'full'
}

let {
    ariaLabel,
    children,
    class: className = '',
    disabled = false,
    onclick,
    size = 'md',
    type = 'button',
    variant = 'outline',
    width = 'auto',
}: Props = $props()

function variantClass(value: typeof variant) {
    switch (value) {
        case 'primary':
            return 'bg-sky-600 text-white hover:bg-sky-500'
        case 'neutral':
            return 'bg-slate-950 text-white hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-950 dark:hover:bg-white'
        case 'surface':
            return 'border border-slate-300 bg-white/70 text-slate-700 shadow-sm hover:border-slate-400 hover:bg-white dark:border-slate-700 dark:bg-slate-950/60 dark:text-slate-100 dark:hover:border-slate-600 dark:hover:bg-slate-950'
        case 'danger':
            return 'bg-rose-600 text-white hover:bg-rose-500'
        case 'success':
            return 'bg-emerald-600 text-white hover:bg-emerald-500'
        case 'icon':
            return 'border border-slate-300 text-slate-600 hover:border-slate-400 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-200 dark:hover:border-slate-600 dark:hover:bg-slate-900'
        case 'unstyled':
            return ''
        case 'outline':
            return 'border border-slate-300 text-slate-700 hover:border-slate-400 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-100 dark:hover:border-slate-600 dark:hover:bg-slate-800'
    }
}

function sizeClass(value: typeof size) {
    switch (value) {
        case 'sm':
            return 'px-3 py-2 text-sm'
        case 'lg':
            return 'px-4 py-3 text-sm font-semibold'
        case 'icon':
            return 'h-10 w-10 p-0 text-lg'
        case 'none':
            return ''
        case 'md':
            return 'px-4 py-2 text-sm'
    }
}

function widthClass(value: typeof width) {
    if (value === 'full') {
        return 'w-full'
    }
    return ''
}
</script>

<button
    {type}
    {disabled}
    aria-label={ariaLabel}
    class={`inline-flex cursor-pointer items-center justify-center gap-2 rounded-full font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-200 dark:focus-visible:ring-sky-950 disabled:cursor-not-allowed disabled:opacity-60 ${variantClass(variant)} ${sizeClass(size)} ${widthClass(width)} ${className}`}
    onclick={onclick}
>
    {@render children?.()}
</button>
