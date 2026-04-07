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
            return 'bg-slate-950 text-white hover:bg-slate-800 dark:bg-white dark:text-slate-950 dark:hover:bg-slate-100'
        case 'neutral':
            return 'bg-[rgba(255,255,255,0.22)] text-slate-900 ring-1 ring-white/70 hover:bg-[rgba(255,255,255,0.32)] dark:bg-white/10 dark:text-white dark:ring-white/12 dark:hover:bg-white/16'
        case 'surface':
            return 'bg-transparent text-slate-700 hover:bg-white/45 dark:text-slate-100 dark:hover:bg-white/6'
        case 'danger':
            return 'bg-rose-600 text-white hover:bg-rose-500'
        case 'success':
            return 'bg-emerald-600 text-white hover:bg-emerald-500'
        case 'icon':
            return 'bg-white/60 text-slate-600 ring-1 ring-slate-200/80 hover:bg-white dark:bg-white/8 dark:text-slate-200 dark:ring-white/10 dark:hover:bg-white/14'
        case 'unstyled':
            return ''
        case 'outline':
            return 'text-slate-700 ring-1 ring-slate-300/80 hover:bg-white/45 dark:text-slate-100 dark:ring-white/12 dark:hover:bg-white/6'
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
    class={`inline-flex cursor-pointer items-center justify-center gap-2 rounded-full font-medium transition duration-150 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-200 dark:focus-visible:ring-sky-950 disabled:cursor-not-allowed disabled:opacity-60 ${variantClass(variant)} ${sizeClass(size)} ${widthClass(width)} ${className}`}
    onclick={onclick}
>
    {@render children?.()}
</button>
