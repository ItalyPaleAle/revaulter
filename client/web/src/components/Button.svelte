<script lang="ts">
import type { Snippet } from 'svelte'

interface Props {
    ariaLabel?: string
    children?: Snippet
    class?: string
    disabled?: boolean
    onclick?: (event: MouseEvent) => void
    size?: 'sm' | 'md' | 'lg' | 'icon' | 'none'
    title?: string
    type?: 'button' | 'submit' | 'reset'
    variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'icon' | 'unstyled'
    width?: 'auto' | 'full'
}

let {
    ariaLabel,
    children,
    class: className = '',
    disabled = false,
    onclick,
    size = 'md',
    title,
    type = 'button',
    variant = 'secondary',
    width = 'auto',
}: Props = $props()

function variantClass(value: typeof variant) {
    switch (value) {
        case 'primary':
            return 'bg-neutral-950 text-neutral-50 border border-neutral-950 hover:opacity-90 dark:bg-neutral-50 dark:text-neutral-950 dark:border-neutral-50'
        case 'secondary':
            return 'bg-white text-neutral-900 border border-neutral-300 hover:border-neutral-900 dark:bg-neutral-900 dark:text-neutral-50 dark:border-neutral-700 dark:hover:border-neutral-300'
        case 'ghost':
            return 'bg-transparent text-neutral-500 border border-transparent hover:bg-neutral-100 hover:text-neutral-900 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-50'
        case 'danger':
            return 'bg-transparent text-rose-600 border border-neutral-200 hover:border-rose-400 dark:text-rose-400 dark:border-neutral-800 dark:hover:border-rose-500'
        case 'icon':
            return 'bg-white text-neutral-500 border border-neutral-200 hover:text-neutral-900 hover:border-neutral-300 dark:bg-neutral-900 dark:text-neutral-400 dark:border-neutral-800 dark:hover:text-neutral-50 dark:hover:border-neutral-700'
        case 'unstyled':
            return ''
    }
}

function sizeClass(value: typeof size) {
    switch (value) {
        case 'sm':
            return 'h-[30px] px-3 text-[13px]'
        case 'md':
            return 'h-9 px-3.5 text-[13px]'
        case 'lg':
            return 'h-11 px-4.5 text-sm'
        case 'icon':
            return 'h-9 w-9 p-0 text-sm'
        case 'none':
            return ''
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
    {title}
    aria-label={ariaLabel}
    class={`inline-flex cursor-pointer items-center justify-center gap-2 rounded-lg font-medium transition duration-150 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-400/70 dark:focus-visible:ring-neutral-500/70 disabled:cursor-not-allowed disabled:opacity-50 ${variantClass(variant)} ${sizeClass(size)} ${widthClass(width)} ${className}`}
    onclick={onclick}
>
    {@render children?.()}
</button>
