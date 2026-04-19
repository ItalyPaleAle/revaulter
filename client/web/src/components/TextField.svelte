<script lang="ts">
import type { HTMLInputAttributes } from 'svelte/elements'

interface Props {
    autocomplete?: HTMLInputAttributes['autocomplete']
    autofocus?: boolean
    class?: string
    disabled?: boolean
    id?: string
    name?: string
    oninput?: (event: Event) => void
    placeholder?: string
    required?: boolean
    type?: 'text' | 'password' | 'email'
    value?: string
}

let {
    autocomplete,
    autofocus,
    class: className = '',
    disabled = false,
    id,
    name,
    oninput,
    placeholder,
    required = false,
    type = 'text',
    value = $bindable(''),
}: Props = $props()
</script>

<!-- svelte-ignore a11y_autofocus -->
<input
    {autocomplete}
    {autofocus}
    {disabled}
    {id}
    {name}
    {placeholder}
    {required}
    {type}
    bind:value
    class={`h-10.5 w-full rounded-lg border border-neutral-300 bg-white px-3 text-sm text-neutral-900 outline-none transition-colors focus:border-neutral-900 disabled:cursor-not-allowed disabled:opacity-60 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-50 dark:focus:border-neutral-300 ${className}`}
    oninput={oninput}
/>
