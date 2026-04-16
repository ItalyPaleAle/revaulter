<script lang="ts">
import type { HTMLInputAttributes } from 'svelte/elements'

interface Props {
    autocomplete?: HTMLInputAttributes['autocomplete']
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

<input
    {autocomplete}
    {disabled}
    {id}
    {name}
    {placeholder}
    {required}
    {type}
    bind:value
    class={`w-full rounded-[1.35rem] border border-slate-300/90 bg-white/92 px-4 py-3 text-slate-950 outline-none transition focus:border-sky-500 focus:ring-2 focus:ring-sky-200 dark:border-slate-600/80 dark:bg-slate-950/72 dark:text-white dark:focus:border-sky-400 dark:focus:ring-sky-950 ${className}`}
    oninput={oninput}
/>
