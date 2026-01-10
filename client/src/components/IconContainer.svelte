<script lang="ts">
import type { Snippet } from 'svelte'

interface Props {
    title: string
    size: string
    children: Snippet
}

const { title, size, children }: Props = $props()
</script>

{#if title}
    <svg
        xmlns="http://www.w3.org/2000/svg"
        class="w-{size} h-{size}"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        role="img"
        aria-label={title}
    >
        <title>{title}</title>
        {@render children()}
    </svg>
{:else}
    <svg
        xmlns="http://www.w3.org/2000/svg"
        class="w-{size} h-{size}"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        aria-hidden="true"
    >
        {@render children()}
    </svg>
{/if}
