<script lang="ts">
import type { Snippet } from 'svelte'

interface Props {
    title: string
    size: string
    children: Snippet
}

const { title, size, children }: Props = $props()

function svgSize(value: string) {
    if (/^\d+(\.\d+)?$/.test(value)) {
        return `${Number(value) * 0.25}rem`
    }
    return value
}
</script>

{#if title}
    <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        role="img"
        aria-label={title}
        style={`width: ${svgSize(size)}; height: ${svgSize(size)};`}
    >
        <title>{title}</title>
        {@render children()}
    </svg>
{:else}
    <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        aria-hidden="true"
        style={`width: ${svgSize(size)}; height: ${svgSize(size)};`}
    >
        {@render children()}
    </svg>
{/if}
