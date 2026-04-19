<script lang="ts">
interface Props {
    size?: number
    radius?: number
    class?: string
}

let { size = 28, radius = 7, class: className = '' }: Props = $props()
</script>

<span
    class={`inline-flex shrink-0 items-center justify-center bg-neutral-950 text-neutral-50 dark:bg-neutral-50 dark:text-neutral-950 ${className}`}
    style={`width: ${size}px; height: ${size}px; border-radius: ${radius}px;`}
    aria-hidden="true"
>
    <svg viewBox="0 0 32 32" width={Math.round(size * 0.64)} height={Math.round(size * 0.64)} fill="none">
        <path
            d="M11 9v14M11 9h6a4 4 0 0 1 0 8h-6M15 17l5 6"
            stroke="currentColor"
            stroke-width="2.4"
            stroke-linecap="round"
            stroke-linejoin="round"
        />
    </svg>
</span>
