<script lang="ts">
import iconDark from '$assets/icon-dark.svg?url'
import iconLight from '$assets/icon-light.svg?url'

interface Props {
    size?: number
    class?: string
}

let { size = 28, class: className = '' }: Props = $props()
</script>

<picture>
    <source srcset={iconLight} media="(prefers-color-scheme: dark)" />
    <img src={iconDark} alt="Revaulter icon" width={size} height={size} class={`inline-block shrink-0 ${className}`} aria-label="Revaulter icon" />
</picture>
