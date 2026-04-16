<script lang="ts">
import IconContainer from '$components/IconContainer.svelte'

interface Props {
    icon: string
    title: string
    size?: string
}

const { icon, title, size = '12' }: Props = $props()
</script>

<!--
    All icons from lucide.dev
    Copyright (c) Lucide Contributors
    Licensed under ISC license: https://github.com/lucide-icons/lucide/blob/main/LICENSE
-->
<i class="w-{size}">
    {#if icon == 'lock-open'}
        <IconContainer {title} {size}>
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 9.9-1" />
        </IconContainer>
    {:else if icon == 'lock-closed'}
        <IconContainer {title} {size}>
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </IconContainer>
    {:else if icon == 'key'}
        <IconContainer {title} {size}>
            <path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4" />
            <path d="m21 2-9.6 9.6" />
            <circle cx="7.5" cy="15.5" r="5.5" />
        </IconContainer>
    {:else if icon == 'clock'}
        <IconContainer {title} {size}>
            <circle cx="12" cy="12" r="10" />
            <path d="M12 6v6l4 2" />
        </IconContainer>
    {:else if icon == 'note'}
        <IconContainer {title} {size}>
            <path d="M22 17a2 2 0 0 1-2 2H6.828a2 2 0 0 0-1.414.586l-2.202 2.202A.71.71 0 0 1 2 21.286V5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2z" />
            <path d="M7 11h10" />
            <path d="M7 15h6" />
            <path d="M7 7h8" />
        </IconContainer>
    {:else if icon == 'check-circle'}
        <IconContainer {title} {size}>
            <circle cx="12" cy="12" r="10" />
            <path d="m9 12 2 2 4-4" />
        </IconContainer>
    {:else if icon == 'pencil'}
        <IconContainer {title} {size}>
            <path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z" />
            <path d="m15 5 4 4" />
        </IconContainer>
    {:else if icon == 'check-badge'}
        <IconContainer {title} {size}>
            <path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z" />
            <path d="m9 12 2 2 4-4" />
        </IconContainer>
    {:else if icon == 'x-circle'}
        <IconContainer {title} {size}>
            <circle cx="12" cy="12" r="10" />
            <path d="m15 9-6 6" />
            <path d="m9 9 6 6" />
        </IconContainer>
    {:else if icon == 'data'}
        <IconContainer {title} {size}>
            <ellipse cx="12" cy="5" rx="9" ry="3" />
            <path d="M3 5V19A9 3 0 0 0 21 19V5" />
            <path d="M3 12A9 3 0 0 0 21 12" />
        </IconContainer>
    {:else if icon == 'settings'}
        <IconContainer {title} {size}>
            <path d="M14 17H5" />
            <path d="M19 7h-9" />
            <circle cx="17" cy="17" r="3" />
            <circle cx="7" cy="7" r="3" />
        </IconContainer>
    {:else if icon == 'key-round'}
        <IconContainer {title} {size}>
            <path d="M15.5 14.5 18 17l4-4" />
            <circle cx="7.5" cy="15.5" r="5.5" />
        </IconContainer>
    {:else if icon == 'refresh-cw'}
        <IconContainer {title} {size}>
            <path d="M21 12a9 9 0 0 0-15.5-6.36L3 8" />
            <path d="M3 3v5h5" />
            <path d="M3 12a9 9 0 0 0 15.5 6.36L21 16" />
            <path d="M16 16h5v5" />
        </IconContainer>
    {:else if icon == 'shield'}
        <IconContainer {title} {size}>
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
        </IconContainer>
    {:else if icon == 'log-out'}
        <IconContainer {title} {size}>
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <path d="M16 17l5-5-5-5" />
            <path d="M21 12H9" />
        </IconContainer>
    {:else if icon == 'clipboard-copy'}
        <IconContainer {title} {size}>
            <rect width="8" height="4" x="8" y="2" rx="1" ry="1" />
            <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" />
        </IconContainer>
    {:else if icon == 'check'}
        <IconContainer {title} {size}>
            <path d="M20 6 9 17l-5-5" />
        </IconContainer>
    {:else if icon == 'x'}
        <IconContainer {title} {size}>
            <path d="M18 6 6 18" />
            <path d="m6 6 12 12" />
        </IconContainer>
    {:else if icon == 'user'}
        <IconContainer {title} {size}>
            <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" />
            <circle cx="12" cy="7" r="4" />
        </IconContainer>
    {:else if icon == 'fingerprint'}
        <IconContainer {title} {size}>
            <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
            <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
            <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
            <path d="M2 12a10 10 0 0 1 18-6" />
            <path d="M2 16h.01" />
            <path d="M21.8 16c.2-2 .131-5.354 0-6" />
            <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" />
            <path d="M8.65 22c.21-.66.45-1.32.57-2" />
            <path d="M9 6.8a6 6 0 0 1 9 5.2v2" />
        </IconContainer>
    {:else if icon == 'trash'}
        <IconContainer {title} {size}>
            <path d="M3 6h18" />
            <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" />
            <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" />
        </IconContainer>
    {:else if icon == 'plus'}
        <IconContainer {title} {size}>
            <path d="M5 12h14" />
            <path d="M12 5v14" />
        </IconContainer>
    {/if}
</i>
