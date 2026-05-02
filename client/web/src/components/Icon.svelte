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
    {:else if icon == 'lock-keyhole'}
        <IconContainer {title} {size}>
            <circle cx="12" cy="16" r="1" />
            <rect width="18" height="12" x="3" y="10" rx="2" />
            <path d="M7 10V7a5 5 0 0 1 10 0v3" />
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
    {:else if icon == 'scroll-text'}
        <IconContainer {title} {size}>
            <path d="M15 12h-5" />
            <path d="M15 8h-5" />
            <path d="M19 17V5a2 2 0 0 0-2-2H4" />
            <path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3" />
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
           <path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>
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
    {:else if icon == 'brick-wall-shield'}
        <IconContainer {title} {size}>
            <path d="M12 9v1.258" />
            <path d="M16 3v5.46" />
            <path d="M21 9.118V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5.75" />
            <path d="M22 17.5c0 2.499-1.75 3.749-3.83 4.474a.5.5 0 0 1-.335-.005c-2.085-.72-3.835-1.97-3.835-4.47V14a.5.5 0 0 1 .5-.499c1 0 2.25-.6 3.12-1.36a.6.6 0 0 1 .76-.001c.875.765 2.12 1.36 3.12 1.36a.5.5 0 0 1 .5.5z" />
            <path d="M3 15h7" />
            <path d="M3 9h12.142" />
            <path d="M8 15v6" />
            <path d="M8 3v6" />
        </IconContainer>
    {:else if icon == 'log-out'}
        <IconContainer {title} {size}>
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <path d="M16 17l5-5-5-5" />
            <path d="M21 12H9" />
        </IconContainer>
    {:else if icon == 'copy'}
        <IconContainer {title} {size}>
            <rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
            <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
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
    {:else if icon == 'download'}
        <IconContainer {title} {size}>
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <path d="M7 10l5 5 5-5" />
            <path d="M12 15V3" />
        </IconContainer>
    {:else if icon == 'upload-cloud'}
        <IconContainer {title} {size}>
            <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242" />
            <path d="M12 12v9" />
            <path d="m16 16-4-4-4 4" />
        </IconContainer>
    {:else if icon == 'cloud-off'}
        <IconContainer {title} {size}>
            <path d="m2 2 20 20" />
            <path d="M5.782 5.782A7 7 0 0 0 9 19h8.5a4.5 4.5 0 0 0 1.307-.193" />
            <path d="M21.532 16.5A4.5 4.5 0 0 0 17.5 10h-1.79A7.008 7.008 0 0 0 10 5.07" />
        </IconContainer>
    {:else if icon == 'user-round-pen'}
        <IconContainer {title} {size}>
            <path d="M2 21a8 8 0 0 1 10.821-7.487" />
            <path d="M21.378 16.626a1 1 0 0 0-3.004-3.004l-4.01 4.012a2 2 0 0 0-.506.854l-.837 2.87a.5.5 0 0 0 .62.62l2.87-.837a2 2 0 0 0 .854-.506z" />
            <circle cx="10" cy="8" r="5" />
        </IconContainer>
    {:else if icon == 'arrow-right'}
        <IconContainer {title} {size}>
            <path d="M5 12h14M13 5l7 7-7 7" />
        </IconContainer>
    {:else if icon == 'chevron-down'}
        <IconContainer {title} {size}>
            <path d="m6 9 6 6 6-6" />
        </IconContainer>
    {:else if icon == 'loader'}
        <IconContainer {title} {size}>
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
        </IconContainer>
    {/if}
</i>
