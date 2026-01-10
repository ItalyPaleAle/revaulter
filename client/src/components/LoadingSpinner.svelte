<script lang="ts">
interface Props {
    size?: string
}

const { size = '1.5rem' }: Props = $props()
</script>

<!--
Based on:https://loading.io/css/
License: CC0
-->
<div class="lds-ring" style="--ring-size: {size}" aria-hidden="true">
    <div></div>
    <div></div>
    <div></div>
    <div></div>
</div>

<style>
    .lds-ring {
        display: inline-block;
        position: relative;
        width: var(--ring-size);
        height: var(--ring-size);
        margin: 0 calc(var(--ring-size) * 0.1);
        vertical-align: middle;

        --ring-color: #0369a1; /* sky-700 */
    }

    @media (prefers-color-scheme: dark) {
        .lds-ring {
            --ring-color: #bae6fd; /* sky-200 */
        }
    }

    .lds-ring div {
        box-sizing: border-box;
        display: block;
        position: absolute;
        width: calc(var(--ring-size) * 0.8);
        height: calc(var(--ring-size) * 0.8);
        margin: calc(var(--ring-size) * 0.1);
        border: calc(var(--ring-size) * 0.1) solid var(--ring-color);
        border-radius: 50%;
        animation: lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
        border-color: var(--ring-color) transparent transparent transparent;
    }

    .lds-ring div:nth-child(1) {
        animation-delay: -0.45s;
    }

    .lds-ring div:nth-child(2) {
        animation-delay: -0.3s;
    }

    .lds-ring div:nth-child(3) {
        animation-delay: -0.15s;
    }

    @keyframes lds-ring {
        0% {
            transform: rotate(0deg);
        }

        100% {
            transform: rotate(360deg);
        }
    }
</style>
