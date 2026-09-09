<script lang="ts">
import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'
import Logo from '$components/Logo.svelte'

interface Props {
    clientVersion: string
    onReload: () => Promise<void>
    serverVersion: string
}

let { clientVersion, onReload, serverVersion }: Props = $props()

let reloading = $state(false)

async function reload(): Promise<void> {
    if (reloading) {
        return
    }

    reloading = true
    await onReload()
}
</script>

<main class="flex min-h-screen items-center justify-center px-6 py-12">
    <section
        class="w-full max-w-md overflow-hidden rounded-2xl border border-neutral-200 bg-white shadow-[0_24px_80px_-32px_rgba(0,0,0,0.28)] dark:border-neutral-800 dark:bg-neutral-950 dark:shadow-black/40"
        aria-labelledby="update-title"
        aria-describedby="update-description"
    >
        <div class="h-1 bg-(--app-accent)"></div>

        <div class="p-7 sm:p-9">
            <div class="mb-8 flex items-center justify-between">
                <Logo size={44} />
                <div class="flex h-10 w-10 items-center justify-center rounded-full bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300">
                    <Icon icon="refresh-cw" title="Update available" size="5" />
                </div>
            </div>

            <h1 id="update-title" class="text-[28px] font-semibold leading-tight tracking-tight text-neutral-950 dark:text-neutral-50">
                Update available
            </h1>
            <p id="update-description" class="mt-3 mb-7 text-[15px] leading-6 text-neutral-600 dark:text-neutral-400">
                Revaulter was updated on the server.<br/>
                Reload this page before continuing to keep the app and server in sync.
            </p>

            <Button variant="primary" size="lg" width="full" disabled={reloading} onclick={() => void reload()}>
                {#if reloading}
                    <LoadingSpinner size="1rem" />
                    Loading the update…
                {:else}
                    <Icon icon="refresh-cw" title="Reload" size="4" />
                    Reload Revaulter
                {/if}
            </Button>
        </div>
    </section>
</main>
