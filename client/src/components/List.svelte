<script lang="ts">
import { onMount } from 'svelte'
import ndjson from '../lib/ndjson'
import { ThrowResponseNotOk } from '../lib/request'
import { type pendingRequestItem, pendingRequestStatus } from '../lib/types'
import Icon from './Icon.svelte'
import LoadingSpinner from './LoadingSpinner.svelte'
import PendingItem from './PendingItem.svelte'

interface Props {
    onsessionExpired?: (value: boolean) => void
}

const { onsessionExpired }: Props = $props()

let list: Record<string, pendingRequestItem & { _submit?: (confirm: boolean) => void }> | null = $state(null)
let pageError: string | null = $state(null)
let redirectTimeout: ReturnType<typeof setTimeout> | null = null

let stop: (() => void) | null = null

onMount(() => {
    // Subscribe to the list of pending items
    stop = Subscribe()

    return () => {
        if (stop) {
            stop()
            stop = null
        }
    }
})

// Subscribe to the stream of pending states
// Returns a function that stops the stream
function Subscribe(): () => void {
    let controller: AbortController | null = null

    const stopFn = () => {
        controller?.abort()
        controller = null
    }

    // Start the subscription in background
    void (async () => {
        try {
            while (!controller || !controller.signal.aborted) {
                controller = new AbortController()

                // We can't use the higher-level Request API here because we need to get access to the stream
                const res = await fetch(`${import.meta.env.VITE_URL_PREFIX || ''}/api/list`, {
                    headers: new Headers({
                        accept: 'application/x-ndjson ',
                    }),
                    credentials: 'same-origin',
                    cache: 'no-store',
                    signal: controller.signal,
                })
                if (!res.ok) {
                    // If the error is that we got a 401 response, redirect to the auth page
                    if (res.status == 401) {
                        RedirectToAuth()
                        return
                    }
                    await ThrowResponseNotOk(res)
                }

                // Check if the session has expired
                let ttl = 0
                const ttlHeader = res.headers.get('x-session-ttl')
                if (ttlHeader) {
                    ttl = Number.parseInt(ttlHeader, 10)
                    if (ttl < 1) {
                        ttl = 0
                    }
                }
                if (ttl < 2) {
                    stopFn()
                    RedirectToAuth()
                    return
                }

                // When the session has expired, send a notification to the App
                if (redirectTimeout) {
                    clearTimeout(redirectTimeout)
                }
                // Send the signal 1 second earlier so this is triggered before the server closes the request
                // If the server gets to this before the client, the loop is restarted and the client is redirected (see above where we check for 401 responses) rather than seeing a message here
                redirectTimeout = setTimeout(
                    () => {
                        stopFn()
                        onsessionExpired?.(true)
                    },
                    (ttl - 1) * 1000
                )

                // Get the stream of NDJSON messages
                if (!res.body) {
                    throw Error('Response does not contain any body')
                }

                // We have a stream now so we can initialize the list
                if (list === null) {
                    list = {}
                }

                const gen = ndjson<pendingRequestItem>(res.body.getReader())
                // eslint-disable-line no-constant-condition
                while (true) {
                    const { done, value } = await gen.next()
                    if (done) {
                        break
                    }
                    if (value) {
                        UpdateList(value)
                    }
                }
            }
        } catch (err) {
            pageError = `Error: ${err}`
            stopFn()
        }
    })()

    return stopFn
}

function UpdateList(el: pendingRequestItem) {
    if (!el?.state || !list) {
        return
    }

    // Set or update the element in the list
    if (!list[el.state]?.status) {
        list[el.state] = el
    } else if (list[el.state].status == pendingRequestStatus.pendingRequestPending) {
        list[el.state].status = el.status
    }
}

let hasRedirected = false
function RedirectToAuth() {
    if (!hasRedirected) {
        // Use a flag to prevent multiple redirects
        hasRedirected = true
        window.location.href = `${import.meta.env.VITE_URL_PREFIX || ''}/auth/signin`
    }
}

function SubmitAll(confirm: boolean) {
    if (!list) {
        return
    }
    for (const key in list) {
        const el = list[key]
        if (!el) {
            continue
        }
        if (!el._submit || el.status != pendingRequestStatus.pendingRequestPending) {
            continue
        }
        el._submit(confirm)
    }
}
</script>

<h1 class="text-lg font-medium text-slate-900 dark:text-white">Pending requests</h1>

{#if pageError}
    <p class="p-2 mt-2 border rounded-xs bg-rose-50 dark:bg-rose-800 text-rose-800 dark:text-white border-rose-700 dark:border-rose-900">Failed to list pending items: {pageError}</p>
{/if}
{#if list === null}
    <div class="px-8 py-8 mx-auto my-4 text-lg text-center bg-white rounded-lg shadow-lg lg:text-left lg:pl-20 dark:bg-slate-800 ring-1 ring-slate-900/5 text-slate-700 dark:text-slate-200">
        <LoadingSpinner size="3rem" /> Loading…
    </div>
{:else}
    <div class="pt-2 space-y-4">
        {#if Object.keys(list).length > 1}
            <div class="flex flex-row w-full mx-auto md:w-2/3">
                <div
                    role="button"
                    tabindex="0"
                    class="flex flex-row items-center flex-auto p-2 m-2 rounded-sm shadow-xs text-emerald-700 dark:text-emerald-400 hover:text-slate-900 dark:hover:text-white bg-slate-200 dark:bg-slate-700 border-emerald-300 dark:border-emerald-600 hover:bg-emerald-300 dark:hover:bg-emerald-600 cursor-pointer"
                    onclick={() => SubmitAll(true)}
                    onkeypress={() => SubmitAll(true)}
                >
                    <span class="pr-2 w-7">
                        <Icon icon="check-circle" title="" size={'5'} />
                    </span>
                    <span>Confirm All</span>
                </div>
                <div
                    role="button"
                    tabindex="0"
                    class="flex flex-row items-center flex-auto p-2 m-2 rounded-sm shadow-xs text-rose-700 dark:text-rose-400 hover:text-slate-900 dark:hover:text-white bg-slate-200 dark:bg-slate-700 border-rose-300 dark:border-rose-600 hover:bg-rose-300 dark:hover:bg-rose-600 cursor-pointer"
                    onclick={() => SubmitAll(false)}
                    onkeypress={() => SubmitAll(false)}
                >
                    <span class="pr-2 w-7">
                        <Icon icon="x-circle" title="" size={'5'} />
                    </span>
                    <span>Cancel All</span>
                </div>
            </div>
        {/if}
        {#each Object.entries(list) as [state, item] (state)}
            <div class="px-4 py-2 mx-auto my-4 bg-white rounded-lg shadow-lg dark:bg-slate-800 ring-1 ring-slate-900/5 text-slate-700 dark:text-slate-200">
                <PendingItem {item} bind:submit={item._submit} />
            </div>
        {:else}
            <div class="px-4 py-5 mx-auto my-4 bg-white rounded-lg shadow-lg dark:bg-slate-800 ring-1 ring-slate-900/5 text-slate-700 dark:text-slate-200">
                <p>There's no request pending your action at this time.</p>
                <p class="text-sm">Need help getting started? Check out the <a href="https://github.com/italypaleale/revaulter#apis" class="underline hover:text-slate-900 dark:hover:text-white">documentation</a> for the APIs.</p>
            </div>
        {/each}
    </div>
{/if}
