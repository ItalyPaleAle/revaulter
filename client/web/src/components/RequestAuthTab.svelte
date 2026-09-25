<script lang="ts">
import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import TextField from '$components/TextField.svelte'

import type { V2RequestAuthMethods, V2RequestOIDCIssuer } from '$lib/v2-types'

interface Props {
    userId: string
    requestKey: string
    requestKeyEnabled: boolean
    requestOidcEnabled: boolean
    requestOidcIssuers: V2RequestOIDCIssuer[]
    busy: boolean
    onRegenerateRequestKey: () => Promise<void>
    onSetRequestAuthMethods: (methods: V2RequestAuthMethods) => Promise<void>
    onAddRequestOIDCIssuer: (issuer: {
        displayName: string
        issuer: string
        audience: string
        subject: string
        jwksUrl: string
    }) => Promise<boolean>
    onDeleteRequestOIDCIssuer: (id: string) => Promise<void>
}

let {
    userId,
    requestKey,
    requestKeyEnabled,
    requestOidcEnabled,
    requestOidcIssuers,
    busy,
    onRegenerateRequestKey,
    onSetRequestAuthMethods,
    onAddRequestOIDCIssuer,
    onDeleteRequestOIDCIssuer,
}: Props = $props()

let copiedValue = $state<string | null>(null)
let confirmingRegenerate = $state(false)

let showAddIssuer = $state(false)
let issuerName = $state('')
let issuerUrl = $state('')
let issuerAudience = $state('')
let issuerSubject = $state('')
let issuerJwksUrl = $state('')

function copyToClipboard(value: string) {
    navigator.clipboard.writeText(value).then(() => {
        copiedValue = value
        setTimeout(() => {
            if (copiedValue === value) {
                copiedValue = null
            }
        }, 2000)
    })
}

async function handleToggle(event: Event, method: 'requestKey' | 'oidc') {
    // Keep a reference to the input, since currentTarget is null once the handler awaits
    const input = event.currentTarget as HTMLInputElement
    const checked = input.checked
    await onSetRequestAuthMethods({
        requestKeyEnabled: method === 'requestKey' ? checked : requestKeyEnabled,
        requestOidcEnabled: method === 'oidc' ? checked : requestOidcEnabled,
    })

    // The input only follows the props when they change, so reset it to the saved value
    // If the update failed, the props didn't change, and this undoes the click
    input.checked = method === 'requestKey' ? requestKeyEnabled : requestOidcEnabled
}

async function handleRegenerate() {
    confirmingRegenerate = false
    await onRegenerateRequestKey()
}

function openAddIssuer() {
    issuerName = ''
    issuerUrl = ''
    // The audience defaults to the public endpoint of this server
    issuerAudience = window.location.origin
    issuerSubject = ''
    issuerJwksUrl = ''
    showAddIssuer = true
}

async function handleAddIssuer() {
    const ok = await onAddRequestOIDCIssuer({
        displayName: issuerName,
        issuer: issuerUrl,
        audience: issuerAudience,
        subject: issuerSubject,
        jwksUrl: issuerJwksUrl,
    })
    if (ok) {
        showAddIssuer = false
    }
}
</script>

<div class="max-w-2xl space-y-4">
    <div>
        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Authentication methods</div>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
            Choose how the CLI and other clients can authenticate the requests they send you. You can enable both.
        </p>
    </div>

    <!-- Request key -->
    <div class="space-y-4 rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
        <label class="flex gap-3 {busy ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}">
            <input
                type="checkbox"
                class="mt-0.5 size-4 shrink-0 cursor-pointer accent-neutral-900 disabled:cursor-not-allowed dark:accent-neutral-100"
                checked={requestKeyEnabled}
                disabled={busy}
                onchange={(event) => handleToggle(event, 'requestKey')}
            />
            <span>
                <span class="flex items-center gap-1.5 text-sm font-medium text-neutral-900 dark:text-neutral-50">
                    <Icon icon="key-round" title="Request key" size="4" />
                    Request key
                </span>
                <span class="mt-0.5 block text-sm text-neutral-500 dark:text-neutral-400">The CLI sends a static request key.</span>
            </span>
        </label>

        {#if requestKeyEnabled}
            <div class="space-y-2 pl-7">
                <div class="flex items-center gap-2">
                    <div class="flex min-w-0 max-w-80 flex-1 items-center rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950/40">
                        <div class="mono min-w-0 flex-1 overflow-x-auto whitespace-nowrap px-3 py-2 text-sm text-neutral-900 dark:text-neutral-100">{requestKey}</div>
                        <button
                            type="button"
                            class="flex shrink-0 cursor-pointer items-center justify-center rounded-r-lg border-l border-neutral-200 px-2.5 py-2 text-neutral-500 transition hover:bg-neutral-100 hover:text-neutral-900 dark:border-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-50"
                            aria-label="Copy to clipboard"
                            onclick={() => copyToClipboard(requestKey)}
                        >
                            {#if copiedValue === requestKey}
                                <Icon icon="check" title="Copied" size="4" />
                            {:else}
                                <Icon icon="copy" title="Copy to clipboard" size="4" />
                            {/if}
                        </button>
                    </div>
                    <Button
                        variant="secondary"
                        onclick={() => {
                            confirmingRegenerate = true
                        }}
                        disabled={busy || confirmingRegenerate}
                    >
                        <Icon icon="refresh-cw" title="Regenerate" size="3.5" />
                        Regenerate
                    </Button>
                </div>
                {#if confirmingRegenerate}
                    <div class="rounded-lg border border-amber-200 bg-amber-50 px-3.5 py-3 dark:border-amber-900/70 dark:bg-amber-950/40">
                        <p class="text-sm font-medium text-amber-800 dark:text-amber-200">Are you sure?</p>
                        <p class="mt-1 text-sm text-amber-700 dark:text-amber-300">This will invalidate the existing Request key.</p>
                        <div class="mt-3 flex gap-2">
                            <Button variant="danger" onclick={handleRegenerate} disabled={busy}>
                                Yes, regenerate
                            </Button>
                            <Button
                                variant="secondary"
                                onclick={() => {
                                    confirmingRegenerate = false
                                }}
                            >
                                Cancel
                            </Button>
                        </div>
                    </div>
                {/if}
            </div>
        {/if}
    </div>

    <!-- OIDC tokens -->
    <div class="space-y-4 rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
        <label class="flex gap-3 {busy ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'}">
            <input
                type="checkbox"
                class="mt-0.5 size-4 shrink-0 cursor-pointer accent-neutral-900 disabled:cursor-not-allowed dark:accent-neutral-100"
                checked={requestOidcEnabled}
                disabled={busy}
                onchange={(event) => handleToggle(event, 'oidc')}
            />
            <span>
                <span class="flex items-center gap-1.5 text-sm font-medium text-neutral-900 dark:text-neutral-50">
                    <Icon icon="shield" title="OIDC tokens" size="4" />
                    OIDC tokens
                </span>
                <span class="mt-0.5 block text-sm text-neutral-500 dark:text-neutral-400">
                    The CLI sends a short-lived JWT signed by one of your trusted issuers (for example, a GitHub Actions OIDC token or a Kubernetes Service Account Token) together with your user ID.
                </span>
            </span>
        </label>

        {#if requestOidcEnabled}
            <div class="space-y-5 pl-7">
                <!-- User ID -->
                <div class="space-y-2">
                    <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">User ID</div>
                    <div class="flex min-w-0 max-w-md items-center rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950/40">
                        <div class="mono min-w-0 flex-1 overflow-x-auto whitespace-nowrap px-3 py-2 text-sm text-neutral-900 dark:text-neutral-100">{userId}</div>
                        <button
                            type="button"
                            class="flex shrink-0 cursor-pointer items-center justify-center rounded-r-lg border-l border-neutral-200 px-2.5 py-2 text-neutral-500 transition hover:bg-neutral-100 hover:text-neutral-900 dark:border-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-50"
                            aria-label="Copy user ID to clipboard"
                            onclick={() => copyToClipboard(userId)}
                        >
                            {#if copiedValue === userId}
                                <Icon icon="check" title="Copied" size="4" />
                            {:else}
                                <Icon icon="copy" title="Copy to clipboard" size="4" />
                            {/if}
                        </button>
                    </div>
                    <p class="text-xs text-neutral-500 dark:text-neutral-400">
                        Pass it to the CLI with <span class="mono">--user-id</span>, or in the <span class="mono">X-Revaulter-User</span> header.
                    </p>
                </div>

                <!-- Trusted OIDC issuers -->
                <div class="space-y-3">
                    <div>
                        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Trusted OIDC issuers</div>
                        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                            A JWT is accepted when it's signed by the issuer's keys, and its audience and subject match an entry.
                        </p>
                    </div>

                    {#if requestOidcIssuers.length === 0}
                        <div class="rounded-lg border border-dashed border-neutral-300 bg-white px-6 py-6 text-center text-sm text-neutral-500 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-400">
                            No trusted issuers.
                        </div>
                    {:else}
                        <div class="divide-y divide-neutral-200 overflow-hidden rounded-lg border border-neutral-200 dark:divide-neutral-800 dark:border-neutral-800">
                            {#each requestOidcIssuers as iss (iss.id)}
                                <div class="flex items-start gap-3 px-4 py-3">
                                    <div class="min-w-0 flex-1 space-y-1">
                                        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">
                                            {iss.displayName || iss.issuer}
                                        </div>
                                        <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
                                            <dt class="text-neutral-500 dark:text-neutral-400">Issuer</dt>
                                            <dd class="mono min-w-0 break-all text-neutral-700 dark:text-neutral-300">{iss.issuer}</dd>
                                            <dt class="text-neutral-500 dark:text-neutral-400">Audience</dt>
                                            <dd class="mono min-w-0 break-all text-neutral-700 dark:text-neutral-300">{iss.audience}</dd>
                                            <dt class="text-neutral-500 dark:text-neutral-400">Subject</dt>
                                            <dd class="mono min-w-0 break-all text-neutral-700 dark:text-neutral-300">{iss.subject}</dd>
                                            <dt class="text-neutral-500 dark:text-neutral-400">Keys</dt>
                                            <dd class="mono min-w-0 break-all text-neutral-700 dark:text-neutral-300">{iss.jwksUrl || 'OIDC discovery'}</dd>
                                        </dl>
                                    </div>
                                    <Button
                                        variant="icon"
                                        size="icon"
                                        ariaLabel="Remove OIDC issuer"
                                        onclick={() => onDeleteRequestOIDCIssuer(iss.id)}
                                        disabled={busy}
                                    >
                                        <Icon icon="trash" title="Remove" size="3.5" />
                                    </Button>
                                </div>
                            {/each}
                        </div>
                    {/if}

                    {#if showAddIssuer}
                        <div class="rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
                            <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Add a trusted issuer</div>
                            <div class="mt-3 grid gap-3 sm:grid-cols-2">
                                <div class="space-y-1.5">
                                    <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="oidc-issuer-name">Name (optional)</label>
                                    <TextField id="oidc-issuer-name" placeholder="e.g. Release workflow" bind:value={issuerName} disabled={busy} />
                                </div>
                                <div class="space-y-1.5">
                                    <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="oidc-issuer-url">Issuer</label>
                                    <TextField id="oidc-issuer-url" placeholder="https://token.actions.githubusercontent.com" bind:value={issuerUrl} disabled={busy} />
                                </div>
                                <div class="space-y-1.5">
                                    <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="oidc-issuer-audience">Audience</label>
                                    <TextField id="oidc-issuer-audience" bind:value={issuerAudience} disabled={busy} />
                                </div>
                                <div class="space-y-1.5">
                                    <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="oidc-issuer-subject">Subject</label>
                                    <TextField id="oidc-issuer-subject" placeholder="repo:my-org/my-repo:ref:refs/tags/*" bind:value={issuerSubject} disabled={busy} />
                                </div>
                                <div class="space-y-1.5 sm:col-span-2">
                                    <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="oidc-issuer-jwks">JWKS URL (optional)</label>
                                    <TextField id="oidc-issuer-jwks" placeholder="Discovered from the issuer when empty" bind:value={issuerJwksUrl} disabled={busy} />
                                </div>
                            </div>
                            <p class="mt-3 text-xs text-neutral-500 dark:text-neutral-400">
                                In the subject, <span class="mono">*</span> matches any sequence of characters.
                                Leave the JWKS URL empty for issuers that support OpenID Connect discovery.
                            </p>
                            <div class="mt-3 flex gap-2">
                                <Button variant="primary" onclick={handleAddIssuer} disabled={busy}>
                                    Add issuer
                                </Button>
                                <Button
                                    variant="secondary"
                                    onclick={() => {
                                        showAddIssuer = false
                                    }}
                                >
                                    Cancel
                                </Button>
                            </div>
                        </div>
                    {:else}
                        <Button variant="secondary" onclick={openAddIssuer} disabled={busy}>
                            <Icon icon="plus" title="Add issuer" size="4" />
                            Add trusted issuer
                        </Button>
                    {/if}
                </div>
            </div>
        {/if}
    </div>
</div>
