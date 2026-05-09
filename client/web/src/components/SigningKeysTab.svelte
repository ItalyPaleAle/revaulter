<script lang="ts">
import { formatDistanceToNowStrict } from 'date-fns'

import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import TextField from '$components/TextField.svelte'

import type { DerivedSigningKey, V2PublishedSigningKey } from '$lib/v2-types'

type SigningKeyDownloadKind = 'jwk' | 'pem' | 'ssh'

interface Props {
    signingKeys: V2PublishedSigningKey[]
    busy: boolean
    onDeriveSigningKey: (keyLabel: string, algorithm: string) => Promise<DerivedSigningKey>
    onPublishSigningKey: (derived: DerivedSigningKey) => Promise<void>
    onUnpublishSigningKey: (id: string) => Promise<void>
    onDeleteSigningKey: (id: string) => Promise<void>
}

let { signingKeys, busy, onDeriveSigningKey, onPublishSigningKey, onUnpublishSigningKey, onDeleteSigningKey }: Props =
    $props()

const SIGNING_ALGORITHMS = ['ES256', 'Ed25519', 'Ed25519ph'] as const

let derivingKey = $state(false)
let deriveLabel = $state('')
let deriveAlgorithm = $state<string>(SIGNING_ALGORITHMS[0])
let derivedKey = $state<DerivedSigningKey | null>(null)
let deriveError = $state<string | null>(null)
let copiedFetchId = $state<string | null>(null)
let confirmingDeleteId = $state<string | null>(null)
let publishingStoredId = $state<string | null>(null)
let downloadMenuOpenId = $state<string | null>(null)
let downloadingStoredId = $state<string | null>(null)

$effect(() => {
    if (downloadMenuOpenId === null) {
        return
    }

    const handleDocClick = (event: MouseEvent) => {
        const target = event.target as HTMLElement | null
        if (!target?.closest('[data-download-menu]')) {
            downloadMenuOpenId = null
        }
    }

    const handleKeyDown = (event: KeyboardEvent) => {
        if (event.key !== 'Escape' || downloadMenuOpenId === null) {
            return
        }

        event.preventDefault()
        event.stopImmediatePropagation()
        downloadMenuOpenId = null
    }

    const timer = setTimeout(() => {
        document.addEventListener('click', handleDocClick)
    }, 0)
    document.addEventListener('keydown', handleKeyDown, true)

    return () => {
        clearTimeout(timer)
        document.removeEventListener('click', handleDocClick)
        document.removeEventListener('keydown', handleKeyDown, true)
    }
})

function formatTimestamp(value: number | string): string {
    if (!value) {
        return 'Never'
    }

    const date = typeof value === 'string' ? new Date(value) : new Date(value * 1000)
    if (Number.isNaN(date.getTime())) {
        return 'Never'
    }

    return formatDistanceToNowStrict(date, { addSuffix: true })
}

function shortenId(id: string): string {
    if (id.length <= 16) {
        return id
    }
    return `${id.slice(0, 8)}…${id.slice(-8)}`
}

function supportsSshPublicKey(algorithm: string): boolean {
    return algorithm !== 'Ed25519ph'
}

function publicFetchUrl(id: string, kind: 'jwk' | 'pem'): string {
    const origin = typeof window !== 'undefined' ? window.location.origin : ''
    return `${origin}/v2/signing-keys/${id}.${kind}`
}

function triggerDownload(filename: string, contents: string, mimeType: string) {
    const blob = new Blob([contents], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    setTimeout(() => URL.revokeObjectURL(url), 2000)
}

async function handleDeriveSigningKey() {
    deriveError = null
    if (deriveLabel.trim() === '') {
        deriveError = 'Key label is required'
        return
    }

    derivingKey = true
    try {
        derivedKey = await onDeriveSigningKey(deriveLabel.trim(), deriveAlgorithm)
    } catch (err) {
        deriveError = err instanceof Error ? err.message : String(err)
        derivedKey = null
    } finally {
        derivingKey = false
    }
}

function downloadDerived(kind: SigningKeyDownloadKind) {
    downloadMenuOpenId = null
    if (!derivedKey) {
        return
    }

    switch (kind) {
        case 'jwk':
            triggerDownload(
                `${derivedKey.keyLabel}-${derivedKey.algorithm}.jwk.json`,
                JSON.stringify(derivedKey.jwk, null, 2),
                'application/json'
            )
            break
        case 'pem':
            triggerDownload(
                `${derivedKey.keyLabel}-${derivedKey.algorithm}.pem`,
                derivedKey.pem,
                'application/x-pem-file'
            )
            break
        case 'ssh':
            triggerDownload(`${derivedKey.keyLabel}-${derivedKey.algorithm}.pub`, derivedKey.sshPublicKey, 'text/plain')
            break
        default:
            throw new Error(`Unsupported kind: ${kind}`)
    }
}

async function handlePublishDerived() {
    if (!derivedKey) {
        return
    }
    await onPublishSigningKey(derivedKey)
}

async function handleUnpublish(id: string) {
    await onUnpublishSigningKey(id)
}

async function handleDelete(id: string) {
    confirmingDeleteId = null
    await onDeleteSigningKey(id)
}

async function handlePublishStored(sk: V2PublishedSigningKey) {
    publishingStoredId = sk.id
    try {
        const derived = await onDeriveSigningKey(sk.keyLabel, sk.algorithm)
        await onPublishSigningKey(derived)
    } finally {
        publishingStoredId = null
    }
}

async function handleDownloadStored(sk: V2PublishedSigningKey, kind: SigningKeyDownloadKind) {
    downloadMenuOpenId = null
    downloadingStoredId = sk.id
    try {
        const derived = await onDeriveSigningKey(sk.keyLabel, sk.algorithm)
        switch (kind) {
            case 'jwk':
                triggerDownload(
                    `${derived.keyLabel}-${derived.algorithm}.jwk.json`,
                    JSON.stringify(derived.jwk, null, 2),
                    'application/json'
                )
                break
            case 'pem':
                triggerDownload(`${derived.keyLabel}-${derived.algorithm}.pem`, derived.pem, 'application/x-pem-file')
                break
            case 'ssh':
                triggerDownload(`${derived.keyLabel}-${derived.algorithm}.pub`, derived.sshPublicKey, 'text/plain')
                break
            default:
                throw new Error(`Unsupported kind: ${kind}`)
        }
    } finally {
        downloadingStoredId = null
    }
}

async function copyFetchUrl(id: string, kind: 'jwk' | 'pem') {
    await navigator.clipboard.writeText(publicFetchUrl(id, kind))
    copiedFetchId = `${id}/${kind}`
    setTimeout(() => {
        if (copiedFetchId === `${id}/${kind}`) {
            copiedFetchId = null
        }
    }, 2000)
}

function isDerivedPublished(): boolean {
    if (!derivedKey) {
        return false
    }
    return signingKeys.some((k) => k.id === derivedKey?.id && k.published)
}
</script>

<div class="space-y-6">
    <div>
        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Signing keys</div>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
            Signing keys are derived deterministically from your primary key. Publishing a key makes its public half retrievable without authentication so verifiers can check signatures.
        </p>
    </div>

    <div class="rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Derive a signing key</div>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
            Same key label and algorithm always produce the same key.
        </p>

        <div class="mt-3 grid gap-3 md:grid-cols-2">
            <div class="space-y-1.5">
                <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="signing-key-label">Key label</label>
                <TextField
                    id="signing-key-label"
                    type="text"
                    placeholder="e.g. prod-signing"
                    bind:value={deriveLabel}
                    disabled={busy || derivingKey}
                />
            </div>
            <div class="space-y-1.5">
                <label class="block text-xs font-medium text-neutral-700 dark:text-neutral-300" for="signing-key-algorithm">Algorithm</label>
                <select
                    id="signing-key-algorithm"
                    bind:value={deriveAlgorithm}
                    disabled={busy || derivingKey}
                    class="h-10.5 w-full rounded-lg border border-neutral-300 bg-white px-3 text-sm text-neutral-950 outline-none transition focus:border-neutral-900 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-50 dark:focus:border-neutral-300"
                >
                    {#each SIGNING_ALGORITHMS as alg}
                        <option value={alg}>{alg}</option>
                    {/each}
                </select>
            </div>
        </div>

        {#if deriveError}
            <div class="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3.5 py-2.5 text-sm text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                {deriveError}
            </div>
        {/if}

        <div class="mt-3 flex gap-2">
            <Button variant="primary" onclick={handleDeriveSigningKey} disabled={busy || derivingKey}>
                <Icon icon="key" title="Derive" size="3.5" />
                Derive key
            </Button>
        </div>

        {#if derivedKey}
            <div class="mt-4 space-y-3 rounded-lg border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-950/40">
                <div>
                    <div class="text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Derived key</div>
                    <div class="mt-1 text-sm text-neutral-900 dark:text-neutral-50">
                        <span class="font-medium">{derivedKey.keyLabel}</span>
                        <span class="mono ml-2 text-xs text-neutral-500 dark:text-neutral-400">{derivedKey.algorithm}</span>
                    </div>
                </div>
                <div>
                    <div class="text-xs font-medium uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Key ID</div>
                    <div class="mono mt-1 break-all text-xs text-neutral-700 dark:text-neutral-300">{derivedKey.id}</div>
                </div>

                <div class="flex flex-wrap items-center gap-2">
                    <div class="relative" data-download-menu>
                        <Button
                            variant="secondary"
                            size="sm"
                            onclick={() => {
                                downloadMenuOpenId = downloadMenuOpenId === 'derived' ? null : 'derived'
                            }}
                            disabled={busy}
                        >
                            <Icon icon="download" title="Download" size="3.5" />
                            Download
                        </Button>
                        {#if downloadMenuOpenId === 'derived'}
                            <div class="absolute left-0 top-full z-20 mt-1 min-w-40 overflow-hidden rounded-lg border border-neutral-200 bg-white py-1 shadow-lg dark:border-neutral-800 dark:bg-neutral-900">
                                <button
                                    type="button"
                                    class="block w-full cursor-pointer px-3 py-1.5 text-left text-sm text-neutral-900 transition hover:bg-neutral-100 dark:text-neutral-50 dark:hover:bg-neutral-800"
                                    onclick={() => downloadDerived('jwk')}
                                >
                                    JSON (JWK)
                                </button>
                                <button
                                    type="button"
                                    class="block w-full cursor-pointer px-3 py-1.5 text-left text-sm text-neutral-900 transition hover:bg-neutral-100 dark:text-neutral-50 dark:hover:bg-neutral-800"
                                    onclick={() => downloadDerived('pem')}
                                >
                                    PEM
                                </button>
                                {#if supportsSshPublicKey(derivedKey.algorithm)}
                                    <button
                                        type="button"
                                        class="block w-full cursor-pointer px-3 py-1.5 text-left text-sm text-neutral-900 transition hover:bg-neutral-100 dark:text-neutral-50 dark:hover:bg-neutral-800"
                                        onclick={() => downloadDerived('ssh')}
                                    >
                                        SSH public key
                                    </button>
                                {/if}
                            </div>
                        {/if}
                    </div>
                    {#if !isDerivedPublished()}
                        <Button variant="secondary" size="sm" onclick={handlePublishDerived} disabled={busy}>
                            <Icon icon="upload-cloud" title="Publish" size="3.5" />
                            Publish
                        </Button>
                    {:else}
                        <span class="inline-flex items-center gap-1 rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300">
                            <Icon icon="check" title="Published" size="3" />
                            Published
                        </span>
                    {/if}
                </div>
            </div>
        {/if}
    </div>

    <div>
        <div class="text-sm font-medium text-neutral-900 dark:text-neutral-50">Signing keys</div>
        <p class="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
            Public keys used to fulfill a sign request are automatically stored here. Publishing a key makes its public part retrievable without authentication at the URLs shown.
        </p>

        {#if signingKeys.length === 0}
            <div class="mt-3 rounded-lg border border-dashed border-neutral-300 bg-white px-6 py-8 text-center text-sm text-neutral-500 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-400">
                No signing keys yet.
            </div>
        {:else}
            <div class="mt-3 space-y-3">
                {#each signingKeys as sk (sk.id)}
                    <div class="rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
                        <div class="flex flex-wrap items-start justify-between gap-3">
                            <div class="min-w-0">
                                <div class="flex items-center gap-2 text-sm font-medium text-neutral-900 dark:text-neutral-50">
                                    <span>{sk.keyLabel}</span>
                                    <span class="mono text-xs font-normal text-neutral-500 dark:text-neutral-400">{sk.algorithm}</span>
                                    {#if sk.published}
                                        <span class="inline-flex items-center rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300">
                                            Published
                                        </span>
                                    {/if}
                                </div>
                                <div class="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                                    {sk.published ? 'Published' : 'Stored'} {formatTimestamp(sk.createdAt)}
                                    {#if sk.updatedAt && sk.updatedAt !== sk.createdAt}
                                        · Updated {formatTimestamp(sk.updatedAt)}
                                    {/if}
                                </div>
                                <div class="mono mt-1 break-all text-xs text-neutral-600 dark:text-neutral-400" title={sk.id}>
                                    {shortenId(sk.id)}
                                </div>
                            </div>
                            <div class="flex shrink-0 items-center gap-1">
                                <div class="relative" data-download-menu>
                                    <Button
                                        variant="secondary"
                                        size="icon"
                                        ariaLabel="Download key"
                                        onclick={() => {
                                            downloadMenuOpenId = downloadMenuOpenId === sk.id ? null : sk.id
                                        }}
                                        disabled={busy || downloadingStoredId === sk.id}
                                    >
                                        <Icon icon="download" title="Download" size="4" />
                                    </Button>
                                    {#if downloadMenuOpenId === sk.id}
                                        <div class="absolute right-0 top-full z-20 mt-1 min-w-40 overflow-hidden rounded-lg border border-neutral-200 bg-white py-1 shadow-lg dark:border-neutral-800 dark:bg-neutral-900">
                                            <button
                                                type="button"
                                                class="block w-full cursor-pointer px-3 py-1.5 text-left text-sm text-neutral-900 transition hover:bg-neutral-100 dark:text-neutral-50 dark:hover:bg-neutral-800"
                                                onclick={() => handleDownloadStored(sk, 'jwk')}
                                            >
                                                JWK
                                            </button>
                                            <button
                                                type="button"
                                                class="block w-full cursor-pointer px-3 py-1.5 text-left text-sm text-neutral-900 transition hover:bg-neutral-100 dark:text-neutral-50 dark:hover:bg-neutral-800"
                                                onclick={() => handleDownloadStored(sk, 'pem')}
                                            >
                                                PEM
                                            </button>
                                            {#if supportsSshPublicKey(sk.algorithm)}
                                                <button
                                                    type="button"
                                                    class="block w-full cursor-pointer px-3 py-1.5 text-left text-sm text-neutral-900 transition hover:bg-neutral-100 dark:text-neutral-50 dark:hover:bg-neutral-800"
                                                    onclick={() => handleDownloadStored(sk, 'ssh')}
                                                >
                                                    SSH public key
                                                </button>
                                            {/if}
                                        </div>
                                    {/if}
                                </div>
                                {#if !sk.published}
                                    <Button
                                        variant="secondary"
                                        size="icon"
                                        ariaLabel="Publish key"
                                        onclick={() => handlePublishStored(sk)}
                                        disabled={busy || publishingStoredId === sk.id}
                                    >
                                        <Icon icon="upload-cloud" title="Publish" size="4" />
                                    </Button>
                                {:else}
                                    <Button
                                        variant="secondary"
                                        size="icon"
                                        ariaLabel="Unpublish key"
                                        onclick={() => handleUnpublish(sk.id)}
                                        disabled={busy}
                                    >
                                        <Icon icon="cloud-off" title="Unpublish" size="4" />
                                    </Button>
                                {/if}
                                <Button
                                    variant="danger"
                                    size="icon"
                                    ariaLabel="Delete key"
                                    onclick={() => {
                                        confirmingDeleteId = sk.id
                                    }}
                                    disabled={busy}
                                >
                                    <Icon icon="trash" title="Delete" size="4" />
                                </Button>
                            </div>
                        </div>

                        {#if confirmingDeleteId === sk.id}
                            <div class="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3.5 py-3 dark:border-amber-900/70 dark:bg-amber-950/40">
                                <p class="text-sm font-medium text-amber-800 dark:text-amber-200">Delete this signing key?</p>
                                <p class="mt-1 text-sm text-amber-700 dark:text-amber-300">
                                    The row will be removed from the server. The same key can be re-derived from your primary key, but any existing published URL will stop resolving until it is re-derived and published again.
                                </p>
                                <div class="mt-3 flex gap-2">
                                    <Button variant="danger" size="sm" onclick={() => handleDelete(sk.id)} disabled={busy}>
                                        Yes, delete
                                    </Button>
                                    <Button
                                        variant="secondary"
                                        size="sm"
                                        onclick={() => {
                                            confirmingDeleteId = null
                                        }}
                                    >
                                        Cancel
                                    </Button>
                                </div>
                            </div>
                        {/if}

                        {#if sk.published}
                            <div class="mt-3 space-y-2">
                                {#each ['jwk', 'pem'] as const as kind}
                                    <div class="flex items-center gap-2">
                                        <div class="w-10 shrink-0 text-xs font-medium uppercase text-neutral-500 dark:text-neutral-400">{kind}</div>
                                        <div class="flex min-w-0 flex-1 items-center rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-950/40">
                                            <div class="mono min-w-0 flex-1 overflow-x-auto whitespace-nowrap px-3 py-1.5 text-xs text-neutral-900 dark:text-neutral-100">{publicFetchUrl(sk.id, kind)}</div>
                                            <button
                                                type="button"
                                                class="flex shrink-0 cursor-pointer items-center justify-center rounded-r-lg border-l border-neutral-200 px-2 py-1.5 text-neutral-500 transition hover:bg-neutral-100 hover:text-neutral-900 dark:border-neutral-800 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-50"
                                                aria-label="Copy to clipboard"
                                                onclick={() => copyFetchUrl(sk.id, kind)}
                                            >
                                                {#if copiedFetchId === `${sk.id}/${kind}`}
                                                    <Icon icon="check" title="Copied" size="3.5" />
                                                {:else}
                                                    <Icon icon="copy" title="Copy to clipboard" size="3.5" />
                                                {/if}
                                            </button>
                                        </div>
                                    </div>
                                {/each}
                            </div>
                        {/if}
                    </div>
                {/each}
            </div>
        {/if}
    </div>
</div>
