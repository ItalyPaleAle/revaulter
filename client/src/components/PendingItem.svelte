<script lang="ts">
import { formatDistanceToNowStrict } from 'date-fns'

import {
    deriveOperationKeyBytes,
    encryptTransportEnvelope,
    performAesGcmOperation,
    splitAesGcmCiphertextAndTag,
} from '$lib/crypto'
import { base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import { v2Cancel, v2Confirm, v2GetRequest } from '$lib/v2-api'
import type { V2PendingRequestItem, V2RequestDetail } from '$lib/v2-types'
import LoadingSpinner from '$components/LoadingSpinner.svelte'

interface Props {
    item: V2PendingRequestItem
    prfSecret: Uint8Array
    password?: string
    onRemoved?: (state: string) => void
}

let { item, prfSecret, password = '', onRemoved }: Props = $props()

let working = $state(false)
let localStatus = $state<string>('pending')
let error = $state<string | null>(null)
let detailOpen = $state(false)
let detail = $state<V2RequestDetail | null>(null)

$effect(() => {
    if (
        localStatus === '_processing' ||
        localStatus === 'confirmed' ||
        localStatus === 'canceled' ||
        localStatus === '_failed'
    ) {
        return
    }
    localStatus = item.status
})

async function ensureDetail() {
    if (detail) return detail
    detail = await v2GetRequest(item.state)
    return detail
}

async function doCancel() {
    error = null
    working = true
    localStatus = '_processing'
    try {
        const res = await v2Cancel(item.state)
        if (!res?.canceled) {
            throw new Error('Cancel failed')
        }
        localStatus = 'canceled'
        onRemoved?.(item.state)
    } catch (err) {
        localStatus = '_failed'
        error = err instanceof Error ? err.message : String(err)
    } finally {
        working = false
    }
}

async function doConfirm() {
    error = null
    working = true
    localStatus = '_processing'
    try {
        const req = await ensureDetail()
        const env = await buildResponseEnvelope(req)
        const res = await v2Confirm(item.state, env)
        if (!res?.confirmed) {
            throw new Error('Confirm failed')
        }
        localStatus = 'confirmed'
        onRemoved?.(item.state)
    } catch (err) {
        localStatus = '_failed'
        error = err instanceof Error ? err.message : String(err)
    } finally {
        working = false
    }
}

async function buildResponseEnvelope(req: V2RequestDetail) {
    if (req.algorithm !== 'aes-gcm-256') {
        throw new Error(`Unsupported algorithm: ${req.algorithm}`)
    }

    const operationKey = await deriveOperationKeyBytes({
        targetUser: req.targetUser,
        keyLabel: req.keyLabel,
        algorithm: req.algorithm,
        prfSecret,
        password: password.trim() || undefined,
    })

    const input = req.request
    const value = base64UrlToBytes(input.value)
    const aad = base64UrlToBytes(input.additionalData)

    let resultPlain: Uint8Array
    switch (req.operation) {
        case 'encrypt': {
            const nonce = input.nonce ? base64UrlToBytes(input.nonce) : crypto.getRandomValues(new Uint8Array(12))
            const combined = await performAesGcmOperation({
                mode: 'encrypt',
                keyBytes: operationKey,
                value,
                nonce,
                aad,
            })
            const split = splitAesGcmCiphertextAndTag(combined)
            resultPlain = new TextEncoder().encode(
                JSON.stringify({
                    state: req.state,
                    operation: req.operation,
                    algorithm: req.algorithm,
                    value: bytesToBase64Url(split.data),
                    nonce: bytesToBase64Url(nonce),
                    tag: bytesToBase64Url(split.tag),
                    additionalData: input.additionalData || undefined,
                })
            )
            break
        }

        case 'decrypt': {
            const nonce = base64UrlToBytes(input.nonce)
            if (nonce.length === 0) {
                throw new Error('Missing nonce for decrypt')
            }
            const tag = base64UrlToBytes(input.tag)
            if (tag.length === 0) {
                throw new Error('Missing authentication tag for decrypt')
            }
            const plain = await performAesGcmOperation({
                mode: 'decrypt',
                keyBytes: operationKey,
                value,
                nonce,
                aad,
                tag,
            })
            resultPlain = new TextEncoder().encode(
                JSON.stringify({
                    state: req.state,
                    operation: req.operation,
                    algorithm: req.algorithm,
                    value: bytesToBase64Url(plain),
                })
            )
            break
        }
        default:
            throw new Error(`Unsupported operation: ${req.operation}`)
    }

    const transportAAD = new TextEncoder().encode(
        JSON.stringify({
            v: 1,
            state: req.state,
            operation: req.operation,
            algorithm: req.algorithm,
        })
    )
    return encryptTransportEnvelope(req.state, req.request.clientTransportKey, resultPlain, transportAAD)
}

function operationTitle(op: V2PendingRequestItem['operation']) {
    switch (op) {
        case 'encrypt':
            return 'Encrypt'
        case 'decrypt':
            return 'Decrypt'
    }
}

function expiresIn(item: V2PendingRequestItem) {
    return formatDistanceToNowStrict(new Date(item.expiry * 1000), { addSuffix: true })
}
</script>

<div class="rounded-lg border border-slate-200/80 dark:border-slate-700 p-4 bg-white/90 dark:bg-slate-900/70">
    <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div class="space-y-1">
            <div class="text-sm text-slate-500 dark:text-slate-400">{operationTitle(item.operation)} request</div>
            <div class="text-base font-semibold text-slate-900 dark:text-white">
                {item.keyLabel}
                <span class="font-normal text-slate-500 dark:text-slate-400"> · {item.algorithm}</span>
            </div>
            <div class="text-sm text-slate-700 dark:text-slate-300">
                Target user: <span class="font-mono">{item.targetUser}</span>
            </div>
            {#if item.requestor}
                <div class="text-sm text-slate-700 dark:text-slate-300">
                    Requestor: <span class="font-mono">{item.requestor}</span>
                </div>
            {/if}
            {#if item.note}
                <div class="text-sm italic text-slate-700 dark:text-slate-300">“{item.note}”</div>
            {/if}
            <div class="text-xs text-slate-500 dark:text-slate-400">
                Expires {expiresIn(item)} · <span class="font-mono">{item.state}</span>
            </div>
            {#if detailOpen && detail}
                <pre class="mt-2 max-h-64 overflow-auto rounded bg-slate-100 dark:bg-slate-800 p-2 text-xs">{JSON.stringify(detail.request, null, 2)}</pre>
            {/if}
        </div>

        <div class="flex flex-col gap-2 min-w-52">
            {#if error}
                <div class="rounded border border-rose-200 bg-rose-50 px-2 py-1 text-xs text-rose-800 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
                    {error}
                </div>
            {/if}
            <div class="flex gap-2">
                <button
                    class="flex-1 rounded bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
                    disabled={working || localStatus !== 'pending'}
                    onclick={doConfirm}
                >
                    {#if working && localStatus === '_processing'}<LoadingSpinner size="1rem" />{/if}
                    Confirm
                </button>
                <button
                    class="flex-1 rounded bg-rose-600 px-3 py-2 text-sm font-medium text-white hover:bg-rose-500 disabled:opacity-50"
                    disabled={working || localStatus !== 'pending'}
                    onclick={doCancel}
                >
                    Cancel
                </button>
            </div>
            <button
                class="rounded border border-slate-300 dark:border-slate-600 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800"
                type="button"
                onclick={async () => {
                    detailOpen = !detailOpen
                    if (detailOpen) {
                        try {
                            await ensureDetail()
                        } catch (err) {
                            error = err instanceof Error ? err.message : String(err)
                        }
                    }
                }}
            >
                {detailOpen ? 'Hide request body' : 'Show request body'}
            </button>
            {#if localStatus === 'confirmed'}
                <div class="text-sm text-emerald-700 dark:text-emerald-300">Confirmed</div>
            {:else if localStatus === 'canceled'}
                <div class="text-sm text-rose-700 dark:text-rose-300">Canceled</div>
            {:else if localStatus === '_failed'}
                <div class="text-sm text-rose-700 dark:text-rose-300">Failed</div>
            {/if}
        </div>
    </div>
</div>
