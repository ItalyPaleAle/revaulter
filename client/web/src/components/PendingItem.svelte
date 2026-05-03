<script lang="ts">
import { formatDistanceStrict } from 'date-fns'

import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'

import {
    decryptRequestPayload,
    deriveOperationKeyBytes,
    deriveSigningKeyPair,
    encryptTransportEnvelope,
    signingJwkToPem,
    signDigestEd25519ph,
    signDigestEs256,
    signMessageEd25519,
} from '$lib/crypto'
import {
    buildRequestEncAAD,
    buildTransportAAD,
    isSupportedAeadAlgorithm,
    normalizeAeadAlgorithm,
    performAesGcmOperation,
    performChaCha20Poly1305Operation,
    splitAeadCiphertextAndTag,
} from '$lib/crypto-symmetric'
import { base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import { v2Cancel, v2Confirm, v2GetRequest } from '$lib/v2-api'
import type { V2PendingRequestItem, V2RequestDetail, V2ResponseEnvelope, V2SigningJwk } from '$lib/v2-types'

interface Props {
    bulkAction?: { id: number; action: 'confirm' | 'cancel' } | null
    item: V2PendingRequestItem
    now: number
    primaryKey: Uint8Array
    onRemoved?: (state: string) => void
}

let { bulkAction = null, item, now, primaryKey, onRemoved }: Props = $props()

let working = $state(false)
let localStatus = $state<string>('pending')
let error = $state<string | null>(null)
let detail = $state<V2RequestDetail | null>(null)
let removeTimer: ReturnType<typeof setTimeout> | null = null
let handledBulkActionId = $state(0)

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
    if (detail) {
        return detail
    }
    detail = await v2GetRequest(item.state)
    return detail
}

async function doCancel() {
    if (working || (localStatus !== 'pending' && localStatus !== '_failed')) {
        return
    }
    error = null
    working = true
    localStatus = '_processing'
    try {
        const res = await v2Cancel(item.state)
        if (!res?.canceled) {
            throw new Error('Cancel failed')
        }
        localStatus = 'canceled'
        scheduleRemoval()
    } catch (err) {
        localStatus = '_failed'
        error = err instanceof Error ? err.message : String(err)
    } finally {
        working = false
    }
}

async function doConfirm() {
    if (working || (localStatus !== 'pending' && localStatus !== '_failed')) {
        return
    }
    error = null
    working = true
    localStatus = '_processing'
    try {
        const req = await ensureDetail()
        const { envelope, publicKey } = await buildResponseEnvelope(req)
        const res = await v2Confirm(item.state, envelope, publicKey)
        if (!res?.confirmed) {
            throw new Error('Confirm failed')
        }
        localStatus = 'confirmed'
        scheduleRemoval()
    } catch (err) {
        localStatus = '_failed'
        error = err instanceof Error ? err.message : String(err)
    } finally {
        working = false
    }
}

function scheduleRemoval() {
    if (removeTimer) {
        clearTimeout(removeTimer)
    }
    removeTimer = setTimeout(() => {
        onRemoved?.(item.state)
    }, 1100)
}

$effect(() => {
    if (!bulkAction || handledBulkActionId === bulkAction.id) {
        return
    }
    handledBulkActionId = bulkAction.id

    if (bulkAction.action === 'confirm') {
        void doConfirm()
        return
    }

    void doCancel()
})

async function buildResponseEnvelope(
    req: V2RequestDetail
): Promise<{ envelope: V2ResponseEnvelope; publicKey?: { jwk: V2SigningJwk; pem: string } }> {
    // Validate the algorithm against what the operation supports
    switch (req.operation) {
        case 'sign':
            if (!['ES256', 'Ed25519', 'Ed25519ph'].includes(req.algorithm)) {
                throw new Error(`Unsupported signing algorithm: ${req.algorithm}`)
            }
            break

        case 'encrypt':
        case 'decrypt':
            if (!isSupportedAeadAlgorithm(req.algorithm)) {
                throw new Error(`Unsupported algorithm: ${req.algorithm}`)
            }
            break

        default:
            throw new Error(`Unsupported operation: ${req.operation}`)
    }

    // Decrypt the E2EE request payload using hybrid ECDH + ML-KEM
    const requestEncAAD = buildRequestEncAAD(req.algorithm, req.keyLabel, req.operation)
    const input = await decryptRequestPayload({
        userId: req.userId,
        primaryKey,
        cliEphemeralPublicKey: req.encryptedRequest.cliEphemeralPublicKey,
        mlkemCiphertext: req.encryptedRequest.mlkemCiphertext,
        nonce: req.encryptedRequest.nonce,
        ciphertext: req.encryptedRequest.ciphertext,
        aad: requestEncAAD,
    })

    const value = base64UrlToBytes(input.value)
    const aad = input.additionalData ? base64UrlToBytes(input.additionalData) : new Uint8Array()

    let resultPlain: Uint8Array
    let publicKey: { jwk: V2SigningJwk; pem: string } | undefined
    switch (req.operation) {
        case 'sign': {
            // Sign operations carry only the algorithm-specific signing bytes in `value`
            // `nonce`, `tag`, and `additionalData` must be empty — enforced here because the server cannot inspect the decrypted inner payload
            if (input.nonce) {
                throw new Error('sign: nonce must be empty')
            }
            if (input.tag) {
                throw new Error('sign: tag must be empty')
            }
            if (input.additionalData) {
                throw new Error('sign: additionalData must be empty')
            }

            const { secretKey, publicJwk } = await deriveSigningKeyPair({
                userId: req.userId,
                keyLabel: req.keyLabel,
                algorithm: req.algorithm,
                primaryKey,
            })
            let signature: Uint8Array
            switch (req.algorithm) {
                case 'ES256':
                    if (value.length !== 32) {
                        throw new Error('sign: ES256 digest must be exactly 32 bytes')
                    }
                    signature = await signDigestEs256(secretKey, value)
                    break
                case 'Ed25519':
                    signature = await signMessageEd25519(secretKey, value)
                    break
                case 'Ed25519ph':
                    if (value.length !== 64) {
                        throw new Error('sign: Ed25519ph digest must be exactly 64 bytes')
                    }
                    signature = await signDigestEd25519ph(secretKey, value)
                    break
                default:
                    throw new Error(`Unsupported signing algorithm: ${req.algorithm}`)
            }
            const pem = await signingJwkToPem(publicJwk)
            publicKey = { jwk: publicJwk, pem }
            resultPlain = new TextEncoder().encode(
                JSON.stringify({
                    state: req.state,
                    operation: req.operation,
                    algorithm: req.algorithm,
                    keyLabel: req.keyLabel,
                    signature: bytesToBase64Url(signature),
                })
            )
            break
        }

        case 'encrypt': {
            // Encrypt always generates a fresh random nonce; a CLI-supplied nonce would risk reuse under the same key, breaking AEAD security
            if (input.nonce) {
                throw new Error('encrypt: nonce must be empty')
            }
            if (input.tag) {
                throw new Error('encrypt: tag must be empty')
            }

            const operationKey = await deriveOperationKeyBytes({
                userId: req.userId,
                keyLabel: req.keyLabel,
                algorithm: req.algorithm,
                primaryKey,
            })

            const nonce = crypto.getRandomValues(new Uint8Array(12))

            // Dispatch on the normalized algorithm; the validation switch above already gated unsupported values
            const primitive = normalizeAeadAlgorithm(req.algorithm)
            const opParams = { mode: 'encrypt' as const, keyBytes: operationKey, value, nonce, aad }
            const combined =
                primitive === 'chacha20-poly1305'
                    ? await performChaCha20Poly1305Operation(opParams)
                    : await performAesGcmOperation(opParams)

            const split = splitAeadCiphertextAndTag(combined)

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
            const operationKey = await deriveOperationKeyBytes({
                userId: req.userId,
                keyLabel: req.keyLabel,
                algorithm: req.algorithm,
                primaryKey,
            })

            const nonce = input.nonce ? base64UrlToBytes(input.nonce) : new Uint8Array()
            if (nonce.length === 0) {
                throw new Error('Missing nonce for decrypt')
            }

            const tag = input.tag ? base64UrlToBytes(input.tag) : new Uint8Array()
            if (tag.length === 0) {
                throw new Error('Missing authentication tag for decrypt')
            }

            const primitive = normalizeAeadAlgorithm(req.algorithm)
            const opParams = { mode: 'decrypt' as const, keyBytes: operationKey, value, nonce, aad, tag }
            const plain =
                primitive === 'chacha20-poly1305'
                    ? await performChaCha20Poly1305Operation(opParams)
                    : await performAesGcmOperation(opParams)

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

    const transportAAD = buildTransportAAD(req.state, req.operation, req.algorithm)
    const envelope = await encryptTransportEnvelope(
        req.state,
        input.clientTransportEcdhKey,
        input.clientTransportMlkemKey,
        resultPlain,
        transportAAD
    )

    return { envelope, publicKey }
}

/** Visual metadata per operation — icon, label, and accent color classes */
const OP_META = {
    encrypt: {
        label: 'Encrypt',
        icon: 'lock-closed',
        colorClass: 'text-sky-600 dark:text-sky-400',
        bgClass: 'bg-sky-50 dark:bg-sky-950/40',
    },
    decrypt: {
        label: 'Decrypt',
        icon: 'lock-open',
        colorClass: 'text-emerald-600 dark:text-emerald-400',
        bgClass: 'bg-emerald-50 dark:bg-emerald-950/40',
    },
    sign: {
        label: 'Sign',
        icon: 'user-round-pen',
        colorClass: 'text-amber-700 dark:text-amber-400',
        bgClass: 'bg-amber-50 dark:bg-amber-950/40',
    },
} as const

function formatHex(bytes: Uint8Array): string {
    let hex = ''
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0').toUpperCase()
        if (i < bytes.length - 1 && (i + 1) % 2 === 0) {
            hex += ' '
        }
    }
    return hex
}

/** Renders the sign request input in a compact algorithm-aware way */
function formatSignInput(algorithm: string, valueB64Url: string): string {
    try {
        const bytes = base64UrlToBytes(valueB64Url)
        switch (algorithm) {
            case 'ES256':
                return bytes.length === 32 ? `SHA-256 ${formatHex(bytes)}` : valueB64Url
            case 'Ed25519ph':
                return bytes.length === 64 ? `SHA-512 ${formatHex(bytes)}` : valueB64Url
            case 'Ed25519': {
                const preview = bytes.subarray(0, Math.min(bytes.length, 24))
                const previewHex = formatHex(preview)
                if (bytes.length <= preview.length) {
                    return `${bytes.length} byte message ${previewHex}`
                }
                return `${bytes.length} byte message ${previewHex} …`
            }
            default:
                return valueB64Url
        }
    } catch {
        return valueB64Url
    }
}

/**
 * For sign requests, decrypts the E2EE inner payload so the user can review
 * the signing input before approving.
 */
let signInputPreview = $state<string | null>(null)
let signInputLoading = $state(false)
let signInputError = $state<string | null>(null)
$effect(() => {
    if (item.operation !== 'sign') {
        return
    }
    if (signInputPreview || signInputLoading || signInputError) {
        return
    }
    signInputLoading = true
    void (async () => {
        try {
            const req = await ensureDetail()
            const requestEncAAD = buildRequestEncAAD(req.algorithm, req.keyLabel, req.operation)
            const inner = await decryptRequestPayload({
                userId: req.userId,
                primaryKey,
                cliEphemeralPublicKey: req.encryptedRequest.cliEphemeralPublicKey,
                mlkemCiphertext: req.encryptedRequest.mlkemCiphertext,
                nonce: req.encryptedRequest.nonce,
                ciphertext: req.encryptedRequest.ciphertext,
                aad: requestEncAAD,
            })
            signInputPreview = formatSignInput(req.algorithm, inner.value)
        } catch (err) {
            signInputError = err instanceof Error ? err.message : String(err)
        } finally {
            signInputLoading = false
        }
    })()
})

function expiresIn(item: V2PendingRequestItem) {
    return formatDistanceStrict(new Date(item.expiry * 1000), new Date(now), { addSuffix: true })
}

function ttlPercent(item: V2PendingRequestItem) {
    const total = (item.expiry - item.date) * 1000
    if (total <= 0) {
        return 0
    }
    const remaining = item.expiry * 1000 - now
    return Math.max(0, Math.min(100, (remaining / total) * 100))
}

function ttlIsLow(item: V2PendingRequestItem) {
    return item.expiry * 1000 - now < 120_000
}

function ageLabel(item: V2PendingRequestItem) {
    return formatDistanceStrict(new Date(item.date * 1000), new Date(now), { addSuffix: true })
}

let meta = $derived(OP_META[item.operation])
let confirmed = $derived(localStatus === 'confirmed')
let canceled = $derived(localStatus === 'canceled')
let terminal = $derived(confirmed || canceled)

$effect(() => {
    return () => {
        if (removeTimer) {
            clearTimeout(removeTimer)
        }
    }
})
</script>

<div
    class={`operation-card px-6 py-5 transition-colors ${confirmed ? 'operation-card-complete bg-emerald-50/60 dark:bg-emerald-950/20' : canceled ? 'operation-card-canceled bg-rose-50/60 dark:bg-rose-950/20' : ''} ${terminal ? 'opacity-70' : ''}`}
>
    <div class="flex items-start gap-4">
        <!-- Icon puck -->
        <div
            class={`operation-puck mt-0.5 inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${meta.bgClass} ${meta.colorClass} ${confirmed ? `operation-complete operation-${item.operation}` : ''}`}
            title={item.algorithm}
        >
            <span class="operation-icon">
                <Icon icon={meta.icon} title={meta.label} size="5" />
            </span>
        </div>

        <!-- Main -->
        <div class="min-w-0 flex-1">
            <!-- Label row -->
            <div class="flex flex-wrap items-baseline gap-2">
                <span class={`text-[11px] font-semibold uppercase tracking-wider ${meta.colorClass}`}>{meta.label}</span>
                <span class="text-neutral-300 dark:text-neutral-600">·</span>
                <span class="mono text-[13px] font-medium text-neutral-900 dark:text-neutral-50">{item.keyLabel}</span>
            </div>

            <!-- Requestor + note -->
            <div class="mt-1 text-[13px] leading-5 text-neutral-500 dark:text-neutral-400">
                {#if item.requestor}
                    from <span class="mono text-neutral-900 dark:text-neutral-100">{item.requestor}</span>
                {/if}
                {#if item.note}
                    {#if item.requestor}
                        <span class="mx-1.5 text-neutral-300 dark:text-neutral-600">·</span>
                    {/if}
                    <span>{item.note}</span>
                {/if}
            </div>

            <!-- Meta row -->
            <div class="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-neutral-400 dark:text-neutral-500">
                <span>{ageLabel(item)}</span>
                <span>·</span>
                <span
                    class={`tabular-nums ${ttlIsLow(item) ? 'text-rose-600 dark:text-rose-400' : ''}`}
                >
                    Expires {expiresIn(item)}
                </span>
                <span>·</span>
                <span class="mono truncate underline decoration-neutral-300 underline-offset-2 dark:decoration-neutral-700" title={item.state}>
                    {item.state}
                </span>
            </div>

            <!-- TTL progress bar -->
            <div class="mt-2.5 h-0.5 w-full overflow-hidden rounded-sm bg-neutral-200 dark:bg-neutral-800">
                <div
                    class={`h-full transition-[width] duration-1000 ease-linear ${ttlIsLow(item) ? 'bg-rose-500 dark:bg-rose-400' : 'bg-neutral-500 dark:bg-neutral-400'}`}
                    style={`width: ${ttlPercent(item)}%;`}
                ></div>
            </div>

            <!-- Sign input preview expanded by default -->
            {#if item.operation === 'sign'}
                <div class="mt-3.5 rounded-lg border border-neutral-200 bg-neutral-50 p-3 dark:border-neutral-800 dark:bg-neutral-800/60">
                    <div class="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                        Signing input
                    </div>
                    {#if signInputLoading}
                        <div class="mono text-[11px] text-neutral-500 dark:text-neutral-400">Loading…</div>
                    {:else if signInputError}
                        <div class="text-[11px] text-rose-700 dark:text-rose-300">
                            Could not decrypt sign input: {signInputError}
                        </div>
                    {:else if signInputPreview}
                        <div class="mono break-all text-[11px] leading-relaxed text-neutral-900 dark:text-neutral-100">
                            {signInputPreview}
                        </div>
                    {/if}
                </div>
            {/if}

            {#if error}
                <div class="mt-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-800 dark:border-rose-900/70 dark:bg-rose-950/40 dark:text-rose-200">
                    {error}
                </div>
            {/if}
        </div>

        <!-- Actions column -->
        <div class="flex min-w-24 shrink-0 flex-col gap-1.5">
            {#if confirmed}
                <div class="inline-flex items-center gap-1.5 px-3 py-2 text-[13px] font-medium text-emerald-600 dark:text-emerald-400">
                    <Icon icon="check" title="" size="3.5" />
                    Confirmed
                </div>
            {:else if canceled}
                <div class="inline-flex items-center gap-1.5 px-3 py-2 text-[13px] font-medium text-rose-600 dark:text-rose-400">
                    <Icon icon="x" title="" size="3.5" />
                    Canceled
                </div>
            {:else}
                <Button
                    variant="primary"
                    size="sm"
                    disabled={working || (localStatus !== 'pending' && localStatus !== '_failed')}
                    onclick={doConfirm}
                >
                    {#if working && localStatus === '_processing'}
                        <LoadingSpinner size="0.85rem" />
                    {:else}
                        <Icon icon="check" title="" size="3.5" />
                        {localStatus === '_failed' ? 'Retry' : 'Confirm'}
                    {/if}
                </Button>
                <Button
                    variant="ghost"
                    size="sm"
                    disabled={working || (localStatus !== 'pending' && localStatus !== '_failed')}
                    onclick={doCancel}
                >
                    <Icon icon="x" title="" size="3.5" />
                    Decline
                </Button>
            {/if}
        </div>
    </div>
</div>

<style>
    .operation-card {
        will-change: transform, opacity;
    }

    .operation-card-complete {
        animation: card-complete-slide 980ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
    }

    .operation-card-canceled {
        animation: card-canceled-slide 980ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
    }

    .operation-puck {
        position: relative;
        overflow: visible;
    }

    .operation-puck::after {
        content: '';
        position: absolute;
        inset: -3px;
        border-radius: 0.75rem;
        border: 1px solid currentColor;
        opacity: 0;
        transform: scale(0.78);
    }

    .operation-icon {
        display: inline-flex;
    }

    .operation-complete {
        animation: complete-puck 680ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
    }

    .operation-complete::after {
        animation: complete-ring 760ms ease-out both;
    }

    .operation-complete.operation-encrypt .operation-icon {
        animation: encrypt-seal 680ms ease-out both;
    }

    .operation-complete.operation-decrypt .operation-icon {
        animation: decrypt-open 680ms ease-out both;
    }

    .operation-complete.operation-sign .operation-icon {
        animation: sign-stamp 720ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
    }

    @keyframes card-complete-slide {
        0% {
            transform: translateX(0);
            opacity: 1;
        }
        28% {
            transform: translateX(10px);
            opacity: 1;
        }
        100% {
            transform: translateX(56px);
            opacity: 0;
        }
    }

    @keyframes card-canceled-slide {
        0% {
            transform: translateX(0);
            opacity: 1;
        }
        28% {
            transform: translateX(-10px);
            opacity: 1;
        }
        100% {
            transform: translateX(-56px);
            opacity: 0;
        }
    }

    @keyframes complete-puck {
        0% {
            transform: scale(1);
        }
        38% {
            transform: scale(1.12);
        }
        100% {
            transform: scale(1);
        }
    }

    @keyframes complete-ring {
        0% {
            opacity: 0.42;
            transform: scale(0.82);
        }
        100% {
            opacity: 0;
            transform: scale(1.55);
        }
    }

    @keyframes encrypt-seal {
        0% {
            transform: translateY(-1px) scale(0.92);
            opacity: 0.7;
        }
        42% {
            transform: translateY(1px) scale(1.12);
            opacity: 1;
        }
        100% {
            transform: translateY(0) scale(1);
        }
    }

    @keyframes decrypt-open {
        0% {
            transform: rotate(-10deg) scale(0.92);
            opacity: 0.7;
        }
        45% {
            transform: rotate(10deg) scale(1.12);
            opacity: 1;
        }
        100% {
            transform: rotate(0) scale(1);
        }
    }

    @keyframes sign-stamp {
        0% {
            transform: translateY(-5px) rotate(-5deg) scale(1.08);
            opacity: 0.78;
        }
        42% {
            transform: translateY(2px) rotate(0) scale(0.94);
            opacity: 1;
        }
        72% {
            transform: translateY(-1px) scale(1.05);
        }
        100% {
            transform: translateY(0) scale(1);
        }
    }

    @media (prefers-reduced-motion: reduce) {
        .operation-complete,
        .operation-complete::after,
        .operation-card-complete,
        .operation-card-canceled,
        .operation-complete.operation-encrypt .operation-icon,
        .operation-complete.operation-decrypt .operation-icon,
        .operation-complete.operation-sign .operation-icon {
            animation: none;
        }
    }
</style>
