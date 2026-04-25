<script lang="ts">
import { formatDistanceToNowStrict } from 'date-fns'

import Button from '$components/Button.svelte'
import Icon from '$components/Icon.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'

import {
    buildRequestEncAAD,
    buildTransportAAD,
    decryptRequestPayload,
    deriveOperationKeyBytes,
    deriveSigningKeyPair,
    ecP256JwkToPem,
    encryptTransportEnvelope,
    isSupportedAeadAlgorithm,
    normalizeAeadAlgorithm,
    performAesGcmOperation,
    performChaCha20Poly1305Operation,
    signDigestEs256,
    splitAeadCiphertextAndTag,
} from '$lib/crypto'
import { base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import { v2Cancel, v2Confirm, v2GetRequest } from '$lib/v2-api'
import type { V2PendingRequestItem, V2RequestDetail, V2ResponseEnvelope, V2SigningJwk } from '$lib/v2-types'

interface Props {
    item: V2PendingRequestItem
    primaryKey: Uint8Array
    onRemoved?: (state: string) => void
}

let { item, primaryKey, onRemoved }: Props = $props()

let working = $state(false)
let localStatus = $state<string>('pending')
let error = $state<string | null>(null)
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
    if (detail) {
        return detail
    }
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
        const { envelope, publicKey } = await buildResponseEnvelope(req)
        const res = await v2Confirm(item.state, envelope, publicKey)
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

async function buildResponseEnvelope(
    req: V2RequestDetail
): Promise<{ envelope: V2ResponseEnvelope; publicKey?: { jwk: V2SigningJwk; pem: string } }> {
    // Validate the algorithm against what the operation supports
    switch (req.operation) {
        case 'sign':
            if (req.algorithm !== 'ES256') {
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
            // Sign operations carry only a 32-byte SHA-256 digest in `value`
            // `nonce`, `tag`, and `additionalData` must be empty — enforced here because the server cannot inspect the decrypted inner payload
            if (value.length !== 32) {
                throw new Error('sign: digest must be exactly 32 bytes')
            }
            if (input.nonce) {
                throw new Error('sign: nonce must be empty')
            }
            if (input.tag) {
                throw new Error('sign: tag must be empty')
            }
            if (input.additionalData) {
                throw new Error('sign: additionalData must be empty')
            }

            const { scalar, publicJwk } = await deriveSigningKeyPair({
                userId: req.userId,
                keyLabel: req.keyLabel,
                algorithm: req.algorithm,
                primaryKey,
            })
            const signature = await signDigestEs256(scalar, value)
            const pem = await ecP256JwkToPem(publicJwk)
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
            const operationKey = await deriveOperationKeyBytes({
                userId: req.userId,
                keyLabel: req.keyLabel,
                algorithm: req.algorithm,
                primaryKey,
            })

            const nonce = input.nonce ? base64UrlToBytes(input.nonce) : crypto.getRandomValues(new Uint8Array(12))

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
        icon: 'signature',
        colorClass: 'text-amber-700 dark:text-amber-400',
        bgClass: 'bg-amber-50 dark:bg-amber-950/40',
    },
} as const

/** Renders a SHA-256 digest (32 bytes, base64url) as uppercase hex with spaces */
function formatDigest(digestB64Url: string): string {
    try {
        const bytes = base64UrlToBytes(digestB64Url)
        if (bytes.length !== 32) {
            return digestB64Url
        }
        let hex = ''
        for (let i = 0; i < bytes.length; i++) {
            hex += bytes[i].toString(16).padStart(2, '0').toUpperCase()
            if (i < bytes.length - 1 && (i + 1) % 2 === 0) {
                hex += ' '
            }
        }
        return hex
    } catch {
        return digestB64Url
    }
}

/**
 * For sign requests, decrypts the E2EE inner payload so the user can review
 * the SHA-256 digest before approving.
 */
let digestHex = $state<string | null>(null)
let digestLoading = $state(false)
let digestError = $state<string | null>(null)
$effect(() => {
    if (item.operation !== 'sign') {
        return
    }
    if (digestHex || digestLoading || digestError) {
        return
    }
    digestLoading = true
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
            digestHex = formatDigest(inner.value)
        } catch (err) {
            digestError = err instanceof Error ? err.message : String(err)
        } finally {
            digestLoading = false
        }
    })()
})

/** Ticking clock so age/expiry labels stay live */
let now = $state(Date.now())
$effect(() => {
    const id = setInterval(() => {
        now = Date.now()
    }, 1000)
    return () => clearInterval(id)
})

function expiresIn(item: V2PendingRequestItem) {
    // Touch `now` so this re-computes every tick
    void now
    return formatDistanceToNowStrict(new Date(item.expiry * 1000), { addSuffix: true })
}

function ttlPercent(item: V2PendingRequestItem) {
    void now
    const total = (item.expiry - item.date) * 1000
    if (total <= 0) {
        return 0
    }
    const remaining = item.expiry * 1000 - now
    return Math.max(0, Math.min(100, (remaining / total) * 100))
}

function ttlIsLow(item: V2PendingRequestItem) {
    void now
    return item.expiry * 1000 - now < 120_000
}

function ageLabel(item: V2PendingRequestItem) {
    void now
    return formatDistanceToNowStrict(new Date(item.date * 1000), { addSuffix: true })
}

let meta = $derived(OP_META[item.operation])
let confirmed = $derived(localStatus === 'confirmed')
let canceled = $derived(localStatus === 'canceled')
let terminal = $derived(confirmed || canceled)
</script>

<div
    class={`px-6 py-5 transition-colors ${confirmed ? 'bg-emerald-50/60 dark:bg-emerald-950/20' : canceled ? 'bg-rose-50/60 dark:bg-rose-950/20' : ''} ${terminal ? 'opacity-70' : ''}`}
>
    <div class="flex items-start gap-4">
        <!-- Icon puck -->
        <div
            class={`mt-0.5 inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${meta.bgClass} ${meta.colorClass}`}
            title={item.algorithm}
        >
            <Icon icon={meta.icon} title={meta.label} size="4" />
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

            <!-- Sign digest expanded by default -->
            {#if item.operation === 'sign'}
                <div class="mt-3.5 rounded-lg border border-neutral-200 bg-neutral-50 p-3 dark:border-neutral-800 dark:bg-neutral-800/60">
                    <div class="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-neutral-500 dark:text-neutral-400">
                        SHA-256 digest to sign
                    </div>
                    {#if digestLoading}
                        <div class="mono text-[11px] text-neutral-500 dark:text-neutral-400">Loading…</div>
                    {:else if digestError}
                        <div class="text-[11px] text-rose-700 dark:text-rose-300">Could not decrypt digest: {digestError}</div>
                    {:else if digestHex}
                        <div class="mono break-all text-[11px] leading-relaxed text-neutral-900 dark:text-neutral-100">
                            {digestHex}
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
