<script lang="ts">
import { formatDistanceToNowStrict } from 'date-fns'

import Button from '$components/Button.svelte'
import LoadingSpinner from '$components/LoadingSpinner.svelte'

import {
    buildRequestEncAAD,
    buildTransportAAD,
    decryptRequestPayload,
    deriveOperationKeyBytes,
    deriveSigningKeyPair,
    ecP256JwkToPem,
    encryptTransportEnvelope,
    performAesGcmOperation,
    signDigestEs256,
    splitAesGcmCiphertextAndTag,
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
            if (req.algorithm !== 'A256GCM') {
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

            const { privateKey, publicJwk } = await deriveSigningKeyPair({
                userId: req.userId,
                keyLabel: req.keyLabel,
                algorithm: req.algorithm,
                primaryKey,
            })
            const signature = await signDigestEs256(privateKey, value)
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

function operationTitle(op: V2PendingRequestItem['operation']) {
    switch (op) {
        case 'encrypt':
            return 'Encrypt'
        case 'decrypt':
            return 'Decrypt'
        case 'sign':
            return 'Sign'
    }
}

/** Renders a SHA-256 digest (32 bytes, base64url) as an uppercase hex string with spaces for display */
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
 * For sign requests, decrypts the E2EE inner payload so the user can review the
 * SHA-256 digest before approving. Triggered lazily when the item is a sign
 * request — other operations don't need to expose inner payload contents.
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

function expiresIn(item: V2PendingRequestItem) {
    return formatDistanceToNowStrict(new Date(item.expiry * 1000), { addSuffix: true })
}
</script>

<div class="rounded-[1.6rem] border border-white/80 bg-white/86 p-4 shadow-[0_4px_16px_-14px_rgba(15,23,42,0.18)] backdrop-blur-sm dark:border-white/10 dark:bg-slate-950/82">
    <div class="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div class="space-y-1">
            <div class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500 dark:text-slate-400">{operationTitle(item.operation)} request</div>
            <div class="text-base font-semibold text-slate-900 dark:text-white">
                {item.keyLabel}
                <span class="font-normal text-slate-500 dark:text-slate-400"> · {item.algorithm}</span>
            </div>
            {#if item.requestor}
                <div class="text-sm text-slate-700 dark:text-slate-300">
                    Requestor: <span class="font-mono">{item.requestor}</span>
                </div>
            {/if}
            {#if item.note}
                <div class="text-sm italic text-slate-700 dark:text-slate-300">“{item.note}”</div>
            {/if}
            {#if item.operation === 'sign'}
                <div class="mt-2 text-xs text-slate-500 dark:text-slate-400">SHA-256 digest to sign:</div>
                {#if digestLoading}
                    <div class="text-xs text-slate-500 dark:text-slate-400">Loading…</div>
                {:else if digestError}
                    <div class="text-xs text-rose-700 dark:text-rose-300">Could not decrypt digest: {digestError}</div>
                {:else if digestHex}
                    <div class="break-all rounded bg-slate-100 px-2 py-1 font-mono text-xs text-slate-800 dark:bg-slate-900 dark:text-slate-200">
                        {digestHex}
                    </div>
                {/if}
            {/if}
            <div class="text-xs text-slate-500 dark:text-slate-400">
                Expires {expiresIn(item)} · <span class="font-mono">{item.state}</span>
            </div>
        </div>

        <div class="min-w-52 border-t border-slate-200/80 pt-3 dark:border-white/10 md:border-l md:border-t-0 md:pl-4 md:pt-0">
            {#if error}
                <div class="rounded border border-rose-200 bg-rose-50 px-2 py-1 text-xs text-rose-800 dark:border-rose-800 dark:bg-rose-950/40 dark:text-rose-200">
                    {error}
                </div>
            {/if}
            <div class="flex gap-2">
                <Button
                    class="flex-1"
                    size="sm"
                    variant="success"
                    disabled={working || localStatus !== 'pending'}
                    onclick={doConfirm}
                >
                    {#if working && localStatus === '_processing'}<LoadingSpinner size="1rem" />{/if}
                    Confirm
                </Button>
                <Button
                    class="flex-1"
                    size="sm"
                    variant="danger"
                    disabled={working || localStatus !== 'pending'}
                    onclick={doCancel}
                >
                    Cancel
                </Button>
            </div>
            {#if localStatus === 'confirmed'}
                <div class="mt-2 text-sm text-emerald-700 dark:text-emerald-300">Confirmed</div>
            {:else if localStatus === 'canceled'}
                <div class="mt-2 text-sm text-rose-700 dark:text-rose-300">Canceled</div>
            {:else if localStatus === '_failed'}
                <div class="mt-2 text-sm text-rose-700 dark:text-rose-300">Failed</div>
            {/if}
        </div>
    </div>
</div>
