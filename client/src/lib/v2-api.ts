import ndjson from '$lib/ndjson'
import { Request } from '$lib/request'
import type {
    EcP256PublicJwk,
    V2AuthSessionInfo,
    V2LoginBeginResponse,
    V2LoginFinishResponse,
    V2PendingRequestItem,
    V2RegisterBeginResponse,
    V2RequestDetail,
    V2ResponseEnvelope,
    V2SessionResponse,
} from '$lib/v2-types'

/** Starts the public registration flow and returns the WebAuthn challenge/options payload */
export async function v2RegisterBegin(displayName: string) {
    const res = await Request<V2RegisterBeginResponse>('/v2/auth/register/begin', {
        postData: { displayName },
    })
    return res.data
}

/** Completes registration with the browser's WebAuthn credential response */
export async function v2RegisterFinish(args: { challengeId: string; credential: unknown }) {
    const res = await Request<{ registered: boolean; session: V2AuthSessionInfo }>('/v2/auth/register/finish', {
        postData: args,
    })
    return res.data
}

/** Starts a discoverable WebAuthn login ceremony */
export async function v2LoginBegin() {
    const res = await Request<V2LoginBeginResponse>('/v2/auth/login/begin', { method: 'POST' })
    return res.data
}

/** Finishes login by posting the WebAuthn assertion back to the server */
export async function v2LoginFinish(args: { challengeId: string; credential: unknown }) {
    const res = await Request<V2LoginFinishResponse>('/v2/auth/login/finish', {
        postData: {
            challengeId: args.challengeId,
            credential: args.credential,
        },
    })
    return res.data
}

/** Finalizes the signup by storing the request encryption public keys (ECDH + ML-KEM) and optional password canary */
export async function v2FinalizeSignup(
    requestEncEcdhPubkey: EcP256PublicJwk,
    requestEncMlkemPubkey: string,
    canary?: string
) {
    const body: Record<string, unknown> = { requestEncEcdhPubkey, requestEncMlkemPubkey }
    if (canary) {
        body.canary = canary
    }
    const res = await Request<{ ok: boolean }>('/v2/auth/finalize-signup', { postData: body })
    return res.data
}

/** Updates the currently signed-in user's allowed IP allowlist */
export async function v2SetAllowedIPs(allowedIps: string[]) {
    const res = await Request<{ ok: boolean; allowedIps: string[] }>('/v2/auth/allowed-ips', {
        postData: { allowedIps },
    })
    return res.data
}

/** Regenerates the currently signed-in user's request key */
export async function v2RegenerateRequestKey() {
    const res = await Request<{ ok: boolean; requestKey: string }>('/v2/auth/regenerate-request-key', {
        method: 'POST',
    })
    return res.data
}

/** Returns the current authenticated session, if any */
export async function v2Session() {
    const res = await Request<V2SessionResponse>('/v2/auth/session')
    return res.data
}

/** Revokes the current session and clears the auth cookie */
export async function v2Logout() {
    const res = await Request<{ loggedOut: boolean }>('/v2/auth/logout', { method: 'POST' })
    return res.data
}

/** Lists the currently pending requests assigned to the signed-in user */
export async function v2List() {
    const res = await Request<V2PendingRequestItem[]>('/v2/api/list')
    return res.data
}

/** Fetches full details for a single pending request */
export async function v2GetRequest(state: string) {
    const res = await Request<V2RequestDetail>(`/v2/api/request/${state}`)
    return res.data
}

/** Confirms a pending request and sends the encrypted response envelope to the server */
export async function v2Confirm(state: string, responseEnvelope: V2ResponseEnvelope) {
    const res = await Request<{ confirmed: boolean }>('/v2/api/confirm', {
        postData: { state, confirm: true, responseEnvelope },
    })
    return res.data
}

/** Cancels a pending request without returning any encrypted result payload */
export async function v2Cancel(state: string) {
    const res = await Request<{ canceled: boolean }>('/v2/api/confirm', { postData: { state, cancel: true } })
    return res.data
}

/** Validates that an object represents a correct V2PendingRequestItem */
function isV2PendingRequestItem(v: unknown): v is V2PendingRequestItem {
    if (typeof v !== 'object' || v === null) {
        return false
    }
    const obj = v as Record<string, unknown>
    return typeof obj.state === 'string' && typeof obj.status === 'string'
}

/**
 * Streams pending request list updates over NDJSON. The server emits full list items
 * incrementally so the UI can update in real time without polling.
 */
export async function* v2ListStream(): AsyncGenerator<V2PendingRequestItem | null, void, unknown> {
    // Abort the streaming connection after 5 minutes of inactivity to prevent hanging connections from leaking resources
    const controller = new AbortController()
    const connectionTimeout = 5 * 60 * 1000 // 5 minutes
    let timer = setTimeout(() => controller.abort(), connectionTimeout)

    // Reset the timeout whenever we receive data
    const resetTimer = () => {
        clearTimeout(timer)
        timer = setTimeout(() => controller.abort(), connectionTimeout)
    }

    // Request the streaming list endpoint explicitly as NDJSON and keep credentials attached.
    const res = await fetch('/v2/api/list', {
        headers: new Headers({ accept: 'application/x-ndjson' }),
        credentials: 'same-origin',
        cache: 'no-store',
        signal: controller.signal,
    })
    if (!res.ok || !res.body) {
        throw new Error(`Failed list stream: ${res.status}`)
    }

    // Decode the response body as a stream of newline-delimited JSON objects
    const gen = ndjson<V2PendingRequestItem>(res.body.getReader(), isV2PendingRequestItem)
    try {
        while (true) {
            const { done, value } = await gen.next()
            if (done) {
                break
            }

            // Reset the inactivity timeout each time we receive a frame
            resetTimer()

            // Yield `null` for empty keepalive frames so callers can distinguish them if needed
            yield value ?? null
        }
    } finally {
        clearTimeout(timer)
    }
}
