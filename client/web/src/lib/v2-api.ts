import ndjson from '$lib/ndjson'
import { Request } from '$lib/request'
import type {
    EcP256PublicJwk,
    V2AddCredentialBeginResponse,
    V2AuthSessionInfo,
    V2CredentialItem,
    V2LoginBeginResponse,
    V2LoginFinishResponse,
    V2PendingRequestItem,
    V2PublishedSigningKey,
    V2RegisterBeginResponse,
    V2RequestDetail,
    V2ResponseEnvelope,
    V2SessionResponse,
    V2SigningJwk,
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

/**
 * Finalizes the signup by storing the transport pubkeys, the wrapped primary key,
 * the user's long-lived hybrid anchor pubkeys + self-signatures over the pubkey
 * bundle, and the first credential's wrapped anchor + hybrid attestation.
 */
export async function v2FinalizeSignup(args: {
    requestEncEcdhPubkey: EcP256PublicJwk
    requestEncMlkemPubkey: string
    wrappedPrimaryKey?: string
    anchorEs384PublicKey: unknown
    anchorMldsa87PublicKey: string
    pubkeyBundleSignatureEs384: string
    pubkeyBundleSignatureMldsa87: string
    wrappedAnchorKey: string
    attestationPayload: string
    attestationSignatureEs384: string
    attestationSignatureMldsa87: string
}) {
    const body: Record<string, unknown> = {
        requestEncEcdhPubkey: args.requestEncEcdhPubkey,
        requestEncMlkemPubkey: args.requestEncMlkemPubkey,
        anchorEs384PublicKey: args.anchorEs384PublicKey,
        anchorMldsa87PublicKey: args.anchorMldsa87PublicKey,
        pubkeyBundleSignatureEs384: args.pubkeyBundleSignatureEs384,
        pubkeyBundleSignatureMldsa87: args.pubkeyBundleSignatureMldsa87,
        wrappedAnchorKey: args.wrappedAnchorKey,
        attestationPayload: args.attestationPayload,
        attestationSignatureEs384: args.attestationSignatureEs384,
        attestationSignatureMldsa87: args.attestationSignatureMldsa87,
    }
    if (args.wrappedPrimaryKey) {
        body.wrappedPrimaryKey = args.wrappedPrimaryKey
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

/** Confirms a pending request and sends the encrypted response envelope to the server
 * For sign operations, the derived public key (jwk + pem) is sent alongside the envelope so the server can auto-store it (published=false) if it isn't already known
 */
export async function v2Confirm(
    state: string,
    responseEnvelope: V2ResponseEnvelope,
    publicKey?: { jwk: V2SigningJwk; pem: string }
) {
    const body: Record<string, unknown> = { state, confirm: true, responseEnvelope }
    if (publicKey) {
        body.publicKey = publicKey
    }

    const res = await Request<{ confirmed: boolean }>('/v2/api/confirm', {
        postData: body,
    })
    return res.data
}

/** Cancels a pending request without returning any encrypted result payload */
export async function v2Cancel(state: string) {
    const res = await Request<{ canceled: boolean }>('/v2/api/confirm', { postData: { state, cancel: true } })
    return res.data
}

/** Updates the currently signed-in user's display name */
export async function v2UpdateDisplayName(displayName: string) {
    const res = await Request<{ ok: boolean; displayName: string }>('/v2/auth/update-display-name', {
        postData: { displayName },
    })
    return res.data
}

/** Updates the wrapped primary key and anchor key for a specific credential */
export async function v2UpdateWrappedKey(
    credentialId: string,
    wrappedPrimaryKey: string,
    wrappedAnchorKey: string,
    advanceEpoch = false
) {
    const res = await Request<{ ok: boolean }>('/v2/auth/update-wrapped-key', {
        postData: { credentialId, wrappedPrimaryKey, wrappedAnchorKey, advanceEpoch },
    })
    return res.data
}

/** Lists all passkey credentials for the currently signed-in user */
export async function v2ListCredentials() {
    const res = await Request<V2CredentialItem[]>('/v2/auth/credentials')
    return res.data
}

/** Begins WebAuthn registration ceremony for adding a new credential */
export async function v2AddCredentialBegin(credentialName?: string) {
    const res = await Request<V2AddCredentialBeginResponse>('/v2/auth/credentials/add/begin', {
        postData: { credentialName: credentialName || '' },
    })
    return res.data
}

/**
 * Completes WebAuthn registration ceremony for adding a new credential.
 * The browser must also supply a wrapped anchor blob and a hybrid attestation
 * (both signatures) so the server can bind the new credential to the user's
 * existing anchor identity root before inserting it.
 */
export async function v2AddCredentialFinish(args: {
    challengeId: string
    credential: unknown
    credentialName?: string
    wrappedPrimaryKey?: string
    wrappedAnchorKey: string
    attestationPayload: string
    attestationSignatureEs384: string
    attestationSignatureMldsa87: string
}) {
    const res = await Request<{ ok: boolean }>('/v2/auth/credentials/add/finish', {
        postData: args,
    })
    return res.data
}

/** Renames a passkey credential */
export async function v2RenameCredential(id: string, displayName: string) {
    const res = await Request<{ ok: boolean }>('/v2/auth/credentials/rename', {
        postData: { id, displayName },
    })
    return res.data
}

/** Deletes a passkey credential (must keep at least one) */
export async function v2DeleteCredential(id: string) {
    const res = await Request<{ ok: boolean }>('/v2/auth/credentials/delete', {
        postData: { id },
    })
    return res.data
}

/** Lists the current user's published signing keys (metadata only) */
export async function v2ListSigningKeys() {
    const res = await Request<V2PublishedSigningKey[]>('/v2/api/signing-keys')
    return res.data
}

/** Fetches a single signing key owned by the current user, including JWK and PEM
 * The row is returned regardless of its published flag so the UI can re-export an auto-stored key without publishing it
 */
export async function v2GetSigningKey(id: string) {
    const res = await Request<V2PublishedSigningKey & { jwk: V2SigningJwk; pem: string }>(
        `/v2/api/signing-keys/${encodeURIComponent(id)}`
    )
    return res.data
}

/** Creates a new signing key for the current user
 * The server rejects the request with 409 Conflict if a key already exists for the same `(algorithm, keyLabel)`
 * `published=true` exposes the key via the public endpoint; `published=false` stores it but keeps the public endpoint hidden
 */
export async function v2CreateSigningKey(args: {
    algorithm: string
    keyLabel: string
    jwk: V2SigningJwk
    pem: string
    published: boolean
}) {
    const res = await Request<V2PublishedSigningKey>('/v2/api/signing-keys', {
        postData: args,
    })
    return res.data
}

/** Flips the published flag on an existing signing key without resubmitting the key material */
export async function v2SetSigningKeyPublished(id: string, published: boolean) {
    const res = await Request<V2PublishedSigningKey>(`/v2/api/signing-keys/${encodeURIComponent(id)}`, {
        postData: { published },
    })
    return res.data
}

/** Hard-deletes a signing key owned by the current user */
export async function v2DeleteSigningKey(id: string) {
    const res = await Request<{ deleted: boolean }>(`/v2/api/signing-keys/${encodeURIComponent(id)}`, {
        method: 'DELETE',
    })
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
