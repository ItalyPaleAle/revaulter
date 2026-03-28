import ndjson from './ndjson'
import { Request } from './request'
import type {
    EcP256PublicJwk,
    V2AdminRegisterFinishResponse,
    V2LoginBeginResponse,
    V2PendingRequestItem,
    V2RegisterBeginResponse,
    V2RequestCreateBody,
    V2RequestDetail,
    V2ResponseEnvelope,
    V2SessionResponse,
} from './v2-types'

export async function v2AuthStatus() {
    return (await Request<{ setupNeeded: boolean }>('/v2/auth/status')).data
}

export async function v2RegisterBegin(username: string, displayName: string) {
    return (await Request<V2RegisterBeginResponse>('/v2/auth/register/begin', { postData: { username, displayName } }))
        .data
}

export async function v2AdminRegisterBegin(username: string, displayName: string) {
    return (
        await Request<V2RegisterBeginResponse>('/v2/auth/admin/register/begin', { postData: { username, displayName } })
    ).data
}

export async function v2RegisterFinish(args: {
    username: string
    displayName: string
    challengeId: string
    credential: unknown
}) {
    return (
        await Request<{ registered: boolean; session: V2SessionResponse }>('/v2/auth/register/finish', {
            postData: args,
        })
    ).data
}

export async function v2AdminRegisterFinish(args: {
    username: string
    displayName: string
    challengeId: string
    credential: unknown
}) {
    return (
        await Request<V2AdminRegisterFinishResponse>('/v2/auth/admin/register/finish', {
            postData: args,
        })
    ).data
}

export async function v2LoginBegin() {
    return (await Request<V2LoginBeginResponse>('/v2/auth/login/begin', { postData: {} })).data
}

export async function v2LoginFinish(args: { challengeId: string; credential: unknown }) {
    return (
        await Request<{ authenticated: boolean; session: V2SessionResponse }>('/v2/auth/login/finish', {
            postData: {
                challengeId: args.challengeId,
                credential: args.credential,
            },
        })
    ).data
}

export async function v2Session() {
    return (await Request<V2SessionResponse>('/v2/auth/session')).data
}

export async function v2Logout() {
    return (await Request<{ loggedOut: boolean }>('/v2/auth/logout', { postData: {} })).data
}

export async function v2List() {
    return (await Request<V2PendingRequestItem[]>('/v2/api/list')).data
}

export async function v2GetRequest(state: string) {
    return (await Request<V2RequestDetail>(`/v2/api/request/${state}`)).data
}

export async function v2Confirm(state: string, responseEnvelope: V2ResponseEnvelope) {
    return (
        await Request<{ confirmed: boolean }>('/v2/api/confirm', {
            postData: { state, confirm: true, responseEnvelope },
        })
    ).data
}

export async function v2Cancel(state: string) {
    return (await Request<{ canceled: boolean }>('/v2/api/confirm', { postData: { state, cancel: true } })).data
}

export async function* v2ListStream(): AsyncGenerator<V2PendingRequestItem | null, void, unknown> {
    const res = await fetch(`${import.meta.env.VITE_URL_PREFIX || ''}/v2/api/list`, {
        headers: new Headers({ accept: 'application/x-ndjson' }),
        credentials: 'same-origin',
        cache: 'no-store',
    })
    if (!res.ok || !res.body) {
        throw new Error(`Failed list stream: ${res.status}`)
    }
    const gen = ndjson<V2PendingRequestItem>(res.body.getReader())
    while (true) {
        const { done, value } = await gen.next()
        if (done) {
            break
        }
        yield value ?? null
    }
}

export function buildV2RequestBody(
    base: Omit<V2RequestCreateBody, 'clientTransportKey'>,
    clientTransportKey: EcP256PublicJwk
): V2RequestCreateBody {
    return {
        ...base,
        clientTransportKey,
    }
}
