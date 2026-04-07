export type EcP256PublicJwk = {
    kty: 'EC'
    crv: 'P-256'
    x: string
    y: string
}

export type V2ResponseEnvelope = {
    transportAlg: 'ecdh-p256+a256gcm'
    browserEphemeralPublicKey: EcP256PublicJwk
    nonce: string
    ciphertext: string
    resultType?: string
}

export type V2RequestCreateBody = {
    keyLabel: string
    algorithm: string
    value: string
    nonce?: string
    tag?: string
    additionalData?: string
    timeout?: string
    note?: string
    clientTransportKey: EcP256PublicJwk
}

export type V2PendingRequestItem = {
    state: string
    status: 'pending' | 'completed' | 'canceled' | 'expired' | 'removed'
    operation: 'encrypt' | 'decrypt'
    userId: string
    keyLabel: string
    algorithm: string
    requestor?: string
    date: number
    expiry: number
    note?: string
}

export type V2RequestDetail = {
    state: string
    status: string
    operation: 'encrypt' | 'decrypt'
    userId: string
    keyLabel: string
    algorithm: string
    requestor?: string
    date: number
    expiry: number
    note?: string
    request: V2RequestCreateBody
}

export type V2RegisterBeginResponse = {
    challengeId: string
    challenge: string
    expiresAt: number
    mode: string
    options?: unknown
    basePrfSalt: string
}

export type V2AuthSessionInfo = {
    userId: string
    displayName: string
    requestKey: string
    allowedIps: string[]
    ttl: number
}

export type V2LoginBeginResponse = {
    challengeId: string
    challenge: string
    expiresAt: number
    mode: string
    options?: unknown
    basePrfSalt: string
}

export type V2LoginFinishResponse = {
    authenticated: boolean
    session?: V2AuthSessionInfo
    passwordCanary?: string
}

export type V2SessionResponse = {
    authenticated: boolean
    userId: string
    displayName: string
    requestKey: string
    allowedIps: string[]
    ttl: number
}
