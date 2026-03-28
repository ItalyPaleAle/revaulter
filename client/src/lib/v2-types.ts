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
    aad?: string
    resultType?: string
}

export type V2RequestCreateBody = {
    targetUser: string
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
    targetUser: string
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
    targetUser: string
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
    username: string
    displayName: string
    expiresAt: number
    mode: string
    options?: unknown
    passwordFactorRequired?: boolean
    passwordSalt?: string
    passwordPbkdf2Iterations?: number
}

export type V2LoginBeginResponse = {
    challengeId: string
    challenge: string
    username: string
    allowedCredentialIds: string[]
    expiresAt: number
    mode: string
    options?: unknown
    prfSalt?: string
    passwordFactorRequired?: boolean
    passwordSalt?: string
    passwordPbkdf2Iterations?: number
    passwordProofChallenge?: string
}

export type V2SessionResponse = {
    authenticated: boolean
    username: string
    ttl: number
    passwordVerified?: boolean
}

export type V2AdminRegisterFinishResponse = {
    registered: boolean
    username: string
}
