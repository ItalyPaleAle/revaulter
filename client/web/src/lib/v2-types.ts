export type EcP256PublicJwk = {
    kty: 'EC'
    crv: 'P-256'
    x: string
    y: string
}

export type V2ResponseEnvelope = {
    transportAlg: 'ecdh-p256+mlkem768+a256gcm'
    browserEphemeralPublicKey: EcP256PublicJwk
    mlkemCiphertext: string
    nonce: string
    ciphertext: string
    resultType?: string
}

export type V2RequestCreateBody = {
    keyLabel: string
    algorithm: string
    timeout?: string
    note?: string
    requestEncAlg: string
    cliEphemeralPublicKey: EcP256PublicJwk
    mlkemCiphertext: string
    encryptedPayloadNonce: string
    encryptedPayload: string
}

export type V2RequestPayloadInner = {
    value: string
    nonce?: string
    tag?: string
    additionalData?: string
    clientTransportEcdhKey: EcP256PublicJwk
    clientTransportMlkemKey: string
}

export type V2RequestEncEnvelope = {
    cliEphemeralPublicKey: EcP256PublicJwk
    mlkemCiphertext: string
    nonce: string
    ciphertext: string
}

export type V2Operation = 'encrypt' | 'decrypt' | 'sign'

export type V2PendingRequestItem = {
    state: string
    status: 'pending' | 'completed' | 'canceled' | 'expired' | 'removed'
    operation: V2Operation
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
    operation: V2Operation
    userId: string
    keyLabel: string
    algorithm: string
    requestor?: string
    date: number
    expiry: number
    note?: string
    encryptedRequest: V2RequestEncEnvelope
}

export type V2SigningJwk = {
    kty: 'EC'
    crv: 'P-256'
    x: string
    y: string
    alg?: 'ES256'
    use?: 'sig'
    kid?: string
}

export type V2PublishedSigningKey = {
    id: string
    algorithm: string
    keyLabel: string
    published: boolean
    hasProof: boolean
    createdAt: string
    updatedAt: string
}

// Optional fields the client sends to authorize publishing a signing key
// All three fields are required together; partial sets are rejected by the server
export type V2SigningKeyPublicationProof = {
    publicationPayload: string
    publicationSignatureEs384: string
    publicationSignatureMldsa87: string
}

export type DerivedSigningKey = {
    keyLabel: string
    algorithm: string
    jwk: V2SigningJwk
    pem: string
    sshPublicKey: string
    id: string
}

export type Argon2idCost = {
    m: number
    t: number
    p: number
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
    anchorFingerprint: string
    wrappedKeyEpoch: number
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
    wrappedPrimaryKey?: string
    wrappedAnchorKey?: string
    credentialWrappedKeyEpoch?: number
    wrappedKeyStale: boolean
}

export type V2SessionResponse = {
    authenticated: boolean
    userId: string
    displayName: string
    requestKey: string
    anchorFingerprint: string
    wrappedKeyEpoch: number
    allowedIps: string[]
    ttl: number
}

export type V2CredentialItem = {
    id: string
    displayName: string
    wrappedKeyEpoch: number
    wrappedKeyStale: boolean
    createdAt: number
    lastUsedAt: number
}

export type V2AuditEvent = {
    id: string
    createdAt: number
    eventType: string
    outcome: string
    authMethod: string
    actorUserId?: string
    targetUserId?: string
    signingKeyId?: string
    credentialId?: string
    requestState?: string
    httpRequestId?: string
    clientIp?: string
    userAgent?: string
    metadata: Record<string, unknown>
}

export type V2AuditEventsResponse = {
    events: V2AuditEvent[]
    nextCursor: string
}

export type V2AddCredentialBeginResponse = {
    challengeId: string
    challenge: string
    expiresAt: number
    options?: unknown
    basePrfSalt: string
}
