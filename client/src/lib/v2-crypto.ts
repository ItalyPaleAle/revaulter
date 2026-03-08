import { Decode as Base64UrlDecode, Encode as Base64UrlEncode } from 'arraybuffer-encoding/base64/url'
import type { EcP256PublicJwk, V2ResponseEnvelope } from './v2-types'

function asBuf(v?: Uint8Array | ArrayBuffer): BufferSource | undefined {
    if (v === undefined) return undefined
    return v as unknown as BufferSource
}

function toArrayBuffer(bytes: ArrayBuffer | Uint8Array): ArrayBuffer {
    if (bytes instanceof Uint8Array) {
        const out = new Uint8Array(bytes.byteLength)
        out.set(bytes)
        return out.buffer
    }
    return bytes
}

function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
    return Base64UrlEncode(toArrayBuffer(bytes))
}

function base64UrlToBytes(s: string): Uint8Array {
    return new Uint8Array(Base64UrlDecode(s))
}

export async function generateTransportKeyPairJwk(): Promise<{
    privateKey: CryptoKey
    publicKeyJwk: EcP256PublicJwk
}> {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
    )
    const jwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
        throw new Error('Failed to export transport public key as P-256 JWK')
    }
    return {
        privateKey: keyPair.privateKey,
        publicKeyJwk: {
            kty: 'EC',
            crv: 'P-256',
            x: jwk.x,
            y: jwk.y,
        },
    }
}

async function deriveTransportAesKey(
    state: string,
    privateKey: CryptoKey,
    peerPublicJwk: EcP256PublicJwk
): Promise<CryptoKey> {
    const peerKey = await crypto.subtle.importKey(
        'jwk',
        peerPublicJwk as JsonWebKey,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    )
    const sharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, privateKey, 256)
    const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey'])
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new Uint8Array(),
            info: new TextEncoder().encode(`revaulter/v2/transport/${state}`),
        },
        hkdfKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )
}

export async function encryptTransportEnvelope(
    state: string,
    clientTransportKey: EcP256PublicJwk,
    plaintext: Uint8Array,
    aad?: Uint8Array
): Promise<V2ResponseEnvelope> {
    const eph = await generateTransportKeyPairJwk()
    const aesKey = await deriveTransportAesKey(state, eph.privateKey, clientTransportKey)
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: asBuf(nonce),
            additionalData: asBuf(aad),
        },
        aesKey,
        asBuf(plaintext) as BufferSource
    )
    return {
        transportAlg: 'ecdh-p256+a256gcm',
        browserEphemeralPublicKey: eph.publicKeyJwk,
        nonce: bytesToBase64Url(nonce),
        ciphertext: bytesToBase64Url(ciphertext),
        aad: aad && aad.length > 0 ? bytesToBase64Url(aad) : undefined,
        resultType: 'bytes',
    }
}

export async function decryptTransportEnvelope(
    state: string,
    privateKey: CryptoKey,
    env: V2ResponseEnvelope
): Promise<Uint8Array> {
    const aesKey = await deriveTransportAesKey(state, privateKey, env.browserEphemeralPublicKey)
    const plain = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: asBuf(base64UrlToBytes(env.nonce)) as BufferSource,
            additionalData: asBuf(env.aad ? base64UrlToBytes(env.aad) : undefined),
        },
        aesKey,
        asBuf(base64UrlToBytes(env.ciphertext)) as BufferSource
    )
    return new Uint8Array(plain)
}

export async function deriveOperationKeyBytes(params: {
    state: string
    targetUser: string
    keyLabel: string
    operation: string
    algorithm: string
    prfSecret: Uint8Array
    passwordKey?: Uint8Array
}): Promise<Uint8Array> {
    const ikm = await crypto.subtle.importKey('raw', asBuf(params.prfSecret) as BufferSource, 'HKDF', false, ['deriveBits'])
    const salt = params.passwordKey ?? new Uint8Array()
    const infoObj = {
        v: 1,
        state: params.state,
        targetUser: params.targetUser,
        keyLabel: params.keyLabel,
        operation: params.operation,
        algorithm: params.algorithm,
    }
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: asBuf(salt) as BufferSource,
            info: new TextEncoder().encode(JSON.stringify(infoObj)),
        },
        ikm,
        256
    )
    return new Uint8Array(bits)
}

export async function derivePasswordKeyBytes(password: string, salt: Uint8Array, iterations = 300_000): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey('raw', asBuf(new TextEncoder().encode(password)) as BufferSource, 'PBKDF2', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt: asBuf(salt) as BufferSource,
            iterations,
        },
        key,
        256
    )
    return new Uint8Array(bits)
}

async function hkdfSha256(inputKeyMaterial: Uint8Array, info: string, salt?: Uint8Array): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey('raw', asBuf(inputKeyMaterial) as BufferSource, 'HKDF', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: asBuf(salt ?? new Uint8Array()) as BufferSource,
            info: asBuf(new TextEncoder().encode(info)) as BufferSource,
        },
        key,
        256
    )
    return new Uint8Array(bits)
}

export async function derivePasswordAuthKeyBytes(password: string, salt: Uint8Array, iterations = 300_000): Promise<Uint8Array> {
    const base = await derivePasswordKeyBytes(password, salt, iterations)
    return hkdfSha256(base, 'revaulter/v2/password-auth')
}

export async function derivePasswordLocalKeyBytes(password: string, salt: Uint8Array, iterations = 300_000): Promise<Uint8Array> {
    const base = await derivePasswordKeyBytes(password, salt, iterations)
    return hkdfSha256(base, 'revaulter/v2/password-local')
}

export async function computePasswordProof(params: {
    username: string
    challengeId: string
    webauthnChallenge: string
    passwordProofChallenge: string
    passwordAuthKey: Uint8Array
}): Promise<string> {
    const msg = new TextEncoder().encode(
        ['revaulter-v2-password-proof', params.username, params.challengeId, params.webauthnChallenge, params.passwordProofChallenge].join('|')
    )
    const hmacKey = await crypto.subtle.importKey('raw', asBuf(params.passwordAuthKey) as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const sig = await crypto.subtle.sign('HMAC', hmacKey, asBuf(msg) as BufferSource)
    return bytesToBase64Url(sig)
}

export async function performAesGcmOperation(params: {
    mode: 'encrypt' | 'decrypt' | 'wrapkey' | 'unwrapkey'
    keyBytes: Uint8Array
    value: Uint8Array
    nonce?: Uint8Array
    aad?: Uint8Array
    tag?: Uint8Array
}): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey('raw', asBuf(params.keyBytes) as BufferSource, { name: 'AES-GCM' }, false, [
        params.mode === 'encrypt' || params.mode === 'wrapkey' ? 'encrypt' : 'decrypt',
    ])
    const iv = params.nonce ?? crypto.getRandomValues(new Uint8Array(12))

    if (params.mode === 'encrypt' || params.mode === 'wrapkey') {
        const res = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: asBuf(iv) as BufferSource, additionalData: asBuf(params.aad) },
            key,
            asBuf(params.value) as BufferSource
        )
        return new Uint8Array(res)
    }

    // For decrypt/unwrap, if a separate tag is passed, concatenate ciphertext+tag (WebCrypto expects combined input).
    const combined =
        params.tag && params.tag.length > 0
            ? (() => {
                  const out = new Uint8Array(params.value.length + params.tag.length)
                  out.set(params.value, 0)
                  out.set(params.tag, params.value.length)
                  return out
              })()
            : params.value

    const res = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: asBuf(iv) as BufferSource, additionalData: asBuf(params.aad) },
        key,
        asBuf(combined) as BufferSource
    )
    return new Uint8Array(res)
}

export function splitAesGcmCiphertextAndTag(ciphertextWithTag: Uint8Array, tagLen = 16) {
    if (ciphertextWithTag.length < tagLen) {
        throw new Error('Ciphertext is too short')
    }
    return {
        data: ciphertextWithTag.slice(0, ciphertextWithTag.length - tagLen),
        tag: ciphertextWithTag.slice(ciphertextWithTag.length - tagLen),
    }
}

export function b64urlToBytes(s?: string): Uint8Array {
    return s ? base64UrlToBytes(s) : new Uint8Array()
}

export function bytesToB64url(v: Uint8Array): string {
    return bytesToBase64Url(v)
}
