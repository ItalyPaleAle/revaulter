import { createHash, createHmac, randomBytes } from 'node:crypto'

import { cborBytes, cborMap, cborText } from './cbor.mjs'
import { getPasskeyAlgorithm } from './passkey-algorithms.mjs'

// Chrome's built-in virtual authenticator only ever mints ES256 credentials, so tests that need another passkey algorithm run against this software authenticator instead
// It lives in the node test process and is reached from the page through a Playwright binding, which keeps the credential store alive across reloads and navigations the same way a real authenticator would

// Fixed AAGUID identifying credentials minted by this authenticator
const AAGUID = Buffer.from('9c1e0f7a3b5d4e6f8a0b1c2d3e4f5061', 'hex')

// authData flag bits
// Specification: §6.1. Authenticator Data (https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
const FLAG_USER_PRESENT = 0x01
const FLAG_USER_VERIFIED = 0x04
const FLAG_BACKUP_ELIGIBLE = 0x08
const FLAG_BACKUP_STATE = 0x10
const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40
const FLAG_EXTENSION_DATA = 0x80

// The PRF extension hashes its inputs with this prefix before handing them to the authenticator's hmac-secret
// Specification: §10.1.4. Pseudo-random function extension (https://www.w3.org/TR/webauthn-3/#prf-extension)
const PRF_PREFIX = Buffer.concat([Buffer.from('WebAuthn PRF', 'utf8'), Buffer.from([0x00])])

function base64UrlToBuffer(value) {
    if (typeof value !== 'string') {
        throw new Error('Expected a base64url string')
    }
    return Buffer.from(value, 'base64url')
}

function toBase64Url(value) {
    return Buffer.from(value).toString('base64url')
}

// Errors carrying a DOMException name so the page shim can rethrow them the way the Credentials API would
class AuthenticatorError extends Error {
    constructor(name, message) {
        super(message)
        this.domName = name
    }
}

export class SoftwareAuthenticator {
    constructor(options = {}) {
        this.algorithm = getPasskeyAlgorithm(options.algorithm ?? 'es256')
        // A "PRF-less" authenticator is useful for asserting the client's error path, matching the virtual authenticator's hasPrf option
        this.supportsPrf = options.supportsPrf ?? true
        this.credentials = new Map()
        this.enabled = true
    }

    get credentialCount() {
        return this.credentials.size
    }

    // Handles one request forwarded from the page shim
    // Errors are returned rather than thrown so Playwright's binding does not turn them into an opaque rejection
    async handle(request) {
        if (!this.enabled) {
            return { error: { name: 'NotAllowedError', message: 'The software authenticator was disposed' } }
        }

        try {
            switch (request?.kind) {
                case 'create':
                    return { result: this.create(request) }
                case 'get':
                    return { result: this.get(request) }
                default:
                    throw new AuthenticatorError('NotSupportedError', `Unsupported request: ${request?.kind}`)
            }
        } catch (err) {
            return {
                error: {
                    name: err instanceof AuthenticatorError ? err.domName : 'NotAllowedError',
                    message: err instanceof Error ? err.message : String(err),
                },
            }
        }
    }

    create(request) {
        const publicKey = request.publicKey ?? {}
        const rpID = publicKey.rp?.id
        if (!rpID) {
            throw new AuthenticatorError('NotSupportedError', 'Creation options are missing rp.id')
        }

        // Honor the relying party's algorithm preferences: a real authenticator only mints a credential the RP asked for
        const params = Array.isArray(publicKey.pubKeyCredParams) ? publicKey.pubKeyCredParams : []
        const offered = params.some((param) => param?.alg === this.algorithm.coseAlgorithm)
        if (!offered) {
            throw new AuthenticatorError(
                'NotSupportedError',
                `The relying party did not offer ${this.algorithm.label} (COSE algorithm ${this.algorithm.coseAlgorithm}) in pubKeyCredParams`
            )
        }

        // Registering a second credential for a credential this authenticator already holds is what excludeCredentials prevents
        const excluded = Array.isArray(publicKey.excludeCredentials) ? publicKey.excludeCredentials : []
        for (const descriptor of excluded) {
            const existing = this.credentials.get(descriptor?.id)
            if (existing && existing.rpID === rpID) {
                throw new AuthenticatorError(
                    'InvalidStateError',
                    'A credential for this authenticator is already registered'
                )
            }
        }

        const { privateKey, coseKey } = this.algorithm.generateKeyPair()
        const credentialID = randomBytes(32)
        const credentialIDEncoded = toBase64Url(credentialID)
        const credential = {
            id: credentialIDEncoded,
            rawID: credentialID,
            rpID,
            userHandle: base64UrlToBuffer(publicKey.user?.id ?? ''),
            privateKey,
            coseKey,
            prfKey: randomBytes(32),
            signCount: 0,
        }
        this.credentials.set(credentialIDEncoded, credential)

        const clientDataJSON = this.#clientData('webauthn.create', publicKey.challenge, request.origin)
        const authData = this.#authenticatorData(credential, { attestedCredentialData: true })
        // "none" attestation is what a platform authenticator returns when the RP does not ask for one
        const attestationObject = cborMap([
            [cborText('fmt'), cborText('none')],
            [cborText('attStmt'), cborMap([])],
            [cborText('authData'), cborBytes(authData)],
        ])

        return {
            kind: 'attestation',
            id: credential.id,
            rawId: credential.id,
            authenticatorAttachment: 'platform',
            response: {
                clientDataJSON: toBase64Url(clientDataJSON),
                attestationObject: toBase64Url(attestationObject),
                authenticatorData: toBase64Url(authData),
                transports: ['internal', 'hybrid'],
                publicKeyAlgorithm: this.algorithm.coseAlgorithm,
            },
            clientExtensionResults: this.supportsPrf ? { prf: { enabled: true } } : {},
        }
    }

    get(request) {
        const publicKey = request.publicKey ?? {}
        const rpID = publicKey.rpId
        if (!rpID) {
            throw new AuthenticatorError('NotSupportedError', 'Request options are missing rpId')
        }

        const credential = this.#selectCredential(rpID, publicKey.allowCredentials)
        if (!credential) {
            throw new AuthenticatorError('NotAllowedError', 'No credential is available for this relying party')
        }

        credential.signCount++

        const clientDataJSON = this.#clientData('webauthn.get', publicKey.challenge, request.origin)
        const authData = this.#authenticatorData(credential, { attestedCredentialData: false })
        const clientDataHash = createHash('sha256').update(clientDataJSON).digest()
        const signature = this.algorithm.sign(credential.privateKey, Buffer.concat([authData, clientDataHash]))

        return {
            kind: 'assertion',
            id: credential.id,
            rawId: credential.id,
            authenticatorAttachment: 'platform',
            response: {
                clientDataJSON: toBase64Url(clientDataJSON),
                authenticatorData: toBase64Url(authData),
                signature: toBase64Url(signature),
                userHandle: credential.userHandle.length > 0 ? toBase64Url(credential.userHandle) : null,
            },
            clientExtensionResults: this.#prfResults(credential, publicKey.extensions?.prf),
        }
    }

    // Picks the credential that answers a request, honoring allowCredentials when the relying party restricts the set
    #selectCredential(rpID, allowCredentials) {
        const allowed = Array.isArray(allowCredentials) ? allowCredentials : []
        if (allowed.length > 0) {
            for (const descriptor of allowed) {
                const credential = this.credentials.get(descriptor?.id)
                if (credential && credential.rpID === rpID) {
                    return credential
                }
            }
            return null
        }

        // A discoverable credential request takes the most recently created credential for the relying party, which is the one tests just registered
        let selected = null
        for (const credential of this.credentials.values()) {
            if (credential.rpID === rpID) {
                selected = credential
            }
        }
        return selected
    }

    #clientData(type, challenge, origin) {
        if (typeof challenge !== 'string') {
            throw new AuthenticatorError('NotSupportedError', 'Options are missing a challenge')
        }

        return Buffer.from(
            JSON.stringify({
                type,
                challenge,
                origin,
                crossOrigin: false,
            }),
            'utf8'
        )
    }

    #authenticatorData(credential, { attestedCredentialData }) {
        const rpIDHash = createHash('sha256').update(credential.rpID, 'utf8').digest()

        let flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_BACKUP_ELIGIBLE | FLAG_BACKUP_STATE
        const parts = []

        if (attestedCredentialData) {
            flags |= FLAG_ATTESTED_CREDENTIAL_DATA
            const credentialIDLength = Buffer.alloc(2)
            credentialIDLength.writeUInt16BE(credential.rawID.length)
            parts.push(AAGUID, credentialIDLength, credential.rawID, credential.coseKey)
        }

        // A PRF-capable authenticator reports hmac-secret in the authenticator extension outputs, which also puts trailing bytes after the COSE key for the client's parser to skip
        if (this.supportsPrf) {
            flags |= FLAG_EXTENSION_DATA
            parts.push(cborMap([[cborText('hmac-secret'), Buffer.from([0xf5])]]))
        }

        const header = Buffer.alloc(37)
        rpIDHash.copy(header, 0)
        header[32] = flags
        header.writeUInt32BE(credential.signCount, 33)

        return Buffer.concat([header, ...parts])
    }

    // Evaluates the PRF extension inputs against the credential's hmac-secret
    // The output only has to be stable for a given credential and salt, which is what the client relies on to re-derive its local keys on every sign-in
    #prfResults(credential, prfInput) {
        if (!this.supportsPrf) {
            return {}
        }
        if (!prfInput?.eval) {
            return { prf: { enabled: true } }
        }

        const results = {}
        for (const key of ['first', 'second']) {
            const salt = prfInput.eval[key]
            if (typeof salt !== 'string') {
                continue
            }
            const input = createHash('sha256').update(PRF_PREFIX).update(base64UrlToBuffer(salt)).digest()
            results[key] = toBase64Url(createHmac('sha256', credential.prfKey).update(input).digest())
        }

        return { prf: { enabled: true, results } }
    }
}

// The page-side shim replacing navigator.credentials with one that forwards every ceremony to the node authenticator
// It is stringified into the page by addInitScript, so it may only reference its own argument and browser globals
function installShim({ bindingName }) {
    function toBase64Url(source) {
        const bytes =
            source instanceof ArrayBuffer
                ? new Uint8Array(source)
                : new Uint8Array(source.buffer, source.byteOffset, source.byteLength)
        let binary = ''
        for (const byte of bytes) {
            binary += String.fromCharCode(byte)
        }
        return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
    }

    function fromBase64Url(value) {
        const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/'))
        const bytes = new Uint8Array(binary.length)
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i)
        }
        return bytes
    }

    // Options carry binary as BufferSource values, which have to become base64url strings to cross the binding
    function encodeOptions(input) {
        if (input instanceof ArrayBuffer || ArrayBuffer.isView(input)) {
            return toBase64Url(input)
        }
        if (Array.isArray(input)) {
            return input.map((value) => encodeOptions(value))
        }
        if (input !== null && typeof input === 'object') {
            const out = {}
            for (const [key, value] of Object.entries(input)) {
                out[key] = encodeOptions(value)
            }
            return out
        }
        return input
    }

    function decodeExtensionResults(input) {
        if (input === null || typeof input !== 'object') {
            return input
        }
        if (Array.isArray(input)) {
            return input.map((value) => decodeExtensionResults(value))
        }

        const out = {}
        for (const [key, value] of Object.entries(input)) {
            // PRF outputs reach the page as ArrayBuffers, matching what a browser hands to the relying party
            if ((key === 'first' || key === 'second') && typeof value === 'string') {
                out[key] = fromBase64Url(value).buffer
                continue
            }
            out[key] = decodeExtensionResults(value)
        }
        return out
    }

    async function callAuthenticator(payload) {
        const response = await window[bindingName](payload)
        if (response.error) {
            throw new DOMException(response.error.message, response.error.name)
        }
        return response.result
    }

    function buildCredential(result) {
        const response = {}
        for (const [key, value] of Object.entries(result.response)) {
            // Transports and the algorithm identifier are not binary, and a missing user handle stays null
            if (key === 'transports' || key === 'publicKeyAlgorithm' || value === null) {
                continue
            }
            response[key] = fromBase64Url(value).buffer
        }

        if (result.kind === 'attestation') {
            response.getTransports = () => [...result.response.transports]
            response.getAuthenticatorData = () => fromBase64Url(result.response.authenticatorData).buffer
            response.getPublicKeyAlgorithm = () => result.response.publicKeyAlgorithm
            response.getPublicKey = () => null
        } else {
            response.userHandle = result.response.userHandle ? fromBase64Url(result.response.userHandle).buffer : null
        }

        const extensionResults = decodeExtensionResults(result.clientExtensionResults)
        return {
            id: result.id,
            rawId: fromBase64Url(result.rawId).buffer,
            type: 'public-key',
            authenticatorAttachment: result.authenticatorAttachment,
            response,
            getClientExtensionResults: () => extensionResults,
            // Browsers expose a serializer that already encodes every binary field as base64url
            toJSON: () => ({
                id: result.id,
                rawId: result.rawId,
                type: 'public-key',
                authenticatorAttachment: result.authenticatorAttachment,
                response: { ...result.response },
                clientExtensionResults: result.clientExtensionResults,
            }),
        }
    }

    navigator.credentials.create = async (options) => {
        return buildCredential(
            await callAuthenticator({
                kind: 'create',
                origin: window.location.origin,
                publicKey: encodeOptions(options?.publicKey),
            })
        )
    }

    navigator.credentials.get = async (options) => {
        return buildCredential(
            await callAuthenticator({
                kind: 'get',
                origin: window.location.origin,
                publicKey: encodeOptions(options?.publicKey),
            })
        )
    }
}

let bindingCounter = 0

// Installs a software authenticator on a page for the lifetime of a test
// The authenticator must be installed before the page navigates to the app, because the shim is applied to new documents
export async function installSoftwareAuthenticator(page, options = {}) {
    const authenticator = new SoftwareAuthenticator(options)
    bindingCounter++
    const bindingName = `__revaulterSoftwareAuthenticator${bindingCounter}`

    await page.exposeFunction(bindingName, (request) => authenticator.handle(request))
    await page.addInitScript(installShim, { bindingName })

    return {
        authenticator,
        algorithm: authenticator.algorithm,
        async dispose() {
            authenticator.enabled = false
        },
    }
}
