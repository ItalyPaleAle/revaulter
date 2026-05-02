<script lang="ts">
import { onMount } from 'svelte'

import AuthAccessView from '$components/AuthAccessView.svelte'
import AuthSetupView from '$components/AuthSetupView.svelte'
import ReadyView from '$components/ReadyView.svelte'

import { argon2idCost } from '$lib/argon2id-cost'
import {
    computeEcP256Thumbprint,
    deriveRequestEncKeyPair,
    deriveRequestEncMlkemKeyPair,
    deriveSigningKeyPair,
    deriveWrappingKey,
    ecP256JwkToPem,
    generatePrimaryKey,
    parseWrappedPrimaryKeyEnvelope,
    unwrapPrimaryKey,
    wrapPrimaryKey,
} from '$lib/crypto'
import {
    type AnchorKeyPair,
    anchorEs384JwkToString,
    anchorMldsa87PubToString,
    generateAnchorKeyPair,
    SIGNING_KEY_PUBLICATION_VERSION,
    serializeAnchorSecret,
    signCredentialAttestationHybrid,
    signPubkeyBundleHybrid,
    signSigningKeyPublicationHybrid,
    unwrapAnchorKey,
    wrapAnchorKey,
} from '$lib/crypto-anchor'
import { ResponseNotOkError } from '$lib/request'
import { base64UrlToBytes, bytesToBase64Url } from '$lib/utils'
import {
    v2AddCredentialBegin,
    v2AddCredentialFinish,
    v2CreateSigningKey,
    v2DeleteCredential,
    v2DeleteSigningKey,
    v2FinalizeSignup,
    v2ListCredentials,
    v2ListSigningKeys,
    v2ListStream,
    v2LoginBegin,
    v2LoginFinish,
    v2Logout,
    v2RegenerateRequestKey,
    v2RegisterBegin,
    v2RegisterFinish,
    v2RenameCredential,
    v2Session,
    v2SetAllowedIPs,
    v2SetSigningKeyPublished,
    v2UpdateDisplayName,
    v2UpdateWrappedKey,
} from '$lib/v2-api'
import type {
    Argon2idCost,
    DerivedSigningKey,
    V2AuthSessionInfo,
    V2CredentialItem,
    V2PendingRequestItem,
    V2PublishedSigningKey,
    V2SessionResponse,
} from '$lib/v2-types'
import { webauthnLoginWithPrf, webauthnRegister } from '$lib/webauthn'

type UIState = 'boot' | 'signin' | 'signup' | 'password-login' | 'password-setup' | 'ready'

const missingPrfError = 'Authenticator did not return PRF output'
const signupMissingPrfError =
    'This passkey does not support the PRF extension Revaulter needs to protect your local keys. Sign up with a PRF-capable passkey or use a browser and authenticator that support WebAuthn PRF.'

let uiState = $state<UIState>('boot')
let authBusy = $state(false)
let authError = $state<string | null>(null)
let pageError = $state<string | null>(null)
let signupDisabled = $state(false)

let displayName = $state('')
let passwordInput = $state('')
let loginWrappedPrimaryKey = $state<string | null>(null)
// The credential ID (base64url) of the currently signed-in passkey
let sessionCredentialId = $state<string | null>(null)
let sessionCredentialWrappedKeyEpoch = $state<number>(1)
let loginWrappedKeyStale = $state(false)
// The plaintext password is kept in memory while the session is active adding passkeys and the changing password can wrap new keys without re-prompting
let sessionPassword = $state<string | null>(null)
let allowedIpsText = $state('')
let settingsBusy = $state(false)
let settingsError = $state<string | null>(null)
let settingsSuccess = $state<string | null>(null)
let credentials = $state<V2CredentialItem[]>([])
let signingKeys = $state<V2PublishedSigningKey[]>([])
let hasPassword = $state(false)

let session = $state<V2SessionResponse | null>(null)
let prfSecret = $state<Uint8Array | null>(null)
let primaryKey = $state<Uint8Array | null>(null)
// Unwrapped hybrid anchor keypair for the current session
// Used to sign attestations when adding new credentials
let sessionAnchor = $state<AnchorKeyPair | null>(null)
// Wrapped anchor blob returned by the login finish response; unwrapped once we have the wrapping key
let loginWrappedAnchorKey = $state<string | null>(null)
// Public key (SPKI, base64url) of a freshly-registered credential. Held briefly until the matching finalize step consumes it
let pendingCredentialPublicKeyHash = $state<string | null>(null)

let items = $state<Record<string, V2PendingRequestItem>>({})
let listConnected = $state(false)
let stopStream: (() => Promise<void>) | null = null
let awaitingReadySessionRefresh = $state(false)

onMount(() => {
    void initialize()
    return () => {
        teardownListStream()
    }
})

async function initialize() {
    authError = null
    pageError = null

    try {
        await v2Session()

        // While sessions could survive page reloads, but the PRF secret is intentionally kept in memory only
        // We remove the session state too
        clearLocalAuthState()
        authError = 'Session exists but local key material is missing. Sign in again to continue.'
        uiState = 'signin'
    } catch (err) {
        if (err instanceof ResponseNotOkError) {
            if (err.statusCode === 401) {
                uiState = 'signin'
                return
            }
        }

        pageError = err instanceof Error ? err.message : String(err)
        uiState = 'signin'
    }
}

function toSessionResponse(authSession: V2AuthSessionInfo): V2SessionResponse {
    return {
        authenticated: true,
        userId: authSession.userId,
        displayName: authSession.displayName,
        requestKey: authSession.requestKey,
        anchorFingerprint: authSession.anchorFingerprint,
        wrappedKeyEpoch: authSession.wrappedKeyEpoch,
        allowedIps: authSession.allowedIps,
        ttl: authSession.ttl,
    }
}

function setPrfSecret(v: Uint8Array) {
    prfSecret = v
}

async function teardownListStream() {
    const stop = stopStream
    if (stop) {
        await stop()
    }
    stopStream = null
    listConnected = false
}

function clearLocalAuthState() {
    void teardownListStream()
    session = null
    prfSecret = null
    primaryKey = null
    sessionAnchor = null
    loginWrappedAnchorKey = null
    pendingCredentialPublicKeyHash = null
    loginWrappedPrimaryKey = null
    sessionCredentialId = null
    sessionCredentialWrappedKeyEpoch = 1
    loginWrappedKeyStale = false
    sessionPassword = null
    allowedIpsText = ''
    settingsError = null
    settingsSuccess = null
    signingKeys = []
}

function enterReadyView() {
    uiState = 'ready'
    passwordInput = ''
    authError = null
    settingsError = null
    settingsSuccess = null
    allowedIpsText = session?.allowedIps.join('\n') ?? ''
    startListStream()
    void doLoadCredentials()
    void doLoadSigningKeys()
}

function openSignIn() {
    authError = null
    passwordInput = ''
    loginWrappedPrimaryKey = null
    uiState = 'signin'
}

function openSignup() {
    authError = null
    passwordInput = ''
    loginWrappedPrimaryKey = null
    uiState = 'signup'
}

async function returnToSignIn() {
    if (session) {
        await doLogout()
        return
    }
    openSignIn()
}

function sessionLabel() {
    if (!session) {
        return ''
    }
    return session.displayName.trim() || session.userId
}

async function beginPasskeyLoginStep(): Promise<'authenticated' | 'password-required'> {
    primaryKey = null
    sessionAnchor = null
    sessionPassword = null
    loginWrappedPrimaryKey = null
    loginWrappedAnchorKey = null
    loginWrappedKeyStale = false

    const begin = await v2LoginBegin()
    const assertion = await webauthnLoginWithPrf({
        challenge: begin.challenge,
        prfSalt: base64UrlToBytes(begin.basePrfSalt),
        options: begin.options,
    })
    const finish = await v2LoginFinish({
        challengeId: begin.challengeId,
        credential: (assertion.raw as { credential?: unknown })?.credential ?? {
            id: assertion.id,
            signCount: assertion.signCount,
        },
    })

    if (!finish.authenticated || !finish.session) {
        throw new Error('Login did not complete')
    }
    if (!assertion.prfSecret || assertion.prfSecret.length === 0) {
        throw new Error(missingPrfError)
    }

    session = toSessionResponse(finish.session)
    setPrfSecret(assertion.prfSecret)
    sessionCredentialId = assertion.id
    sessionCredentialWrappedKeyEpoch = finish.credentialWrappedKeyEpoch ?? finish.session.wrappedKeyEpoch
    loginWrappedPrimaryKey = finish.wrappedPrimaryKey ?? null
    loginWrappedAnchorKey = finish.wrappedAnchorKey ?? null
    loginWrappedKeyStale = finish.wrappedKeyStale

    if (finish.wrappedPrimaryKey) {
        // Parse the envelope to determine whether a password is needed
        const envelope = parseWrappedPrimaryKeyEnvelope(finish.wrappedPrimaryKey)
        hasPassword = envelope.passwordRequired
        if (envelope.passwordRequired) {
            return 'password-required'
        }

        // No password required — unwrap immediately with PRF only
        const { wrappingKeyBytes } = await deriveWrappingKey({
            prfSecret: assertion.prfSecret,
            userId: finish.session.userId,
        })
        primaryKey = await unwrapPrimaryKey({
            wrapped: finish.wrappedPrimaryKey,
            wrappingKeyBytes,
            userId: finish.session.userId,
        })

        // Also unwrap the hybrid anchor so subsequent credential-add flows can sign attestations
        if (loginWrappedAnchorKey) {
            sessionAnchor = await unwrapAnchorKey({
                wrapped: loginWrappedAnchorKey,
                wrappingKeyBytes,
                userId: finish.session.userId,
            })
        }
        loginWrappedPrimaryKey = null
        loginWrappedAnchorKey = null
    } else {
        hasPassword = false
    }

    return 'authenticated'
}

async function unlockWithPassword(password: string) {
    const wrappedPrimaryKey = loginWrappedPrimaryKey
    const wrappedAnchorKey = loginWrappedAnchorKey

    if (!wrappedPrimaryKey) {
        throw new Error('Password unlock is not active')
    }
    if (!prfSecret || !session) {
        throw new Error('Missing local key material')
    }

    // Note: we are not trimming or otherwise normalizing the password as we must accept it as-is to ensure consistent key derivation
    if (password === '') {
        throw new Error('Password is required')
    }

    // Parse Argon2id params from the wrapped-key envelope
    const envelope = parseWrappedPrimaryKeyEnvelope(wrappedPrimaryKey)
    if (!envelope.argon2id) {
        throw new Error('Wrapped key envelope is missing Argon2id parameters')
    }

    const argon2idSalt = base64UrlToBytes(envelope.argon2id.salt)
    const envelopeArgon2idCost: Argon2idCost = {
        m: envelope.argon2id.m,
        t: envelope.argon2id.t,
        p: envelope.argon2id.p,
    }

    // Derive the wrapping key using Argon2id-stretched password as HKDF salt
    const { wrappingKeyBytes } = await deriveWrappingKey({
        prfSecret,
        userId: session.userId,
        password,
        argon2idSalt,
        argon2idCost: envelopeArgon2idCost,
    })

    // Unwrap — success proves the password is correct (replaces canary)
    primaryKey = await unwrapPrimaryKey({
        wrapped: wrappedPrimaryKey,
        wrappingKeyBytes,
        userId: session.userId,
    })

    // Unwrap the hybrid anchor secret too. Without it the session cannot add new credentials.
    if (wrappedAnchorKey) {
        sessionAnchor = await unwrapAnchorKey({
            wrapped: wrappedAnchorKey,
            wrappingKeyBytes,
            userId: session.userId,
        })
    }

    loginWrappedKeyStale = false

    loginWrappedPrimaryKey = null
    loginWrappedAnchorKey = null

    // Keep the password in memory for the rest of the session so we can re-wrap the primary key when adding new passkeys or changing credentials without re-prompting
    sessionPassword = password
}

async function doLogin() {
    authBusy = true
    authError = null
    pageError = null

    try {
        const outcome = await beginPasskeyLoginStep()
        if (outcome === 'password-required') {
            passwordInput = ''
            uiState = 'password-login'
            return
        }

        enterReadyView()
    } catch (err) {
        clearLocalAuthState()
        authError = err instanceof Error ? err.message : String(err)
        uiState = 'signin'
    } finally {
        authBusy = false
    }
}

async function doRegister() {
    authBusy = true
    authError = null
    pageError = null

    try {
        const begin = await v2RegisterBegin(displayName)
        const cred = await webauthnRegister({
            options: begin.options,
        })

        // Stash the credential public key hash so we can sign it into the attestation after password setup
        pendingCredentialPublicKeyHash = cred.publicKeyHash
        await v2RegisterFinish({
            challengeId: begin.challengeId,
            credential: (cred.raw as { credential?: unknown })?.credential ?? cred,
        })

        const outcome = await beginPasskeyLoginStep()
        if (outcome === 'password-required') {
            passwordInput = ''
            uiState = 'password-login'
            return
        }

        passwordInput = ''
        uiState = 'password-setup'
    } catch (err) {
        clearLocalAuthState()
        if (err instanceof ResponseNotOkError && err.statusCode === 403) {
            signupDisabled = true
            authError = err.message || 'Account creation is disabled on this server.'
            uiState = 'signin'
        } else {
            authError =
                err instanceof Error && err.message === missingPrfError
                    ? signupMissingPrfError
                    : err instanceof Error
                      ? err.message
                      : String(err)
        }
    } finally {
        authBusy = false
    }
}

async function doFinishPasswordLogin() {
    authBusy = true
    authError = null
    awaitingReadySessionRefresh = true

    try {
        await unlockWithPassword(passwordInput)
        enterReadyView()
    } catch (err) {
        authError = err instanceof Error ? err.message : 'Incorrect password'
    } finally {
        awaitingReadySessionRefresh = false
        authBusy = false
    }
}

async function doSkipPassword() {
    passwordInput = ''
    await doSetPassword()
}

async function doSetPassword() {
    // This method can be invoked with an empty password too
    if (!prfSecret || !session) {
        clearLocalAuthState()
        authError = 'Missing local key material. Sign in again to continue.'
        uiState = 'signin'
        return
    }
    if (!sessionCredentialId || !pendingCredentialPublicKeyHash) {
        clearLocalAuthState()
        authError = 'Missing credential identity for signup. Sign in again to continue.'
        uiState = 'signin'
        return
    }

    authBusy = true
    authError = null

    try {
        // Generate a random primary key and a fresh hybrid anchor (the user's long-lived identity root)
        const pk = await generatePrimaryKey()
        const anchor = await generateAnchorKeyPair()

        // Derive wrapping key (with optional Argon2id if password is set)
        const {
            wrappingKeyBytes,
            argon2idSalt,
            argon2idCost: usedCost,
        } = await deriveWrappingKey({
            prfSecret,
            userId: session.userId,
            password: passwordInput || undefined,
            argon2idCost: passwordInput ? argon2idCost : undefined,
        })

        // Wrap the primary key
        const wrapped = await wrapPrimaryKey({
            primaryKey: pk,
            wrappingKeyBytes,
            userId: session.userId,
            passwordRequired: !!passwordInput,
            argon2idSalt,
            argon2idCost: usedCost,
        })

        // Wrap the anchor secret blob using the same wrapping key
        const anchorSecret = await serializeAnchorSecret(anchor)
        const wrappedAnchor = await wrapAnchorKey({
            anchorSecret,
            wrappingKeyBytes,
            userId: session.userId,
        })

        // Derive request encryption keys from the primary key
        const { publicKeyJwk } = await deriveRequestEncKeyPair({
            userId: session.userId,
            primaryKey: pk,
        })
        const { encapsulationKeyB64 } = await deriveRequestEncMlkemKeyPair({
            userId: session.userId,
            primaryKey: pk,
        })

        // Canonical wire strings for the anchor pubkeys — signed by the anchor and also stored on the user row.
        const anchorEs384Str = anchorEs384JwkToString(anchor.es384.publicKeyJwk)
        const anchorMldsa87Str = anchorMldsa87PubToString(anchor.mldsa87.publicKey)

        // Sign the pubkey bundle. The CLI pins the anchor and verifies these signatures on every request.
        const bundleSig = await signPubkeyBundleHybrid(anchor, {
            userId: session.userId,
            requestEncEcdhPubkey: JSON.stringify(publicKeyJwk),
            requestEncMlkemPubkey: encapsulationKeyB64,
            anchorEs384Crv: anchor.es384.publicKeyJwk.crv,
            anchorEs384Kty: anchor.es384.publicKeyJwk.kty,
            anchorEs384X: anchor.es384.publicKeyJwk.x,
            anchorEs384Y: anchor.es384.publicKeyJwk.y,
            anchorMldsa87PublicKey: anchorMldsa87Str,
            wrappedKeyEpoch: 1,
        })

        // Sign the first-credential attestation with the fresh anchor.
        const attestSig = await signCredentialAttestationHybrid(anchor, {
            userId: session.userId,
            credentialId: sessionCredentialId,
            credentialPublicKeyHash: pendingCredentialPublicKeyHash,
            wrappedKeyEpoch: 1,
            createdAt: Math.floor(Date.now() / 1000),
        })

        const finalize = await v2FinalizeSignup({
            requestEncEcdhPubkey: publicKeyJwk,
            requestEncMlkemPubkey: encapsulationKeyB64,
            wrappedPrimaryKey: wrapped,
            anchorEs384PublicKey: anchorEs384Str,
            anchorMldsa87PublicKey: anchorMldsa87Str,
            pubkeyBundleSignatureEs384: bundleSig.sigEs384,
            pubkeyBundleSignatureMldsa87: bundleSig.sigMldsa87,
            wrappedAnchorKey: wrappedAnchor,
            attestationPayload: attestSig.canonicalBody,
            attestationSignatureEs384: attestSig.sigEs384,
            attestationSignatureMldsa87: attestSig.sigMldsa87,
        })
        if (finalize.session) {
            session = toSessionResponse(finalize.session)
        }
        session = await v2Session()
        primaryKey = pk
        sessionAnchor = anchor
        hasPassword = !!passwordInput
        pendingCredentialPublicKeyHash = null

        // Remember the password used during signup so subsequent add-passkey operations can wrap the new credential with the same password
        sessionPassword = passwordInput || null
        loginWrappedPrimaryKey = null
        loginWrappedAnchorKey = null
        enterReadyView()
    } catch (err) {
        authError = err instanceof Error ? err.message : String(err)
    } finally {
        awaitingReadySessionRefresh = false
        authBusy = false
    }
}

async function doLogout() {
    void teardownListStream()
    try {
        await v2Logout()
    } catch {
        // Ignore logout failures and still clear the local session state.
    }

    clearLocalAuthState()
    items = {}
    passwordInput = ''
    authError = null
    uiState = 'signin'
}

const parseAllowedIpsInput = (raw: string) =>
    raw
        .split(/[\n,]/)
        .map((entry) => entry.trim())
        .filter((entry) => entry !== '')

async function doUpdateAllowedIps() {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2SetAllowedIPs(parseAllowedIpsInput(allowedIpsText))
        if (session) {
            session = { ...session, allowedIps: res.allowedIps }
        }
        allowedIpsText = res.allowedIps.join('\n')
        settingsSuccess = res.allowedIps.length === 0 ? 'Allowed IP restrictions removed' : 'Allowed IPs updated'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doRegenerateRequestKey() {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2RegenerateRequestKey()
        if (session) {
            session = { ...session, requestKey: res.requestKey }
        }
        settingsSuccess = 'Request key regenerated.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doLoadCredentials() {
    try {
        credentials = (await v2ListCredentials()) ?? []
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    }
}

async function doLoadSigningKeys() {
    try {
        signingKeys = (await v2ListSigningKeys()) ?? []
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    }
}

async function doDeriveSigningKey(keyLabel: string, algorithm: string): Promise<DerivedSigningKey> {
    if (!session || !primaryKey) {
        throw new Error('Missing local key material')
    }

    const { publicJwk } = await deriveSigningKeyPair({
        userId: session.userId,
        keyLabel,
        algorithm,
        primaryKey,
    })
    const [id, pem] = await Promise.all([computeEcP256Thumbprint(publicJwk), ecP256JwkToPem(publicJwk)])

    // Attempt to register the derived key as unpublished; if a row already exists for this (algorithm, keyLabel) the server returns 409 and we treat that as a no-op since the caller just needs the derived material returned
    try {
        await v2CreateSigningKey({
            algorithm,
            keyLabel,
            jwk: publicJwk,
            pem,
            published: false,
        })
    } catch (err) {
        if (!(err instanceof ResponseNotOkError) || err.statusCode !== 409) {
            throw err
        }
    }
    await doLoadSigningKeys()

    return { keyLabel, algorithm, jwk: publicJwk, pem, id }
}

async function doPublishSigningKey(derived: DerivedSigningKey) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        if (!sessionAnchor || !session) {
            throw new Error('Anchor key is not available — please sign in again to publish a signing key.')
        }

        // The publication proof binds the canonical body the server stores to the anchor pinned at registration
        // We always sign at publish time (and on re-publish if the row has no stored proof), so the server can verify the binding without trusting the browser
        const known = signingKeys.find((k) => k.id === derived.id)
        const needsFreshProof = !known || !known.hasProof

        let proof:
            | { publicationPayload: string; publicationSignatureEs384: string; publicationSignatureMldsa87: string }
            | undefined
        if (needsFreshProof) {
            const signed = await signSigningKeyPublicationHybrid(sessionAnchor, {
                userId: session.userId,
                algorithm: derived.algorithm,
                keyLabel: derived.keyLabel,
                keyId: derived.id,
                wrappedKeyEpoch: session.wrappedKeyEpoch,
                createdAt: Math.floor(Date.now() / 1000),
                v: SIGNING_KEY_PUBLICATION_VERSION,
            })
            proof = {
                publicationPayload: signed.canonicalBody,
                publicationSignatureEs384: signed.sigEs384,
                publicationSignatureMldsa87: signed.sigMldsa87,
            }
        }

        if (known) {
            // Existing row: send proof only when it is missing one — otherwise the toggle is a flag flip
            await v2SetSigningKeyPublished(derived.id, true, proof)
        } else {
            await v2CreateSigningKey({
                algorithm: derived.algorithm,
                keyLabel: derived.keyLabel,
                jwk: derived.jwk,
                pem: derived.pem,
                published: true,
                proof,
            })
        }
        await doLoadSigningKeys()
        settingsSuccess = `Signing key "${derived.keyLabel}" published.`
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doUnpublishSigningKey(id: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2SetSigningKeyPublished(id, false)
        await doLoadSigningKeys()
        settingsSuccess = 'Signing key unpublished.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doDeleteSigningKey(id: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2DeleteSigningKey(id)
        await doLoadSigningKeys()
        settingsSuccess = 'Signing key deleted.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doUpdateDisplayName(name: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const res = await v2UpdateDisplayName(name)
        if (session) {
            session = { ...session, displayName: res.displayName }
        }
        settingsSuccess = 'Display name updated.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doAddPasskey(name: string) {
    if (!session || !primaryKey) {
        settingsError = 'Missing local key material'
        return
    }
    if (!sessionAnchor) {
        settingsError = 'Missing anchor secret; sign in again and retry.'
        return
    }

    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const begin = await v2AddCredentialBegin(name)
        const cred = await webauthnRegister({
            options: begin.options,
        })

        // The new credential has its own unique PRF secret, so we must perform a PRF assertion with the newly created credential to derive its wrapping key
        // Use a client-generated random challenge since this ceremony is only used to evaluate PRF locally and is not sent back to the server
        const prfChallenge = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)))
        const prfAssertion = await webauthnLoginWithPrf({
            challenge: prfChallenge,
            prfSalt: base64UrlToBytes(begin.basePrfSalt),
            options: {
                publicKey: {
                    allowCredentials: [{ type: 'public-key', id: cred.id }],
                    userVerification: 'preferred',
                },
            },
        })
        if (!prfAssertion.prfSecret || prfAssertion.prfSecret.length === 0) {
            throw new Error('Authenticator did not return PRF output for the new credential')
        }

        // Derive the wrapping key for the new credential, re-using the current session password (if any) so all passkeys added while signed in share the same password gate
        const password = sessionPassword ?? undefined
        const {
            wrappingKeyBytes,
            argon2idSalt,
            argon2idCost: usedCost,
        } = await deriveWrappingKey({
            prfSecret: prfAssertion.prfSecret,
            userId: session.userId,
            password,
            argon2idCost: password ? argon2idCost : undefined,
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey,
            wrappingKeyBytes,
            userId: session.userId,
            passwordRequired: !!password,
            argon2idSalt,
            argon2idCost: usedCost,
        })

        // Wrap a copy of the anchor secret with the new credential's wrapping key so the user can sign in with it later.
        const anchorSecret = await serializeAnchorSecret(sessionAnchor)
        const wrappedAnchor = await wrapAnchorKey({
            anchorSecret,
            wrappingKeyBytes,
            userId: session.userId,
        })

        // Sign an attestation binding this credential to the user's existing anchor.
        const attestSig = await signCredentialAttestationHybrid(sessionAnchor, {
            userId: session.userId,
            credentialId: cred.id,
            credentialPublicKeyHash: cred.publicKeyHash,
            wrappedKeyEpoch: session.wrappedKeyEpoch,
            createdAt: Math.floor(Date.now() / 1000),
        })

        await v2AddCredentialFinish({
            challengeId: begin.challengeId,
            credential: (cred.raw as { credential?: unknown })?.credential ?? cred,
            credentialName: name,
            wrappedPrimaryKey: wrapped,
            wrappedAnchorKey: wrappedAnchor,
            attestationPayload: attestSig.canonicalBody,
            attestationSignatureEs384: attestSig.sigEs384,
            attestationSignatureMldsa87: attestSig.sigMldsa87,
        })
        await doLoadCredentials()
        settingsSuccess = 'Passkey added.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doRenamePasskey(id: string, name: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2RenameCredential(id, name)
        await doLoadCredentials()
        settingsSuccess = 'Passkey renamed.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doDeletePasskey(id: string) {
    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        await v2DeleteCredential(id)
        await doLoadCredentials()
        settingsSuccess = 'Passkey deleted.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doChangePassword(password: string) {
    if (!prfSecret || !session || !primaryKey || !sessionCredentialId || !sessionAnchor) {
        settingsError = 'Missing local key material'
        return
    }

    settingsBusy = true
    settingsError = null
    settingsSuccess = null
    try {
        const {
            wrappingKeyBytes,
            argon2idSalt,
            argon2idCost: usedCost,
        } = await deriveWrappingKey({
            prfSecret,
            userId: session.userId,
            password: password || undefined,
            argon2idCost: password ? argon2idCost : undefined,
        })

        const wrapped = await wrapPrimaryKey({
            primaryKey,
            wrappingKeyBytes,
            userId: session.userId,
            passwordRequired: !!password,
            argon2idSalt,
            argon2idCost: usedCost,
        })

        // The wrapped primary key lives on the specific credential that signed us in, not on the user record
        const anchorSecret = await serializeAnchorSecret(sessionAnchor)
        const wrappedAnchor = await wrapAnchorKey({
            anchorSecret,
            wrappingKeyBytes,
            userId: session.userId,
        })

        await v2UpdateWrappedKey(sessionCredentialId, wrapped, wrappedAnchor, true)
        await doLoadCredentials()
        hasPassword = !!password

        // Keep the new password in memory so subsequent add-passkey calls wrap with it (or clear it when removed)
        sessionPassword = password || null
        settingsSuccess = password
            ? 'Password updated for this passkey. Other passkeys will ask to refresh on next use.'
            : 'Password removed for this passkey. Other passkeys will refresh on next use.'
    } catch (err) {
        settingsError = err instanceof Error ? err.message : String(err)
    } finally {
        settingsBusy = false
    }
}

async function doRemovePassword() {
    await doChangePassword('')
}

function startListStream() {
    if (stopStream) {
        return
    }

    let stopped = false
    const streamController = new AbortController()
    const stream = v2ListStream({ signal: streamController.signal })
    stopStream = async () => {
        stopped = true
        stopStream = null
        listConnected = false
        streamController.abort()
        await stream.return(undefined)
    }

    void (async () => {
        listConnected = false
        try {
            for await (const item of stream) {
                if (stopped) {
                    return
                }
                listConnected = true
                if (!item) {
                    continue
                }
                if (item.status === 'removed') {
                    delete items[item.state]
                    items = { ...items }
                    continue
                }
                items = {
                    ...items,
                    [item.state]: item,
                }
            }
        } catch (err) {
            if (stopped) {
                return
            }

            if (err instanceof ResponseNotOkError && err.statusCode === 401) {
                clearLocalAuthState()
                items = {}
                authError = 'Session expired. Sign in again.'
                uiState = 'signin'
                return
            }
            if (err instanceof ResponseNotOkError && err.statusCode === 403 && awaitingReadySessionRefresh) {
                return
            }
            pageError = err instanceof Error ? err.message : String(err)
        } finally {
            if (!stopped) {
                stopStream = null
                listConnected = false
                if (uiState === 'ready') {
                    setTimeout(() => {
                        if (uiState === 'ready' && !stopStream) {
                            startListStream()
                        }
                    }, 500)
                }
            }
        }
    })()
}

function removeItem(state: string) {
    delete items[state]
    items = { ...items }
}

function sortedItems() {
    return Object.values(items).sort((a, b) => a.date - b.date)
}
</script>

<div class="min-h-screen">
    {#if uiState === 'ready'}
        <ReadyView
            allowedIpsText={allowedIpsText}
            {credentials}
            displayName={session?.displayName ?? ''}
            {hasPassword}
            listConnected={listConnected}
            onAddPasskey={doAddPasskey}
            onAllowedIpsTextInput={(value) => {
                allowedIpsText = value
            }}
            onChangePassword={doChangePassword}
            onDeletePasskey={doDeletePasskey}
            onDeleteSigningKey={doDeleteSigningKey}
            onDeriveSigningKey={doDeriveSigningKey}
            onLogout={doLogout}
            onPublishSigningKey={doPublishSigningKey}
            onRegenerateRequestKey={doRegenerateRequestKey}
            onRemoveItem={removeItem}
            onRemovePassword={doRemovePassword}
            onRenamePasskey={doRenamePasskey}
            onUnpublishSigningKey={doUnpublishSigningKey}
            onUpdateAllowedIps={doUpdateAllowedIps}
            onUpdateDisplayName={doUpdateDisplayName}
            pageError={pageError}
            pendingItems={sortedItems()}
            {primaryKey}
            requestKey={session?.requestKey ?? ''}
            anchorFingerprint={session?.anchorFingerprint ?? ''}
            sessionLabel={sessionLabel()}
            settingsBusy={settingsBusy}
            settingsError={settingsError}
            settingsSuccess={settingsSuccess}
            {signingKeys}
            userId={session?.userId ?? ''}
        />
    {:else if uiState === 'signup' || uiState === 'password-setup'}
        <AuthSetupView
            authBusy={authBusy}
            authError={authError}
            displayName={displayName}
            onDisplayNameInput={(value) => {
                displayName = value
            }}
            onPasswordInput={(value) => {
                passwordInput = value
            }}
            onRegister={doRegister}
            onReturnToSignIn={returnToSignIn}
            onSetPassword={doSetPassword}
            onSkipPassword={doSkipPassword}
            pageError={pageError}
            passwordInput={passwordInput}
            uiState={uiState}
        />
    {:else}
        <AuthAccessView
            authBusy={authBusy}
            authError={authError}
            loginWrappedPrimaryKey={loginWrappedPrimaryKey}
            onFinishPasswordLogin={doFinishPasswordLogin}
            onLogin={doLogin}
            onOpenSignup={openSignup}
            onPasswordInput={(value) => {
                passwordInput = value
            }}
            onReturnToSignIn={returnToSignIn}
            pageError={pageError}
            passwordInput={passwordInput}
            sessionLabel={sessionLabel()}
            signupDisabled={signupDisabled}
            uiState={uiState}
        />
    {/if}
</div>
