// Minimal CBOR helpers for extracting the WebAuthn credential public key from an attestationObject
// This file intentionally implements only what WebAuthn attestation objects contain in practice: definite-length maps, byte strings, text strings, and integers (majors 0/1/2/3/4/5/6/7)
// A general-purpose CBOR decoder is not needed — we only need to find `authData` inside the outer map and then slice out the one COSE map that is the credential public key

// Reads an unsigned CBOR argument starting at `o` given the additional-info nibble `info`
// Returns the argument value and how many trailing bytes were consumed after the initial byte
function readCborUint(buf: Uint8Array, o: number, info: number): { value: number; size: number } {
    if (info < 24) {
        return { value: info, size: 0 }
    }
    if (info === 24) {
        if (o + 1 > buf.length) {
            throw new Error('CBOR argument truncated')
        }
        return { value: buf[o], size: 1 }
    }
    if (info === 25) {
        if (o + 2 > buf.length) {
            throw new Error('CBOR argument truncated')
        }
        return { value: (buf[o] << 8) | buf[o + 1], size: 2 }
    }
    if (info === 26) {
        if (o + 4 > buf.length) {
            throw new Error('CBOR argument truncated')
        }
        const v = buf[o] * 0x1000000 + (((buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3]) >>> 0)
        return { value: v, size: 4 }
    }
    if (info === 27) {
        if (o + 8 > buf.length) {
            throw new Error('CBOR argument truncated')
        }
        const high = buf[o] * 0x1000000 + (((buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3]) >>> 0)
        const low = buf[o + 4] * 0x1000000 + (((buf[o + 5] << 16) | (buf[o + 6] << 8) | buf[o + 7]) >>> 0)
        if (high > 0x1fffff) {
            throw new Error('CBOR uint exceeds JavaScript safe integer range')
        }
        return { value: high * 0x100000000 + low, size: 8 }
    }
    throw new Error(`unsupported CBOR argument info ${info}`)
}

// Returns the total byte length of the CBOR item starting at `o`
// Only supports definite-length items; indefinite-length encodings are rejected, matching the constraints of deterministic COSE / CTAP encoding
function cborItemLength(buf: Uint8Array, o: number): number {
    if (o >= buf.length) {
        throw new Error('CBOR item starts past end of buffer')
    }
    const start = o
    const initial = buf[o++]
    const majorType = initial >> 5
    const info = initial & 0x1f
    if (info === 31) {
        throw new Error('indefinite-length CBOR items are not supported')
    }
    const { value: arg, size: argSize } = readCborUint(buf, o, info)
    o += argSize

    switch (majorType) {
        case 0:
        case 1:
            return o - start
        case 2:
        case 3:
            if (o + arg > buf.length) {
                throw new Error('CBOR byte/text string runs past end of buffer')
            }
            return o - start + arg
        case 4: {
            let end = o
            for (let i = 0; i < arg; i++) {
                end += cborItemLength(buf, end)
            }
            return end - start
        }
        case 5: {
            let end = o
            for (let i = 0; i < arg; i++) {
                end += cborItemLength(buf, end)
                end += cborItemLength(buf, end)
            }
            return end - start
        }
        case 6:
            return o - start + cborItemLength(buf, o)
        case 7:
            return o - start
    }
    throw new Error(`unsupported CBOR major type ${majorType}`)
}

// Extracts the authData byte string from a WebAuthn attestationObject (a CBOR map containing `fmt`, `attStmt`, `authData`)
// The outer encoding is CTAP's canonical form so keys are text strings; key order is authenticator-defined so this walks the map rather than relying on a fixed index
function extractAuthData(attestationObject: Uint8Array): Uint8Array {
    let o = 0
    if (o >= attestationObject.length) {
        throw new Error('attestationObject is empty')
    }
    const initial = attestationObject[o++]
    if (initial >> 5 !== 5) {
        throw new Error('attestationObject is not a CBOR map')
    }
    const info = initial & 0x1f
    if (info === 31) {
        throw new Error('indefinite-length attestationObject map is not supported')
    }
    const { value: entryCount, size: argSize } = readCborUint(attestationObject, o, info)
    o += argSize

    const decoder = new TextDecoder()
    for (let i = 0; i < entryCount; i++) {
        if (o >= attestationObject.length) {
            throw new Error('attestationObject map key runs past end of buffer')
        }
        const keyInitial = attestationObject[o++]
        if (keyInitial >> 5 !== 3) {
            throw new Error('attestationObject map key is not a text string')
        }
        const keyInfo = keyInitial & 0x1f
        const { value: keyLen, size: keyArgSize } = readCborUint(attestationObject, o, keyInfo)
        o += keyArgSize
        const keyEnd = o + keyLen
        if (keyEnd > attestationObject.length) {
            throw new Error('attestationObject map key runs past end of buffer')
        }
        const key = decoder.decode(attestationObject.subarray(o, keyEnd))
        o = keyEnd

        if (key === 'authData') {
            if (o >= attestationObject.length) {
                throw new Error('attestationObject map value runs past end of buffer')
            }
            const valInitial = attestationObject[o++]
            if (valInitial >> 5 !== 2) {
                throw new Error('authData is not a byte string')
            }
            const valInfo = valInitial & 0x1f
            const { value: valLen, size: valArgSize } = readCborUint(attestationObject, o, valInfo)
            o += valArgSize
            const valEnd = o + valLen
            if (valEnd > attestationObject.length) {
                throw new Error('authData byte string runs past end of attestationObject')
            }
            return attestationObject.subarray(o, valEnd)
        }

        const skip = cborItemLength(attestationObject, o)
        if (o + skip > attestationObject.length) {
            throw new Error('attestationObject map value runs past end of buffer')
        }
        o += skip
    }
    throw new Error('attestationObject is missing authData')
}

const AUTH_DATA_MIN_LEN = 37
const AT_FLAG = 0x40
const AAGUID_LEN = 16

// Extracts the raw COSE-encoded credential public-key bytes from a WebAuthn attestation response
// The returned slice is the exact CBOR item the authenticator wrote, suitable for hashing for a stable cross-language credential identifier regardless of key algorithm
export function extractCredentialPublicKeyCose(attestationObject: ArrayBuffer): Uint8Array {
    const bytes = new Uint8Array(attestationObject)
    const authData = extractAuthData(bytes)

    if (authData.length < AUTH_DATA_MIN_LEN) {
        throw new Error('authData is shorter than the fixed WebAuthn header')
    }
    const flags = authData[32]
    if ((flags & AT_FLAG) === 0) {
        throw new Error('authData missing AT flag; no attested credential data present')
    }

    // Layout after the 37-byte header when AT=1: aaguid(16) | credentialIdLength(2 big-endian) | credentialId(N) | credentialPublicKey (CBOR) | optional extensions (CBOR)
    const acdOffset = AUTH_DATA_MIN_LEN
    if (authData.length < acdOffset + AAGUID_LEN + 2) {
        throw new Error('attested credential data header truncated')
    }
    const credIdLen = (authData[acdOffset + AAGUID_LEN] << 8) | authData[acdOffset + AAGUID_LEN + 1]
    const coseOffset = acdOffset + AAGUID_LEN + 2 + credIdLen
    if (authData.length <= coseOffset) {
        throw new Error('attested credential data truncated before public key')
    }

    const coseLen = cborItemLength(authData, coseOffset)
    if (coseOffset + coseLen > authData.length) {
        throw new Error('credential public key runs past end of authData')
    }
    return authData.slice(coseOffset, coseOffset + coseLen)
}
