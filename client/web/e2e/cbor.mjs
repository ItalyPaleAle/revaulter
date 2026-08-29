// Minimal CBOR encoder for the WebAuthn structures the software authenticator produces
// Only definite-length maps, byte strings, text strings and integers are needed, which is exactly what COSE keys and attestation objects contain

// Encodes the initial byte plus argument for a CBOR item
function encodeHead(majorType, argument) {
    if (argument < 0) {
        throw new Error('CBOR argument must not be negative')
    }
    if (argument < 24) {
        return Buffer.from([(majorType << 5) | argument])
    }
    if (argument < 0x100) {
        return Buffer.from([(majorType << 5) | 24, argument])
    }
    if (argument < 0x10000) {
        return Buffer.from([(majorType << 5) | 25, argument >> 8, argument & 0xff])
    }
    if (argument < 0x100000000) {
        const buf = Buffer.alloc(5)
        buf[0] = (majorType << 5) | 26
        buf.writeUInt32BE(argument, 1)
        return buf
    }
    throw new Error('CBOR argument is too large for the test encoder')
}

// Encodes a CBOR integer, choosing the unsigned or negative major type from the sign
export function cborInt(value) {
    if (!Number.isInteger(value)) {
        throw new Error('CBOR integer must be an integer')
    }
    if (value >= 0) {
        return encodeHead(0, value)
    }
    return encodeHead(1, -1 - value)
}

export function cborBytes(value) {
    const buf = Buffer.from(value)
    return Buffer.concat([encodeHead(2, buf.length), buf])
}

export function cborText(value) {
    const buf = Buffer.from(value, 'utf8')
    return Buffer.concat([encodeHead(3, buf.length), buf])
}

// Encodes a map from an array of already-encoded [key, value] pairs
// The caller controls the order because COSE keys and attestation objects are written in a canonical order
export function cborMap(entries) {
    return Buffer.concat([encodeHead(5, entries.length), ...entries.map(([key, value]) => Buffer.concat([key, value]))])
}
