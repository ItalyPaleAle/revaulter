import { constants, generateKeyPairSync, sign } from 'node:crypto'

import { cborBytes, cborInt, cborMap } from './cbor.mjs'

// COSE key types
// Specification: https://www.iana.org/assignments/cose/cose.xhtml#key-type
const KEY_TYPE_OKP = 1
const KEY_TYPE_EC2 = 2
const KEY_TYPE_RSA = 3
// AKP carries its key material as an opaque byte string and is the key type registered for the ML-DSA parameter sets
const KEY_TYPE_AKP = 7

// COSE elliptic curves
const CURVE_P256 = 1
const CURVE_P384 = 2
const CURVE_ED25519 = 6
const CURVE_SECP256K1 = 8

function jwkBytes(publicKey, field) {
    const jwk = publicKey.export({ format: 'jwk' })
    const value = jwk[field]
    if (typeof value !== 'string') {
        throw new Error(`JWK export is missing the "${field}" field`)
    }
    return Buffer.from(value, 'base64url')
}

// Builds the COSE key for an OKP (Edwards curve) public key
function okpCoseKey(coseAlgorithm, curve, publicKey) {
    return cborMap([
        [cborInt(1), cborInt(KEY_TYPE_OKP)],
        [cborInt(3), cborInt(coseAlgorithm)],
        [cborInt(-1), cborInt(curve)],
        [cborInt(-2), cborBytes(jwkBytes(publicKey, 'x'))],
    ])
}

// Builds the COSE key for an EC2 (NIST curve) public key
function ec2CoseKey(coseAlgorithm, curve, publicKey) {
    return cborMap([
        [cborInt(1), cborInt(KEY_TYPE_EC2)],
        [cborInt(3), cborInt(coseAlgorithm)],
        [cborInt(-1), cborInt(curve)],
        [cborInt(-2), cborBytes(jwkBytes(publicKey, 'x'))],
        [cborInt(-3), cborBytes(jwkBytes(publicKey, 'y'))],
    ])
}

// Builds the COSE key for an RSA public key, whose modulus and exponent are unsigned big-endian integers
function rsaCoseKey(coseAlgorithm, publicKey) {
    return cborMap([
        [cborInt(1), cborInt(KEY_TYPE_RSA)],
        [cborInt(3), cborInt(coseAlgorithm)],
        [cborInt(-1), cborBytes(jwkBytes(publicKey, 'n'))],
        [cborInt(-2), cborBytes(jwkBytes(publicKey, 'e'))],
    ])
}

// Builds the COSE key for an AKP public key, which is the FIPS 204 encoding of the ML-DSA public key
// Specification: §6. COSE Key Type AKP (https://www.rfc-editor.org/rfc/rfc9964#section-6)
function akpCoseKey(coseAlgorithm, publicKey) {
    return cborMap([
        [cborInt(1), cborInt(KEY_TYPE_AKP)],
        [cborInt(3), cborInt(coseAlgorithm)],
        [cborInt(-1), cborBytes(jwkBytes(publicKey, 'pub'))],
    ])
}

function ecdsaAlgorithm(name, label, coseAlgorithm, namedCurve, curve, hash) {
    return {
        name,
        label,
        coseAlgorithm,
        keyType: KEY_TYPE_EC2,
        generateKeyPair() {
            const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve })
            return { privateKey, coseKey: ec2CoseKey(coseAlgorithm, curve, publicKey) }
        },
        // WebAuthn ECDSA signatures are ASN.1 DER encoded, which is node's default encoding
        sign(privateKey, data) {
            return sign(hash, data, privateKey)
        },
    }
}

function rsaAlgorithm(name, label, coseAlgorithm, hash, padding) {
    return {
        name,
        label,
        coseAlgorithm,
        keyType: KEY_TYPE_RSA,
        generateKeyPair() {
            const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
            return { privateKey, coseKey: rsaCoseKey(coseAlgorithm, publicKey) }
        },
        sign(privateKey, data) {
            return sign(hash, data, { key: privateKey, padding, saltLength: constants.RSA_PSS_SALTLEN_DIGEST })
        },
    }
}

function mldsaAlgorithm(name, label, coseAlgorithm, nodeKeyType) {
    return {
        name,
        label,
        coseAlgorithm,
        keyType: KEY_TYPE_AKP,
        nodeKeyType,
        generateKeyPair() {
            const { privateKey, publicKey } = generateKeyPairSync(nodeKeyType)
            return { privateKey, coseKey: akpCoseKey(coseAlgorithm, publicKey) }
        },
        // ML-DSA credentials sign with pure ML-DSA and an empty context, which is what node produces without a digest
        sign(privateKey, data) {
            return sign(null, data, privateKey)
        },
    }
}

// Every passkey algorithm the software authenticator can mint a credential with, keyed by the name tests refer to
export const PASSKEY_ALGORITHMS = {
    es256: ecdsaAlgorithm('es256', 'ES256 (ECDSA P-256)', -7, 'prime256v1', CURVE_P256, 'sha256'),
    es384: ecdsaAlgorithm('es384', 'ES384 (ECDSA P-384)', -35, 'secp384r1', CURVE_P384, 'sha384'),
    ed25519: {
        name: 'ed25519',
        label: 'EdDSA (Ed25519)',
        coseAlgorithm: -8,
        keyType: KEY_TYPE_OKP,
        generateKeyPair() {
            const { privateKey, publicKey } = generateKeyPairSync('ed25519')
            return { privateKey, coseKey: okpCoseKey(-8, CURVE_ED25519, publicKey) }
        },
        // Ed25519 signs the message itself rather than a digest, so node takes a null algorithm
        sign(privateKey, data) {
            return sign(null, data, privateKey)
        },
    },
    // ES256K is registered with COSE but is not offered by any credential parameter list the server sends, which makes it the algorithm to test that path with
    es256k: ecdsaAlgorithm('es256k', 'ES256K (ECDSA secp256k1)', -47, 'secp256k1', CURVE_SECP256K1, 'sha256'),
    rs256: rsaAlgorithm('rs256', 'RS256 (RSA PKCS#1 v1.5)', -257, 'sha256', constants.RSA_PKCS1_PADDING),
    ps256: rsaAlgorithm('ps256', 'PS256 (RSA-PSS)', -37, 'sha256', constants.RSA_PKCS1_PSS_PADDING),
    mldsa44: mldsaAlgorithm('mldsa44', 'ML-DSA-44', -48, 'ml-dsa-44'),
    mldsa65: mldsaAlgorithm('mldsa65', 'ML-DSA-65', -49, 'ml-dsa-65'),
    mldsa87: mldsaAlgorithm('mldsa87', 'ML-DSA-87', -50, 'ml-dsa-87'),
}

export function getPasskeyAlgorithm(name) {
    const algorithm = PASSKEY_ALGORITHMS[name]
    if (!algorithm) {
        throw new Error(`Unknown passkey algorithm: ${name}`)
    }
    return algorithm
}

// Reports whether the node runtime running the tests can generate keys for an algorithm
// ML-DSA needs a node build with a post-quantum-capable OpenSSL, so tests skip rather than fail where it is missing
export function isPasskeyAlgorithmAvailable(name) {
    const algorithm = getPasskeyAlgorithm(name)
    if (!algorithm.nodeKeyType) {
        return true
    }

    try {
        generateKeyPairSync(algorithm.nodeKeyType)
        return true
    } catch {
        return false
    }
}
