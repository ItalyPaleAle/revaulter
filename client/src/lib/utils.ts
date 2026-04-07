import { Decode as Base64StdDecode } from 'arraybuffer-encoding/base64/standard'
import { Decode as Base64UrlDecode, Encode as Base64UrlEncode } from 'arraybuffer-encoding/base64/url'

/**
 * Returns a Promise that resolves after a certain amount of time, in ms
 *
 * @param time Time to wait in ms; if 0, this just executes the action on the next tick of the event loop
 * @returns Promise that resolves after a certain amount of time
 */
export function waitPromise(time: number): Promise<void> {
    return new Promise((resolve) => {
        setTimeout(resolve, time || 0)
    })
}

/**
 * Sets a timeout on a Promise, so it's automatically rejected if it doesn't resolve within a certain time.
 *
 * @param promise Promise to execute
 * @param timeout Timeout in ms
 * @param message Optional error message
 * @returns Promise with a timeout
 */
export function timeoutPromise<T>(promise: Promise<T>, timeout: number, message?: string): Promise<T> {
    return Promise.race([
        waitPromise(timeout).then(() => {
            throw new TimeoutError(message || 'Promise has timed out')
        }),
        promise,
    ])
}

/**
 * Error returned by timed out Promises in timeoutPromise
 */
export class TimeoutError extends Error {}

/** Decodes either base64url or regular base64 into raw bytes. */
export function base64UrlToBytes(s?: string): Uint8Array {
    if (!s) {
        return new Uint8Array()
    }

    const normalized = s.trim()
    if (normalized === '') {
        return new Uint8Array()
    }

    // Prefer base64url because that is what the app emits on the wire
    try {
        return new Uint8Array(Base64UrlDecode(normalized))
    } catch {
        // Accept standard base64 too so callers can pass CLI or older payloads
        return new Uint8Array(Base64StdDecode(normalized))
    }
}

/** Encodes bytes using unpadded base64url, which is the wire format */
export function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
    return Base64UrlEncode(toArrayBuffer(bytes))
}

/** Returns an owned `ArrayBuffer`, copying when the input is a `Uint8Array` view. */
export function toArrayBuffer(bytes: ArrayBuffer | Uint8Array): ArrayBuffer {
    if (bytes instanceof Uint8Array) {
        // Copy typed array views into a standalone buffer before encoding
        const out = new Uint8Array(bytes.byteLength)
        out.set(bytes)
        return out.buffer
    }

    return bytes
}

/** Casts browser binary inputs to the `BufferSource` shape expected by WebCrypto */
export function asBuf(v: Uint8Array | ArrayBuffer): BufferSource
export function asBuf(v?: Uint8Array | ArrayBuffer): undefined
export function asBuf(v?: Uint8Array | ArrayBuffer): BufferSource | undefined {
    if (v === undefined) {
        return undefined
    }
    return v as unknown as BufferSource
}
