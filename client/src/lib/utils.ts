import { Decode as Base64UrlDecode } from 'arraybuffer-encoding/base64/url'
import { Decode as Base64StdDecode } from 'arraybuffer-encoding/base64/standard'

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
export function base64UrlToBytes(s: string): Uint8Array {
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