/*!
Based on https://github.com/mash/fetch-ndjson/blob/45bb6c51ba69e8335c66619df4aa576bb0315e32/src/index.ts
Copyright: Masakazu Ohtsuka (mash)
License: MIT
*/

// reader comes from:
// fetch('/api').then(response => response.body.getReader())
export default async function* gen<T>(reader: ReadableStreamDefaultReader): AsyncGenerator<T, void> {
    const matcher = /\r?\n/
    const decoder = new TextDecoder()
    let buf = ''

    let next = reader.read()
    while (true) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const { done, value } = await next

        if (done) {
            if (buf.length > 0) {
                yield JSON.parse(buf)
            }
            return
        }

        if (!value || !(value as BufferSource).byteLength) {
            continue
        }

        const chunk = decoder.decode(value as BufferSource, { stream: true })
        buf += chunk

        const parts = buf.split(matcher)
        if (parts.length) {
            // biome-ignore lint/style/noNonNullAssertion: it's guaranteed not undefined
            buf = parts.pop()!
            for (const i of parts) {
                // Ignore empty records
                if (i.length) {
                    yield JSON.parse(i)
                }
            }
        }

        next = reader.read()
    }
}
