// MAX_KEY_LABEL_LENGTH mirrors protocolv2.MaxKeyLabelLength in Go
export const MAX_KEY_LABEL_LENGTH = 24

// KEY_LABEL_RULES describes the accepted key labels for error messages and help text
export const KEY_LABEL_RULES = `Key labels must be 1-${MAX_KEY_LABEL_LENGTH} characters long and contain only letters, digits, and _ . + -`

// normalizeKeyLabel returns the canonical form of a key label, or null if the label is not valid
// It mirrors protocolv2.NormalizeAndValidateKeyLabel in Go: the allowed characters are [A-Za-z0-9_.+-] and the result is lowercased
// Keys are always derived from the canonical form, so the browser, the CLI, and the server agree on which key a label refers to
export function normalizeKeyLabel(label: string): string | null {
    if (label === '' || label.length > MAX_KEY_LABEL_LENGTH) {
        return null
    }

    for (let i = 0; i < label.length; i++) {
        const ch = label.charCodeAt(i)
        const isLower = ch >= 0x61 && ch <= 0x7a
        const isUpper = ch >= 0x41 && ch <= 0x5a
        const isDigit = ch >= 0x30 && ch <= 0x39
        const isSymbol = ch === 0x5f || ch === 0x2d || ch === 0x2e || ch === 0x2b
        if (!isLower && !isUpper && !isDigit && !isSymbol) {
            return null
        }
    }

    return label.toLowerCase()
}

// assertCanonicalKeyLabel throws unless the label is already in its canonical form
// Key derivation calls this so a label that skipped normalization can never produce a key that differs from the one the CLI and server refer to
export function assertCanonicalKeyLabel(label: string): void {
    if (normalizeKeyLabel(label) !== label) {
        throw new Error(`Key label "${label}" is not in canonical form`)
    }
}
