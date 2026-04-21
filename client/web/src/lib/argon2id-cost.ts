import type { Argon2idCost } from '$lib/v2-types'

// Argon2id cost used when creating new wrapped-primary-key envelopes
// Injected by Vite at build time via the `__ARGON2ID_COST__` define; see `vite.config.ts`
// Decrypting an existing envelope uses the cost stored inside the envelope, not this value
export const argon2idCost: Argon2idCost = __ARGON2ID_COST__
