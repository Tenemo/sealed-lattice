import type { ProtocolHash } from '@sealed-lattice/types';

import { canonicalJson, hash512Hex } from './canonical-json.js';

const textEncoder = new TextEncoder();

// Single structural hash domain for canonical typed protocol objects, records,
// and roots. Every preimage is the canonical JSON of an object carrying a
// mandatory `objectType` discriminator, so domain separation comes from that
// in-band type tag rather than from a per-type wire namespace. This domain MUST
// byte-match the Rust kernel's derive_canonical_object_hash.
const canonicalObjectHashDomain = 'sealed-lattice-root/canonical-object';

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

// The non-empty-objectType check is required: it makes "never merge a
// typeless preimage into the shared domain" a hard rejection, not a convention.
export const deriveCanonicalObjectHash = (value: unknown): ProtocolHash => {
    const objectType = isRecord(value) ? value.objectType : undefined;
    if (typeof objectType !== 'string' || objectType.length === 0) {
        throw new TypeError(
            'Canonical object hash requires a non-empty objectType discriminator.',
        );
    }

    return hash512Hex(canonicalObjectHashDomain, [
        textEncoder.encode(canonicalJson(value)),
    ]);
};
