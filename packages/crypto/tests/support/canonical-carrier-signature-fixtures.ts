import { shake256 } from '@noble/hashes/sha3.js';

export const hashCanonicalCarrierFixtureFrame = (
    canonicalHashFrame: Uint8Array,
): Uint8Array => {
    const hash = shake256.create({ dkLen: 64 });
    hash.update(canonicalHashFrame);
    return hash.digest();
};
