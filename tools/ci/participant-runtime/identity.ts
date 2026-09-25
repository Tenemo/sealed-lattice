import type { ParticipantIdentities } from '../protocol-participant-predecessor.js';

import type { ParticipantKernel } from './kernel.js';

// The purposes whose identities the participant module derives, each under
// its own domain. The target purpose yields the certified target's own
// identity.
export const custodyPurpose = {
    root: 0,
    record: 1,
    enrollmentInput: 2,
    target: 3,
} as const;
type CustodyPurpose = (typeof custodyPurpose)[keyof typeof custodyPurpose];

// Derives one identity in the participant module, whose SHAKE256 framing is
// the only hash the runtime binds into its retained state.
export const custodyIdentity = (
    kernel: ParticipantKernel,
    purpose: CustodyPurpose,
    bytes: Uint8Array,
): Uint8Array => {
    if (kernel.custody_identity_begin(purpose, bytes.length) !== 0)
        throw new Error('The participant module refused an identity.');
    const capacity = kernel.custody_identity_input_capacity() >>> 0;
    for (let offset = 0; offset < bytes.length; offset += capacity) {
        const part = bytes.subarray(offset, offset + capacity);
        new Uint8Array(
            kernel.memory.buffer,
            kernel.custody_identity_input_pointer() >>> 0,
            part.length,
        ).set(part);
        if (kernel.custody_identity_absorb(part.length) !== 0)
            throw new Error('The participant module refused an identity.');
    }
    if (kernel.custody_identity_finish() !== 0)
        throw new Error('The participant module refused an identity.');
    return new Uint8Array(
        kernel.memory.buffer,
        kernel.custody_identity_output_pointer() >>> 0,
        64,
    ).slice();
};

// The root and record identities a predecessor check recomputes.
export const custodyIdentities = (
    kernel: ParticipantKernel,
): ParticipantIdentities => ({
    root: (bytes) => custodyIdentity(kernel, custodyPurpose.root, bytes),
    record: (bytes) => custodyIdentity(kernel, custodyPurpose.record, bytes),
});
