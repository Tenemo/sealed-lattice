import type { ParticipantModule } from './participant-module.js';
import type { ParticipantIdentities } from './predecessor.js';

// The label of the runtime identity: the SHA-512 digest of this label and the
// SHA-512 digests of the source manifest, the module and the worker.
export const participantRuntimeLabel = 'participant-runtime/8';

// The purposes whose identities the participant module derives, each under
// its own domain. The target, envelope and close-response purposes yield the
// certified target's, a ballot envelope's and a close response body's own
// identities.
export const custodyPurpose = {
    root: 0,
    record: 1,
    enrollmentInput: 2,
    target: 3,
    envelope: 4,
    closeResponse: 5,
} as const;
type CustodyPurpose = (typeof custodyPurpose)[keyof typeof custodyPurpose];

// Derives protocol object and custody identities with the participant
// module's canonical SHAKE256 framing. The separately derived build runtime
// identity is also bound into protocol contexts and retained state.
export const custodyIdentity = (
    module: ParticipantModule,
    purpose: CustodyPurpose,
    bytes: Uint8Array,
): Uint8Array => {
    if (module.custody_identity_begin(purpose, bytes.length) !== 0)
        throw new Error('The participant module refused an identity.');
    const capacity = module.custody_identity_input_capacity() >>> 0;
    for (let offset = 0; offset < bytes.length; offset += capacity) {
        const part = bytes.subarray(offset, offset + capacity);
        new Uint8Array(
            module.memory.buffer,
            module.custody_identity_input_pointer() >>> 0,
            part.length,
        ).set(part);
        if (module.custody_identity_absorb(part.length) !== 0)
            throw new Error('The participant module refused an identity.');
    }
    if (module.custody_identity_finish() !== 0)
        throw new Error('The participant module refused an identity.');
    return new Uint8Array(
        module.memory.buffer,
        module.custody_identity_output_pointer() >>> 0,
        64,
    ).slice();
};

// The root and record identities a predecessor check recomputes.
export const custodyIdentities = (
    module: ParticipantModule,
): ParticipantIdentities => ({
    root: (bytes) => custodyIdentity(module, custodyPurpose.root, bytes),
    record: (bytes) => custodyIdentity(module, custodyPurpose.record, bytes),
});
