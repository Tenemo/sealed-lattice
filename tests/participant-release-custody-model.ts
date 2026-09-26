import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileLinkedReleaseWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { operationSeedBytes } from '#tests/operation-seed-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';

export const participantReleaseProofRoleBytes =
    8n +
    6n * 6n +
    4n +
    BigInt(Buffer.byteLength('sealed-lattice/certified-release/v1')) +
    4n * 64n +
    2n;

const releaseContextBytes = 4n + 3n * 64n + 2n;
// Context, body length and body identity; the same for every profile.
export const participantReleaseEnvelopeBytes = releaseContextBytes + 8n + 64n;

// One original-key release under the retained certified target. Its seed is
// retained from the phase after the target lock until the body is.
export const compileParticipantReleaseCustody = (profile: SupportedProfile) => {
    const proof = compileLinkedReleaseWordProofLayout(profile);
    const { signatureBytes } = compileRegistrationEnrollmentCensus();
    const recordBytes = 1n << 20n;
    const keyBytes = 32n;
    const coinBytes = 32n;
    const bodyHeaderBytes = 4n + 8n + releaseContextBytes;
    const coefficientBytes =
        1n + (BigInt(profile.release.modulus.toString(2).length) + 7n) / 8n;
    const partialBytes =
        fixedModulusBfvInputs.polynomialDegree * coefficientBytes;
    const minimumBodyBytes = bodyHeaderBytes + partialBytes + proof.headerBytes;
    const maximumBodyBytes =
        bodyHeaderBytes + partialBytes + proof.maximumMultiproofBytes;
    const envelopeBytes = participantReleaseEnvelopeBytes;
    const maximumBodyRecords =
        (maximumBodyBytes + recordBytes - 1n) / recordBytes;
    const prefixBytes = 4n + 1n + 2n + 4n + 2n;
    const attempt =
        prefixBytes + compileTargetSigningStateCensus().maximumBodyBytes;
    const retainedBody = keyBytes * maximumBodyRecords + envelopeBytes;
    const phaseBytes = [
        { phase: 25, bytes: attempt },
        { phase: 26, bytes: attempt + operationSeedBytes },
        { phase: 27, bytes: attempt + retainedBody },
        { phase: 28, bytes: attempt + retainedBody + coinBytes },
        { phase: 29, bytes: attempt + retainedBody + signatureBytes },
    ];
    return {
        proofRoleBytes: participantReleaseProofRoleBytes,
        recordBytes,
        bodyHeaderBytes,
        partialBytes,
        minimumBodyBytes,
        maximumBodyBytes,
        envelopeBytes,
        signatureBytes,
        maximumBodyRecords,
        prefixBytes,
        phaseBytes,
        maximumStateBytes: phaseBytes.reduce(
            (maximum, value) => (value.bytes > maximum ? value.bytes : maximum),
            0n,
        ),
        maximumEncryptedBodyBytes: maximumBodyBytes + 16n * maximumBodyRecords,
    };
};
