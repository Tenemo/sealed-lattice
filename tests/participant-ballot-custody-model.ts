import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { operationSeedBytes } from '#tests/operation-seed-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

export const compileParticipantBallotCustody = (profile: SupportedProfile) => {
    const body = compileBallotBodyCensus(profile);
    const recordBytes = 1n << 20n;
    const maximumScores = 20n;
    // The attempt lock fixes the ballot time until the envelope carries it.
    const ballotTimeBytes = 8n;
    const keyBytes = 32n;
    const prefixBytes = 4n + 1n + 4n + 2n;
    const maximumBodyRecords =
        (body.maximumBodyBytes + recordBytes - 1n) / recordBytes;
    const attempt = prefixBytes + maximumScores + ballotTimeBytes;
    const retainedBody = keyBytes * maximumBodyRecords + body.envelopeBytes;
    // The seed is retained from the phase after the lock until the body is.
    const phaseBytes = [
        { phase: 13, bytes: attempt },
        { phase: 14, bytes: attempt + operationSeedBytes },
        { phase: 15, bytes: attempt + retainedBody },

        {
            phase: 17,
            bytes: prefixBytes + retainedBody + body.signatureBytes,
        },
    ];
    return {
        recordBytes,
        prefixBytes,
        maximumBodyRecords,
        maximumEncryptedBodyBytes:
            body.maximumBodyBytes + 16n * maximumBodyRecords,
        maximumStateBytes: phaseBytes.reduce(
            (maximum, value) => (value.bytes > maximum ? value.bytes : maximum),
            0n,
        ),
        phaseBytes,
    };
};
