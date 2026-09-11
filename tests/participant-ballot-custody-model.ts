import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileBallotRandomnessBudget } from '#tests/ballot-randomness-budget-model.js';

export const compileParticipantBallotCustody = () => {
    const body = compileBallotBodyCensus();
    const randomness = compileBallotRandomnessBudget();
    const maximumScores = 20n;
    const keyBytes = 32n;
    const prefixBytes = 4n + 1n + 2n + 4n + 2n;
    const maximumBodyRecords =
        (body.maximumBodyBytes + randomness.recordBytes - 1n) /
        randomness.recordBytes;
    const phaseBytes = [
        {
            phase: 13,
            bytes:
                prefixBytes +
                maximumScores +
                keyBytes * (randomness.recordCount - 1n),
        },
        {
            phase: 14,
            bytes:
                prefixBytes + maximumScores + keyBytes * randomness.recordCount,
        },
        {
            phase: 15,
            bytes:
                prefixBytes +
                maximumScores +
                keyBytes * (randomness.recordCount + maximumBodyRecords) +
                body.envelopeBytes,
        },
        {
            phase: 16,
            bytes:
                prefixBytes +
                maximumScores +
                keyBytes * (randomness.recordCount + maximumBodyRecords) +
                body.envelopeBytes +
                32n,
        },
        {
            phase: 17,
            bytes:
                prefixBytes +
                keyBytes * maximumBodyRecords +
                body.envelopeBytes +
                body.signatureBytes,
        },
    ];
    return {
        prefixBytes,
        maximumBodyRecords,
        maximumEncryptedBodyBytes:
            body.maximumBodyBytes + 16n * maximumBodyRecords,
        maximumStateBytes: phaseBytes.reduce(
            (maximum, value) => (value.bytes > maximum ? value.bytes : maximum),
            0n,
        ),
        phaseBytes,
        maximumJournalAndBodyBytes:
            randomness.encryptedJournalBytes +
            body.maximumBodyBytes +
            16n * maximumBodyRecords,
    };
};
