import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

const modulus = 257;
const reduce = (value: number): number =>
    ((value % modulus) + modulus) % modulus;
const inverse = (value: number): number => {
    for (let candidate = 1; candidate < modulus; candidate++)
        if (reduce(candidate * value) === 1) return candidate;
    throw new Error('No field inverse.');
};

// Counterexample to attaching ordinary threshold-decryption shares to target
// votes. A corrupt participant already knows its own shares and need not
// publish either a vote or a share before combining honest public responses.
export const certificationReleaseThresholdTrace = (
    participantCount: number,
    decryptionThreshold: number,
) => {
    const profile = compileThresholdCompletionProfile(participantCount);
    const corruptCount = profile.maximumCorruptParticipantCount;
    if (
        !Number.isSafeInteger(decryptionThreshold) ||
        decryptionThreshold <= corruptCount ||
        decryptionThreshold > participantCount
    )
        throw new RangeError('Invalid decryption threshold for this trace.');
    const secret = 73;
    const coefficients = Array.from(
        { length: decryptionThreshold },
        (_, index) => (index === 0 ? secret : reduce(11 * index * index + 3)),
    );
    const shares = Array.from({ length: participantCount }, (_, position) => {
        const point = position + 1;
        const value = coefficients.reduceRight(
            (sum, coefficient) => reduce(sum * point + coefficient),
            0,
        );
        return { position, point, value };
    });
    const corruptPrivateShares = shares.slice(0, corruptCount);
    const honestPublicShares = shares.slice(corruptCount, decryptionThreshold);
    const available = [...corruptPrivateShares, ...honestPublicShares];
    const recovered = reduce(
        available.reduce((sum, share) => {
            const weight = available.reduce(
                (product, other) =>
                    other.point === share.point
                        ? product
                        : reduce(
                              product *
                                  reduce(-other.point) *
                                  inverse(reduce(share.point - other.point)),
                          ),
                1,
            );
            return reduce(sum + weight * share.value);
        }, 0),
    );
    return {
        secret,
        recovered,
        corruptPrivateShares,
        honestPublicShares,
        publicVoteCount: honestPublicShares.length,
        certificateThreshold: profile.inventoryCertificateThreshold,
        publicCertificateAvailable:
            honestPublicShares.length >= profile.inventoryCertificateThreshold,
        guaranteedContinuingParticipants: participantCount - corruptCount,
        everyContinuingSetCanDecrypt:
            decryptionThreshold <= participantCount - corruptCount,
    };
};

export const compileCertificationReleaseThresholdCensus = () => {
    const participantCount = 10;
    const profile = compileThresholdCompletionProfile(participantCount);
    return {
        participantCount,
        corruptCount: profile.maximumCorruptParticipantCount,
        certificateThreshold: profile.inventoryCertificateThreshold,
        minimumThresholdDelayingThisTrace:
            profile.inventoryCertificateThreshold +
            profile.maximumCorruptParticipantCount,
        maximumThresholdForEveryContinuingSet:
            participantCount - profile.maximumCorruptParticipantCount,
        cases: Array.from(
            {
                length:
                    participantCount - profile.maximumCorruptParticipantCount,
            },
            (_, index) => {
                const threshold =
                    profile.maximumCorruptParticipantCount + 1 + index;
                const trace = certificationReleaseThresholdTrace(
                    participantCount,
                    threshold,
                );
                return {
                    threshold,
                    honestPublicShares: trace.publicVoteCount,
                    publicCertificateAvailable:
                        trace.publicCertificateAvailable,
                    everyContinuingSetCanDecrypt:
                        trace.everyContinuingSetCanDecrypt,
                };
            },
        ),
    };
};
