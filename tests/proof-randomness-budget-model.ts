import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import {
    compileBallotWordProofLayout,
    compileFullWordProofLayout,
    compileLinkedReleaseWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import { proofHashProfiles } from '#tests/proof-hash-work-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';

const binomial = (population: bigint, count: bigint) => {
    if (count > population) return 0n;
    let result = 1n;
    for (let index = 1n; index <= count; index++)
        result = (result * (population - index + 1n)) / index;
    return result;
};

// One specified accepted output vector and the number of candidate words
// examined through each next acceptance. Rounding to complete reads discards
// an unexamined suffix; the next consumer starts after that whole suffix.
// This is an ideal independent-stream law, not a seed-expansion comparison.
export const bufferedFieldWaitingLaw = (
    candidateValues: bigint,
    acceptedValues: bigint,
    waitingDraws: readonly bigint[],
    bufferWords: bigint,
) => {
    if (
        candidateValues < 1n ||
        acceptedValues < 1n ||
        acceptedValues > candidateValues ||
        bufferWords < 1n ||
        waitingDraws.length === 0 ||
        waitingDraws.some((draws) => draws < 1n)
    )
        throw new RangeError('Invalid buffered field waiting history.');
    const outputs = BigInt(waitingDraws.length);
    const examinedWords = waitingDraws.reduce((sum, draws) => sum + draws, 0n);
    const reads = (examinedWords + bufferWords - 1n) / bufferWords;
    const outputVectors = acceptedValues ** outputs;
    const jointNumerator =
        (candidateValues - acceptedValues) ** (examinedWords - outputs);
    return {
        examinedWords,
        reads,
        requestedWords: reads * bufferWords,
        discardedWords: reads * bufferWords - examinedWords,
        outputVectors,
        jointNumerator,
        historyNumerator: outputVectors * jointNumerator,
        denominator: candidateValues ** examinedWords,
    };
};

// The degree mask's accepted-value count is an exact multiple of the
// native read width. Any rejection in its minimum prefix needs another
// read. Bonferroni and the union bound enclose that probability without
// materializing an integer with one exponent per requested field element.
export const compileFirstOracleReadVariation = () => {
    const agreement = compileCommonAgreementDegreeCensus();
    const field = compileSmallLimbProofFieldCensus();
    const requiredValues = 3n * BigInt(agreement.codeDimension);
    const bufferWords = 65_536n / field.packedFieldElementByteLength;
    if (requiredValues % bufferWords !== 0n)
        throw new Error(
            'The degree-mask prefix no longer fills complete reads.',
        );
    const candidateValues = 1n << field.modulusBitLength;
    const rejectedValues = candidateValues - field.modulus;
    const denominator = candidateValues * candidateValues;
    const upperNumerator = requiredValues * rejectedValues * candidateValues;
    const lowerNumerator =
        upperNumerator -
        binomial(requiredValues, 2n) * rejectedValues * rejectedValues;
    if (lowerNumerator <= 0n || upperNumerator >= denominator)
        throw new Error(
            'The degree-mask read-variation interval needs another bound.',
        );
    let upperProbabilityExponent = 0n;
    while (upperNumerator << (upperProbabilityExponent + 1n) <= denominator)
        upperProbabilityExponent++;
    let lowerProbabilityExponent = 0n;
    while (lowerNumerator << lowerProbabilityExponent < denominator)
        lowerProbabilityExponent++;
    return {
        requiredValues,
        bufferWords,
        minimumReads: requiredValues / bufferWords,
        candidateValues,
        rejectedValues,
        lowerNumerator,
        upperNumerator,
        denominator,
        lowerProbabilityExponent,
        upperProbabilityExponent,
    };
};

export const rejectionSubsetBound = (input: {
    candidatePositions: bigint;
    requiredRejections: bigint;
    rejectedValues: bigint;
    sampleBits: bigint;
    inputCount: bigint;
}) => {
    const {
        candidatePositions,
        requiredRejections,
        rejectedValues,
        sampleBits,
        inputCount,
    } = input;
    if (
        candidatePositions < 0n ||
        requiredRejections < 0n ||
        sampleBits < 1n ||
        sampleBits > 4096n ||
        rejectedValues < 0n ||
        rejectedValues > 1n << sampleBits ||
        inputCount < 0n
    )
        throw new RangeError('Invalid rejection-subset population.');
    return {
        numerator:
            inputCount *
            binomial(candidatePositions, requiredRejections) *
            rejectedValues ** requiredRejections,
        denominatorBits: sampleBits * requiredRejections,
    };
};

// Each extra buffered read requires at least one rejected candidate. This
// union deliberately counts salts, discarded tails and the fresh programmed
// message as candidate positions. All calls are sample-byte aligned.
export const bufferedFieldSamplingFailure = (input: {
    baselineBytes: bigint;
    bufferBytes: bigint;
    sampleBits: bigint;
    modulus: bigint;
    extraReads: bigint;
    invocations: bigint;
}) => {
    const {
        baselineBytes,
        bufferBytes,
        sampleBits,
        modulus,
        extraReads,
        invocations,
    } = input;
    if (
        sampleBits < 8n ||
        sampleBits > 4096n ||
        sampleBits % 8n !== 0n ||
        modulus < 2n ||
        modulus > 1n << sampleBits ||
        baselineBytes < 0n ||
        bufferBytes < sampleBits / 8n ||
        bufferBytes % (sampleBits / 8n) !== 0n ||
        baselineBytes % (sampleBits / 8n) !== 0n ||
        extraReads < 0n ||
        invocations < 1n
    )
        throw new RangeError('Invalid buffered field-sampling population.');
    const maximumBytes = baselineBytes + extraReads * bufferBytes;
    const candidatePositions = maximumBytes / (sampleBits / 8n);
    const rejectedValues = (1n << sampleBits) - modulus;
    const requiredRejections = extraReads + 1n;
    return {
        maximumBytes,
        candidatePositions,
        requiredRejections,
        ...rejectionSubsetBound({
            candidatePositions,
            requiredRejections,
            rejectedValues,
            sampleBits,
            inputCount: invocations,
        }),
    };
};

export const compileProofRandomnessBudgets = (profile: SupportedProfile) => {
    const field = compileSmallLimbProofFieldCensus();
    const compiler = compileWideChallengeCompilerCensus(profile);
    const bufferBytes = 65_536n;
    const failureAllocationBits = 128n;
    // Each role's simulator runs at most once per honest proof, which the
    // compiler's honest-proof budget bounds; restarts replay completed proofs.
    const invocationCap = compiler.honestProofBudget;
    const messageBytes = new Map(
        proofHashProfiles(profile).map((role) => [
            role.role,
            role.messageBytes,
        ]),
    );
    const layouts = [
        ['setup contribution', compileFullWordProofLayout(profile), 'setup'],
        ['linked ballot', compileBallotWordProofLayout(profile), 'ballot'],
        [
            'linked release',
            compileLinkedReleaseWordProofLayout(profile),
            'release',
        ],
    ] as const;
    return layouts.map(([role, layout, descriptor]) => {
        const ordinaryBaselineBytes = layout.minimumRequestedRandomBytes;
        const programmedMessageBytes = messageBytes.get(descriptor)!;
        const simulatorBaselineBytes =
            ordinaryBaselineBytes + programmedMessageBytes;
        const bound = (extraReads: bigint) =>
            bufferedFieldSamplingFailure({
                baselineBytes: simulatorBaselineBytes,
                bufferBytes,
                sampleBits: field.modulusBitLength,
                modulus: field.modulus,
                extraReads,
                invocations: invocationCap,
            });
        let extraReads = 0n;
        while (
            bound(extraReads).numerator << failureAllocationBits >
            1n << bound(extraReads).denominatorBits
        )
            extraReads++;
        const failure = bound(extraReads);
        return {
            role,
            ordinaryBaselineBytes,
            programmedMessageBytes,
            simulatorBaselineBytes,
            bufferBytes,
            extraReads,
            invocationCap,
            failureAllocationBits,
            failure,
        };
    });
};
