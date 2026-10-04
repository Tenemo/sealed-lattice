import {
    compileBallotWordProofLayout,
    compileFullWordProofLayout,
    compileLinkedReleaseWordProofLayout,
    compileRegistrationWordProofLayout,
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
        ['registration', compileRegistrationWordProofLayout(), 'registration'],
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
