import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it, vi } from 'vitest';

import { createVssSourceTrusteeCoefficientCommitmentContribution } from '#packages/protocol/src/setup/vss-coefficient-commitments/commitment-contribution';
import {
    setupCommitmentRandomnessWidth,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/setup/vss-coefficient-commitments/constants-and-types';
import {
    RandomByteSampler,
    maximumPrivateSamplerCandidateDrawsPerOutput,
    sampleCenteredTernaryVector,
    sampleUniformResidueVector,
} from '#packages/protocol/src/setup/vss-coefficient-commitments/encoding';
import { createVssSourceTrusteeCoefficientOpeningState } from '#packages/protocol/src/setup/vss-coefficient-commitments/opening-state';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    makeSetupContext,
    makeSetupFixtureHash,
    makeVssOpeningRandomBytes,
} from '#tests/support/setup-fixtures';

const qSharePrimes = [
    140_700_980_543_489, 140_546_359_361_537, 140_507_704_066_049,
] as const;
const ringDegree = 8;
const participantCount = 2;
const thresholdDegree = 2;

const transcriptCoreKernel = await loadTranscriptCoreKernel();
const setupCommitmentComputer: typeof transcriptCoreKernel.computeSetupCommitmentFromOpening =
    (input) => transcriptCoreKernel.computeSetupCommitmentFromOpening(input);

const fixtureHash = makeSetupFixtureHash('setup-vss-coefficient-commitments');

const deterministicRandomBytes = makeVssOpeningRandomBytes(
    'setup-vss-coefficient-commitments',
);

const withDeterministicOpeningEntropy = <Result>(
    label: string,
    operation: () => Result,
): Result => {
    const randomBytes = deterministicRandomBytes(label);
    const entropySpy = vi.spyOn(globalThis.crypto, 'getRandomValues');
    entropySpy.mockImplementation(
        <Value extends ArrayBufferView>(value: Value): Value => {
            new Uint8Array(
                value.buffer,
                value.byteOffset,
                value.byteLength,
            ).set(randomBytes(value.byteLength));
            return value;
        },
    );
    try {
        return operation();
    } finally {
        entropySpy.mockRestore();
    }
};

const setupContext = makeSetupContext(fixtureHash, participantCount);
const publicMatrixSeedHash = fixtureHash('public-matrix-seed');
const setupParameters = {
    participantCount,
    qSharePrimes,
    ringDegree,
    thresholdDegree,
} as const;
const coefficientCommitmentInput = {
    setupContext,
    publicMatrixSeedHash,
    setupCommitmentComputer,
    qSharePrimes,
    ringDegree,
    thresholdDegree,
} as const;
const sourceTrusteeIdentity = (sourceTrusteeRosterPosition: number): string =>
    `trustee-${String(sourceTrusteeRosterPosition)}`;
const sourceTrusteeReference = (
    sourceTrusteeRosterPosition: number,
): Readonly<{
    sourceTrusteeIdentity: string;
    sourceTrusteeRosterPosition: number;
}> => ({
    sourceTrusteeIdentity: sourceTrusteeIdentity(sourceTrusteeRosterPosition),
    sourceTrusteeRosterPosition,
});

const sourceTrusteeOpeningState = (
    sourceTrusteeRosterPosition: number,
): VssSourceTrusteeCoefficientOpeningState =>
    withDeterministicOpeningEntropy(
        `opening-${sourceTrusteeIdentity(sourceTrusteeRosterPosition)}`,
        () =>
            createVssSourceTrusteeCoefficientOpeningState({
                ...sourceTrusteeReference(sourceTrusteeRosterPosition),
                ...setupParameters,
            }),
    );

const sourceTrusteeCommitmentContributionInput = (
    openingState: VssSourceTrusteeCoefficientOpeningState = sourceTrusteeOpeningState(
        0,
    ),
): Parameters<
    typeof createVssSourceTrusteeCoefficientCommitmentContribution
>[0] => ({
    ...coefficientCommitmentInput,
    sourceTrusteeOpeningState: openingState,
});

const requiredItem = <Item>(
    items: readonly Item[],
    itemIndex: number,
    missingMessage: string,
): Item => {
    const item = items[itemIndex];
    if (item === undefined) {
        throw new Error(missingMessage);
    }

    return item;
};

const requiredOpening = (
    sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    openingIndex: number,
): VssCoefficientOpeningInput =>
    requiredItem(
        sourceTrusteeState.coefficientOpenings,
        openingIndex,
        'fixture opening is missing',
    );

const requiredRandomnessColumn = (
    openingState: VssCoefficientOpeningInput,
    randomnessColumnIndex: number,
): readonly number[] => {
    return requiredItem(
        openingState.randomnessByColumn,
        randomnessColumnIndex,
        'fixture randomness column is missing',
    );
};

const requiredOpeningByCoordinate = (
    sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => {
    const openingState = sourceTrusteeState.coefficientOpenings.find(
        (candidateOpening) =>
            candidateOpening.rnsLimbIndex === rnsLimbIndex &&
            candidateOpening.shamirCoefficientIndex === shamirCoefficientIndex,
    );
    if (openingState === undefined) {
        throw new Error('fixture opening coordinate is missing');
    }

    return openingState;
};

const decodeShortSecretResidues = (
    openingState: VssCoefficientOpeningInput,
): readonly (-1 | 0 | 1)[] =>
    openingState.coefficientMessage.map((coefficient) => {
        if (coefficient === 0) {
            return 0;
        }
        if (coefficient === 1) {
            return 1;
        }
        if (coefficient === openingState.rnsPrime - 1) {
            return -1;
        }
        throw new Error(
            'constant Shamir coefficient is not a centered ternary residue',
        );
    });

type RejectionCase<Input> = Readonly<{
    name: string;
    expectedMessage: RegExp;
    input: () => Input;
}>;

const mutateSourceTrusteeOpeningState = (
    mutate: (
        sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    ) => VssSourceTrusteeCoefficientOpeningState,
): VssSourceTrusteeCoefficientOpeningState =>
    mutate(sourceTrusteeOpeningState(0));

const mutateFirstOpening = (
    mutate: (
        openingState: VssCoefficientOpeningInput,
    ) => VssCoefficientOpeningInput,
): VssSourceTrusteeCoefficientOpeningState =>
    mutateSourceTrusteeOpeningState((sourceTrusteeState) => ({
        ...sourceTrusteeState,
        coefficientOpenings: [
            mutate(requiredOpening(sourceTrusteeState, 0)),
            ...sourceTrusteeState.coefficientOpenings.slice(1),
        ],
    }));

const malformedCoefficientCommitmentContributionCases = [
    {
        name: 'duplicate opening coordinate',
        expectedMessage: /distinct limb\/coefficient coordinates/u,
        input: () =>
            mutateSourceTrusteeOpeningState((sourceTrusteeState) => ({
                ...sourceTrusteeState,
                coefficientOpenings: [
                    requiredOpening(sourceTrusteeState, 0),
                    requiredOpening(sourceTrusteeState, 0),
                    ...sourceTrusteeState.coefficientOpenings.slice(2),
                ],
            })),
    },
    {
        name: 'coefficient residue at the modulus',
        expectedMessage: /residue below the declared modulus/u,
        input: () =>
            mutateFirstOpening((openingState) => ({
                ...openingState,
                coefficientMessage: [
                    qSharePrimes[0],
                    ...openingState.coefficientMessage.slice(1),
                ],
            })),
    },
    {
        name: 'randomness outside the centered ternary domain',
        expectedMessage: /centered ternary/u,
        input: () =>
            mutateFirstOpening((openingState) => ({
                ...openingState,
                randomnessByColumn: [
                    [2, ...requiredRandomnessColumn(openingState, 0).slice(1)],
                    ...openingState.randomnessByColumn.slice(1),
                ],
            })),
    },
] as const satisfies readonly RejectionCase<VssSourceTrusteeCoefficientOpeningState>[];

const openingStateGenerationInput = (
    overrides: Partial<
        Parameters<typeof createVssSourceTrusteeCoefficientOpeningState>[0]
    > = {},
): Parameters<typeof createVssSourceTrusteeCoefficientOpeningState>[0] => ({
    ...sourceTrusteeReference(0),
    ...setupParameters,
    ...overrides,
});

const invalidOpeningStateGenerationCases = [
    {
        name: 'source trustee outside the roster',
        expectedMessage: /inside the accepted participant count/u,
        input: () =>
            openingStateGenerationInput({
                sourceTrusteeIdentity: 'trustee-2',
                sourceTrusteeRosterPosition: 2,
            }),
    },
    {
        name: 'empty RNS basis',
        expectedMessage: /at least one RNS prime/u,
        input: () => openingStateGenerationInput({ qSharePrimes: [] }),
    },
] as const satisfies readonly RejectionCase<
    Parameters<typeof createVssSourceTrusteeCoefficientOpeningState>[0]
>[];

describe('VSS coefficient commitment builders', () => {
    it('preserves every random byte across internal refill boundaries', () => {
        let nextByte = 0;
        const sampler = new RandomByteSampler((byteLength) => {
            const bytes = new Uint8Array(byteLength);
            for (let byteIndex = 0; byteIndex < byteLength; byteIndex += 1) {
                bytes[byteIndex] = nextByte;
                nextByte = (nextByte + 1) & 0xff;
            }

            return bytes;
        });

        sampler.take(4090);
        expect(sampler.take(16)).toEqual(
            Uint8Array.from(
                { length: 16 },
                (_unused, byteIndex) => (4090 + byteIndex) & 0xff,
            ),
        );
    });

    it('fails rather than looping or reducing with bias at the candidate-draw ceiling', () => {
        const rejectedBytes = () => new Uint8Array(4096).fill(0xff);

        expect(() =>
            sampleCenteredTernaryVector(
                new RandomByteSampler(rejectedBytes),
                1,
            ),
        ).toThrow(/candidate-draw ceiling/u);
        expect(() =>
            sampleUniformResidueVector(
                new RandomByteSampler(rejectedBytes),
                qSharePrimes[0],
                1,
            ),
        ).toThrow(/candidate-draw ceiling/u);
        expect(maximumPrivateSamplerCandidateDrawsPerOutput).toBe(64);
    });

    it('generates local openings with one short secret shared across RNS limbs', () => {
        const generatedSourceTrusteeState = withDeterministicOpeningEntropy(
            'trustee-0',
            () =>
                createVssSourceTrusteeCoefficientOpeningState(
                    openingStateGenerationInput(),
                ),
        );
        const constantSecretForFirstLimb = decodeShortSecretResidues(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0),
        );
        const constantSecretForSecondLimb = decodeShortSecretResidues(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 1, 0),
        );
        const nonConstantOpening = requiredOpeningByCoordinate(
            generatedSourceTrusteeState,
            0,
            1,
        );
        const firstRandomnessColumn = requiredRandomnessColumn(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0),
            0,
        );

        expect(generatedSourceTrusteeState.coefficientOpenings).toHaveLength(
            qSharePrimes.length * thresholdDegree,
        );
        expect(constantSecretForSecondLimb).toEqual(constantSecretForFirstLimb);
        expect(
            nonConstantOpening.coefficientMessage.every(
                (coefficient) =>
                    coefficient >= 0 &&
                    coefficient < nonConstantOpening.rnsPrime,
            ),
        ).toBe(true);
        expect(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0)
                .randomnessByColumn,
        ).toHaveLength(setupCommitmentRandomnessWidth);
        expect(
            firstRandomnessColumn.every(
                (coefficient) =>
                    coefficient === -1 ||
                    coefficient === 0 ||
                    coefficient === 1,
            ),
        ).toBe(true);
    });

    it('fails closed when Web Crypto entropy is unavailable', () => {
        const entropySpy = vi.spyOn(globalThis.crypto, 'getRandomValues');
        entropySpy.mockImplementation(() => {
            throw new Error('entropy source failed');
        });
        try {
            expect(() =>
                createVssSourceTrusteeCoefficientOpeningState(
                    openingStateGenerationInput(),
                ),
            ).toThrow(/Web Crypto getRandomValues failed/u);
        } finally {
            entropySpy.mockRestore();
        }
    });

    it('creates deterministic commitment records from local openings', () => {
        const openingState = sourceTrusteeOpeningState(0);
        const contribution =
            createVssSourceTrusteeCoefficientCommitmentContribution(
                sourceTrusteeCommitmentContributionInput(openingState),
            );
        const repeatedContribution =
            createVssSourceTrusteeCoefficientCommitmentContribution(
                sourceTrusteeCommitmentContributionInput(openingState),
            );
        const firstCommitment = contribution.coefficientCommitments[0];
        const firstOpening = requiredOpening(openingState, 0);

        expect(
            contribution.sourceTrusteeCoefficientCommitmentRecord
                .sourceTrusteeIdentity,
        ).toBe('trustee-0');
        expect(
            deriveCanonicalObjectHash(
                contribution.sourceTrusteeCoefficientCommitmentRecord,
            ),
        ).toBe(
            deriveCanonicalObjectHash(
                repeatedContribution.sourceTrusteeCoefficientCommitmentRecord,
            ),
        );
        const recomputedCommitment = setupCommitmentComputer({
            publicMatrixSeedHash,
            sourceRnsLimbIndex: firstOpening.rnsLimbIndex,
            shamirCoefficientIndex: firstOpening.shamirCoefficientIndex,
            messageCoefficients: firstOpening.coefficientMessage,
            randomnessByColumn: firstOpening.randomnessByColumn,
            ringDegree,
        }).commitment;
        expect(firstCommitment).toEqual(recomputedCommitment);
        expect(deriveCanonicalObjectHash(recomputedCommitment)).toBe(
            contribution.coefficientOpenings[0]?.commitmentRoot,
        );
    });

    it.each(malformedCoefficientCommitmentContributionCases)(
        'rejects malformed local opening state before root publication: $name',
        ({ expectedMessage, input }) => {
            expect(() =>
                createVssSourceTrusteeCoefficientCommitmentContribution(
                    sourceTrusteeCommitmentContributionInput(input()),
                ),
            ).toThrow(expectedMessage);
        },
    );

    it.each(invalidOpeningStateGenerationCases)(
        'rejects invalid local opening generation input: $name',
        ({ expectedMessage, input }) => {
            expect(() =>
                createVssSourceTrusteeCoefficientOpeningState(input()),
            ).toThrow(expectedMessage);
        },
    );
});
