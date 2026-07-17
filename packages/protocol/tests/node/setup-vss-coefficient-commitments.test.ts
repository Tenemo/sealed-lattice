import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it, vi } from 'vitest';

import { createVssSourceTrusteeCoefficientCommitmentContribution } from '#packages/protocol/src/setup/vss-coefficient-commitments/commitment-contribution';
import {
    setupCommitmentModulusLimbCount,
    setupCommitmentHidingSecretWidth,
    setupCommitmentRandomnessWidth,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/setup/vss-coefficient-commitments/constants-and-types';
import {
    RandomByteSampler,
    maximumPrivateSamplerCandidateDrawsPerOutput,
    sampleCommitmentOpeningRandomness,
    sampleCenteredTernaryVector,
    sampleUniformResidueVector,
} from '#packages/protocol/src/setup/vss-coefficient-commitments/encoding';
import { createVssSourceTrusteeCoefficientOpeningState } from '#packages/protocol/src/setup/vss-coefficient-commitments/opening-state';
import {
    type ClosedWorkerStructuredCommitmentOpeningCapability,
    type ClosedWorkerStructuredCommitmentOpeningOperations,
} from '#packages/wasm/src/index';
import {
    makeSetupContext,
    makeSetupFixtureHash,
    makeVssOpeningRandomBytes,
} from '#tests/support/setup-fixtures';

const qSharePrimes = [
    140_700_980_543_489, 140_546_359_361_537, 140_507_704_066_049,
] as const;
const ringDegree = 8;
const participantCount = 3;
const thresholdDegree = 2;

const fixtureHash = makeSetupFixtureHash('setup-vss-coefficient-commitments');

const deterministicRandomBytes = makeVssOpeningRandomBytes(
    'setup-vss-coefficient-commitments',
);

type TestOpeningRecord = Readonly<{
    randomnessByCommitmentLimb: readonly (readonly (readonly number[])[])[];
    rnsLimbIndex: number;
    shamirCoefficientIndex: number;
}>;

const testOpeningRecords = new WeakMap<
    ClosedWorkerStructuredCommitmentOpeningCapability,
    TestOpeningRecord
>();
const testOpeningCapabilitiesBySlot = new Map<
    string,
    ClosedWorkerStructuredCommitmentOpeningCapability
>();
const activeTestOpeningCapabilities =
    new Set<ClosedWorkerStructuredCommitmentOpeningCapability>();

const structuredCommitmentOpenings: ClosedWorkerStructuredCommitmentOpeningOperations =
    Object.freeze({
        create: ({
            shamirCoefficientIndex,
            sourceRnsLimbIndex,
            sourceSetupIntentObjectHash,
        }) => {
            const slotKey = `${sourceSetupIntentObjectHash}:${String(sourceRnsLimbIndex)}:${String(shamirCoefficientIndex)}`;
            const existing = testOpeningCapabilitiesBySlot.get(slotKey);
            if (existing !== undefined) {
                return existing;
            }
            const capability = Object.freeze(
                {},
            ) as unknown as ClosedWorkerStructuredCommitmentOpeningCapability;
            const randomnessByCommitmentLimb = Object.freeze(
                Array.from(
                    { length: setupCommitmentModulusLimbCount },
                    (_unused, commitmentLimbPosition) =>
                        sampleCommitmentOpeningRandomness(
                            new RandomByteSampler(
                                deterministicRandomBytes(
                                    `${slotKey}:${String(commitmentLimbPosition)}`,
                                ),
                            ),
                            ringDegree,
                        ),
                ),
            );
            testOpeningRecords.set(capability, {
                randomnessByCommitmentLimb,
                rnsLimbIndex: sourceRnsLimbIndex,
                shamirCoefficientIndex,
            });
            testOpeningCapabilitiesBySlot.set(slotKey, capability);
            activeTestOpeningCapabilities.add(capability);
            return capability;
        },
        computeCommitment: ({
            capability,
            messageCoefficients,
            publicMatrixSeedHash: selectedPublicMatrixSeedHash,
        }) => {
            const record = testOpeningRecords.get(capability);
            if (
                record === undefined ||
                !activeTestOpeningCapabilities.has(capability)
            ) {
                throw new Error(
                    'structured-commitment opening capability is not active in this scope',
                );
            }
            if (selectedPublicMatrixSeedHash !== publicMatrixSeedHash) {
                throw new Error('test matrix-seed hash is outside the scope');
            }
            return {
                commitment: {
                    objectType: 'SetupCommitment' as const,
                    sourceRnsLimbIndex: record.rnsLimbIndex,
                    shamirCoefficientIndex: record.shamirCoefficientIndex,
                    ringDegree,
                    commitmentLimbs: record.randomnessByCommitmentLimb.map(
                        (randomnessByColumn, commitmentLimbPosition) => ({
                            rows: Array.from(
                                { length: setupCommitmentHidingSecretWidth },
                                (_unused, rowIndex) =>
                                    messageCoefficients.map(
                                        (
                                            messageCoefficient,
                                            coefficientIndex,
                                        ) => {
                                            const randomnessCoefficient =
                                                randomnessByColumn[
                                                    rowIndex %
                                                        randomnessByColumn.length
                                                ]?.[coefficientIndex] ?? 0;
                                            const modulus =
                                                qSharePrimes[
                                                    commitmentLimbPosition
                                                ] ?? qSharePrimes[0];
                                            return Number(
                                                (BigInt(messageCoefficient) +
                                                    BigInt(
                                                        randomnessCoefficient,
                                                    ) +
                                                    BigInt(modulus)) %
                                                    BigInt(modulus),
                                            );
                                        },
                                    ),
                            ),
                        }),
                    ),
                },
            };
        },
        release: (capability) => {
            if (!activeTestOpeningCapabilities.delete(capability)) {
                throw new Error(
                    'structured-commitment opening capability is not active in this scope',
                );
            }
        },
        revoke: () => {
            activeTestOpeningCapabilities.clear();
        },
    });

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
    structuredCommitmentOpenings,
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
                sourceSetupIntentObjectHash: fixtureHash(
                    `setup-intent-${String(sourceTrusteeRosterPosition)}`,
                ),
                structuredCommitmentOpenings,
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
    commitmentLimbPosition: number,
    randomnessColumnIndex: number,
): readonly number[] => {
    const openingRecord = testOpeningRecords.get(
        openingState.openingCapability,
    );
    if (openingRecord === undefined) {
        throw new Error('fixture opaque opening record is missing');
    }
    const randomnessByColumn = requiredItem(
        openingRecord.randomnessByCommitmentLimb,
        commitmentLimbPosition,
        'fixture commitment-limb randomness tape is missing',
    );
    return requiredItem(
        randomnessByColumn,
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
): readonly (-1 | 0 | 1)[] => {
    const rnsPrime = requiredItem(
        qSharePrimes,
        openingState.rnsLimbIndex,
        'fixture opening RNS limb is outside Q_share',
    );

    return openingState.coefficientMessage.map((coefficient) => {
        if (coefficient === 0) {
            return 0;
        }
        if (coefficient === 1) {
            return 1;
        }
        if (coefficient === rnsPrime - 1) {
            return -1;
        }
        throw new Error(
            'constant Shamir coefficient is not a centered ternary residue',
        );
    });
};

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
        name: 'opening capability from another worker scope',
        expectedMessage: /not active in this scope/u,
        input: () =>
            mutateFirstOpening((openingState) => ({
                ...openingState,
                openingCapability: Object.freeze(
                    {},
                ) as unknown as ClosedWorkerStructuredCommitmentOpeningCapability,
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
    sourceSetupIntentObjectHash: fixtureHash('setup-intent-0'),
    structuredCommitmentOpenings,
    ...overrides,
});

const invalidOpeningStateGenerationCases = [
    {
        name: 'source trustee outside the roster',
        expectedMessage: /inside the accepted participant count/u,
        input: () =>
            openingStateGenerationInput({
                sourceTrusteeIdentity: sourceTrusteeIdentity(participantCount),
                sourceTrusteeRosterPosition: participantCount,
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
                    coefficient <
                        requiredItem(
                            qSharePrimes,
                            nonConstantOpening.rnsLimbIndex,
                            'fixture opening RNS limb is outside Q_share',
                        ),
            ),
        ).toBe(true);
        const firstOpeningRecord = testOpeningRecords.get(
            requiredOpeningByCoordinate(generatedSourceTrusteeState, 0, 0)
                .openingCapability,
        );
        expect(firstOpeningRecord).toBeDefined();
        expect(firstOpeningRecord?.randomnessByCommitmentLimb).toHaveLength(
            setupCommitmentModulusLimbCount,
        );
        expect(
            requiredItem(
                firstOpeningRecord?.randomnessByCommitmentLimb ?? [],
                0,
                'fixture commitment-limb randomness tape is missing',
            ),
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
        const recomputedCommitment =
            structuredCommitmentOpenings.computeCommitment({
                capability: firstOpening.openingCapability,
                messageCoefficients: firstOpening.coefficientMessage,
                publicMatrixSeedHash,
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
