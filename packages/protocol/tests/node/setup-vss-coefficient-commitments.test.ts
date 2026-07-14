import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createVssSourceTrusteeCoefficientOpeningState,
    createVssSourceTrusteeCoefficientOpeningStateProvider,
    createVssCoefficientCommitmentBundle,
    setupCommitmentRandomnessWidth,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/index';
import {
    RandomByteSampler,
    maximumPrivateSamplerCandidateDrawsPerOutput,
    sampleCenteredTernaryVector,
    sampleUniformResidueVector,
} from '#packages/protocol/src/setup/vss-coefficient-commitments/encoding';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    makeSetupContext,
    makeSetupFixtureHash,
    makeVssOpeningRandomBytes,
} from '#tests/support/setup-fixtures';

const qSharePrimes = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
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

const setupContext = makeSetupContext(fixtureHash, participantCount);
const setupContextHash = deriveCanonicalObjectHash({
    objectType: 'CollectiveBgvSetupContext',
    ...setupContext,
});
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
    ...setupParameters,
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
    createVssSourceTrusteeCoefficientOpeningState({
        ...sourceTrusteeReference(sourceTrusteeRosterPosition),
        ...setupParameters,
        randomBytes: deterministicRandomBytes(
            `opening-${sourceTrusteeIdentity(sourceTrusteeRosterPosition)}`,
        ),
    });

const sourceTrusteeOpeningStates =
    (): readonly VssSourceTrusteeCoefficientOpeningState[] => [
        sourceTrusteeOpeningState(0),
        sourceTrusteeOpeningState(1),
    ];

const coefficientCommitmentBundleInput = (
    openingStates: readonly VssSourceTrusteeCoefficientOpeningState[] = sourceTrusteeOpeningStates(),
): Parameters<typeof createVssCoefficientCommitmentBundle>[0] => ({
    ...coefficientCommitmentInput,
    sourceTrusteeOpeningStates: openingStates,
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

const mutateFirstSourceTrustee = (
    mutate: (
        sourceTrusteeState: VssSourceTrusteeCoefficientOpeningState,
    ) => VssSourceTrusteeCoefficientOpeningState,
): readonly VssSourceTrusteeCoefficientOpeningState[] => {
    const openingStates = sourceTrusteeOpeningStates();
    return [
        mutate(
            requiredItem(
                openingStates,
                0,
                'first source trustee fixture is missing',
            ),
        ),
        ...openingStates.slice(1),
    ];
};

const mutateFirstOpening = (
    mutate: (
        openingState: VssCoefficientOpeningInput,
    ) => VssCoefficientOpeningInput,
): readonly VssSourceTrusteeCoefficientOpeningState[] =>
    mutateFirstSourceTrustee((sourceTrusteeState) => ({
        ...sourceTrusteeState,
        coefficientOpenings: [
            mutate(requiredOpening(sourceTrusteeState, 0)),
            ...sourceTrusteeState.coefficientOpenings.slice(1),
        ],
    }));

const malformedCoefficientCommitmentBundleCases = [
    {
        name: 'missing participant',
        expectedMessage: /every accepted participant/u,
        input: () => sourceTrusteeOpeningStates().slice(0, 1),
    },
    {
        name: 'duplicate opening coordinate',
        expectedMessage: /distinct limb\/coefficient coordinates/u,
        input: () =>
            mutateFirstSourceTrustee((sourceTrusteeState) => ({
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
] as const satisfies readonly RejectionCase<
    readonly VssSourceTrusteeCoefficientOpeningState[]
>[];

const openingStateGenerationInput = (
    overrides: Partial<
        Parameters<typeof createVssSourceTrusteeCoefficientOpeningState>[0]
    > = {},
): Parameters<typeof createVssSourceTrusteeCoefficientOpeningState>[0] => ({
    ...sourceTrusteeReference(0),
    ...setupParameters,
    randomBytes: deterministicRandomBytes('trustee-0'),
    ...overrides,
});

const sourceTrusteeReferences = [
    sourceTrusteeReference(0),
    sourceTrusteeReference(1),
] as const;

const sourceTrusteeOpeningStateProviderInput = (
    sourceTrustees: Parameters<
        typeof createVssSourceTrusteeCoefficientOpeningStateProvider
    >[0]['sourceTrustees'] = sourceTrusteeReferences,
): Parameters<
    typeof createVssSourceTrusteeCoefficientOpeningStateProvider
>[0] => ({
    sourceTrustees,
    ...setupParameters,
    randomBytesForSourceTrustee: (sourceTrustee) =>
        deterministicRandomBytes(
            `provider-${sourceTrustee.sourceTrusteeIdentity}`,
        ),
});

const invalidOpeningStateGenerationCases = [
    {
        name: 'source trustee outside the roster',
        expectedMessage: /inside the accepted participant count/u,
        input: () =>
            openingStateGenerationInput({
                sourceTrusteeIdentity: 'trustee-2',
                sourceTrusteeRosterPosition: 2,
                randomBytes: deterministicRandomBytes('trustee-2'),
            }),
    },
    {
        name: 'empty RNS basis',
        expectedMessage: /at least one RNS prime/u,
        input: () => openingStateGenerationInput({ qSharePrimes: [] }),
    },
    {
        name: 'short randomness response',
        expectedMessage: /exactly the requested byte length/u,
        input: () =>
            openingStateGenerationInput({
                randomBytes: (byteLength) =>
                    new Uint8Array(Math.max(0, byteLength - 1)),
            }),
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
        const generatedSourceTrusteeState =
            createVssSourceTrusteeCoefficientOpeningState(
                openingStateGenerationInput(),
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

    it('loads deterministic source openings through a provider and rejects non-contiguous rosters', () => {
        const sourceTrusteeOpeningStateProvider =
            createVssSourceTrusteeCoefficientOpeningStateProvider({
                ...sourceTrusteeOpeningStateProviderInput(),
            });

        expect(
            sourceTrusteeOpeningStateProvider.loadSourceTrusteeOpeningState(
                sourceTrusteeReferences[0],
            ),
        ).toEqual(
            sourceTrusteeOpeningStateProvider.loadSourceTrusteeOpeningState(
                sourceTrusteeReferences[0],
            ),
        );

        expect(() =>
            createVssSourceTrusteeCoefficientOpeningStateProvider({
                ...sourceTrusteeOpeningStateProviderInput([
                    sourceTrusteeReferences[0],
                    sourceTrusteeReferences[0],
                ]),
            }),
        ).toThrow(/contiguous from zero/u);
    });

    it('creates deterministic commitment records from local openings', () => {
        const bundle = createVssCoefficientCommitmentBundle(
            coefficientCommitmentBundleInput([
                sourceTrusteeOpeningState(1),
                sourceTrusteeOpeningState(0),
            ]),
        );
        const { vssCoefficientCommitmentRoot, ...commitmentSetWithoutRoot } =
            bundle.commitmentSet;
        const firstMaterialRecord =
            bundle.privateOpeningMaterialBySourceTrustee[0]
                ?.sourceTrusteeCoefficientCommitmentMaterialRecords[0];
        const firstOpening = requiredOpening(sourceTrusteeOpeningState(0), 0);

        expect(
            bundle.commitmentSet.sourceTrusteeRecords.map(
                (record) => record.sourceTrusteeRosterPosition,
            ),
        ).toEqual([0, 1]);
        expect(bundle.commitmentSet.setupContextHash).toBe(setupContextHash);
        expect(vssCoefficientCommitmentRoot).toBe(
            deriveCanonicalObjectHash(commitmentSetWithoutRoot),
        );
        expect(firstMaterialRecord?.commitmentRoot).toBe(
            setupCommitmentComputer({
                publicMatrixSeedHash,
                sourceRnsLimbIndex: firstOpening.rnsLimbIndex,
                sourceMessageModulus: firstOpening.rnsPrime,
                shamirCoefficientIndex: firstOpening.shamirCoefficientIndex,
                messageCoefficients: firstOpening.coefficientMessage,
                randomnessByColumn: firstOpening.randomnessByColumn,
                ringDegree,
            }).commitmentRoot,
        );
        expect(
            bundle.privateOpeningMaterialBySourceTrustee[0]
                ?.coefficientOpenings[0]?.commitmentRoot,
        ).toBe(firstMaterialRecord?.commitmentRoot);
    });

    it.each(malformedCoefficientCommitmentBundleCases)(
        'rejects malformed local opening state before root publication: $name',
        ({ expectedMessage, input }) => {
            expect(() =>
                createVssCoefficientCommitmentBundle(
                    coefficientCommitmentBundleInput(input()),
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
