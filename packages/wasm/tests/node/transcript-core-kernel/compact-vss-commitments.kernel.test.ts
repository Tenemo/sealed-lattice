import { describe, expect, it } from 'vitest';

import { deriveProtocolHash, hash512Hex } from '#packages/crypto/src/index';
import {
    combineCompactVssCommitments,
    compactVssCommitmentBinaryFormat,
    compactVssCommitmentPrivateOpeningRoot,
    compactVssEncodedCommitmentByteLength,
    compactVssCommitmentProfileId,
    compactVssCommitmentRandomnessColumnCount,
    compactVssShareLinkageAggregateThresholdRule,
    compactVssShareLinkageCommonKeyRule,
    compactVssShareLinkageProofBatchingRule,
    compactVssShareLinkageShamirEvaluationRule,
    computeCompactVssCommitmentFromOpening,
    createCompactVssShareLinkageStatement,
    decodeCompactVssCommitmentBody,
    encodeCompactVssCommitmentBody,
    verifyCompactVssAggregateThresholdCommitmentSet,
    verifyCompactVssCoefficientCommitmentSet,
    verifyCompactVssRecipientShareCommitmentSet,
    verifyCompactVssShareLinkageStatement,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssCommitmentBodyMetadata,
    type CompactVssCommitmentLimb,
    type CompactVssCommitmentRole,
    type CompactVssCommitmentValue,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssShareLinkageStatement,
} from '#packages/protocol/src/setup/compact-vss-commitments';
import {
    createBinaryChunkedSameSecretProofMaterialTransport,
    createCompactVssSameSecretBridgeProofMaterialSet,
    compactVssSameSecretBridgeIntegerSupport,
    compactVssSameSecretBridgeSignedRepresentativeConvention,
    compactVssSameSecretBridgeTargetBasisLimbOrder,
    verifyCompactVssSameSecretBridgeProofMaterialSet,
    verifyCompactVssSameSecretBridgeStatementSet,
    type CompactVssSameSecretBridgeStatementRecord,
    type CompactVssSameSecretBridgeStatementSet,
    type SameSecretConsistencyStatementSet,
    type SameSecretProofSet,
    type TransportedSameSecretProofMaterialSet,
} from '#packages/protocol/src/setup/same-secret-consistency-records';
import { acceptedBgvSetupQSharePrimes } from '#packages/protocol/src/setup/vss-coefficient-commitments';
import type { CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';
import {
    TranscriptCoreKernelCommandError,
    type BgvCompactSameSecretBridgeProofStatement,
    type BgvCompactVssCommitmentOpeningInput,
    type BgvCompactVssShareLinkageProofStatement,
    type BgvTrusteeEvaluationKeyStatementContext,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/transcript-core-bridge';

type CompactSameSecretBridgeEvidence = {
    readonly statementSet: CompactVssSameSecretBridgeStatementSet;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly transportedSameSecretProofMaterial?: TransportedSameSecretProofMaterialSet;
};

type CompactVssCommitmentWithLimbs = Readonly<
    Record<string, unknown> & {
        readonly commitmentLimbs: readonly CompactVssCommitmentLimb[];
    }
>;

const isCompactVssCommitmentLimb = (
    value: unknown,
): value is CompactVssCommitmentLimb => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }
    const limb = value as Readonly<Record<string, unknown>>;
    const coordinates = limb.coordinates;
    if (
        typeof limb.commitmentModulusIndex !== 'number' ||
        typeof limb.modulus !== 'number' ||
        !Array.isArray(coordinates)
    ) {
        return false;
    }

    const coordinateValues: readonly unknown[] = coordinates;
    return coordinateValues.every(
        (coordinateValue) => typeof coordinateValue === 'number',
    );
};

const isCompactVssCommitmentWithLimbs = (
    value: unknown,
): value is CompactVssCommitmentWithLimbs => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }
    const commitment = value as Readonly<Record<string, unknown>>;
    const commitmentLimbs = commitment.commitmentLimbs;
    if (!Array.isArray(commitmentLimbs)) {
        return false;
    }

    const limbValues: readonly unknown[] = commitmentLimbs;
    return limbValues.every(isCompactVssCommitmentLimb);
};

const compactVssSetupContext = (): CollectiveBgvSetupContext => ({
    ceremonyId: 'compact-vss-wasm-test',
    manifestHash: '1'.repeat(128),
    rosterHash: '2'.repeat(128),
    setupProfileHash: '3'.repeat(128),
    qShareHash: '4'.repeat(128),
    carryAwareVssShareRelationProfileHash: '5'.repeat(128),
    commitmentProfileHash: '6'.repeat(128),
    setupEpoch: 'setup-epoch',
});

const compactVssOpening = (): BgvCompactVssCommitmentOpeningInput => ({
    commitmentRole: 'aggregate-threshold-share',
    commitmentContext: {
        objectType: 'CompactVssAggregateThresholdShareCommitmentContext',
        objectVersion: 1,
        ceremonyId: 'compact-vss-wasm-test',
        manifestHash: '1'.repeat(128),
        rosterHash: '2'.repeat(128),
        setupProfileHash: '3'.repeat(128),
        qShareHash: '4'.repeat(128),
        carryAwareVssShareRelationProfileHash: '5'.repeat(128),
        commitmentProfileHash: '6'.repeat(128),
        setupEpoch: 'setup-epoch',
        recipientIdentity: 'trustee-1',
        recipientRosterPosition: 0,
        rnsLimbIndex: 0,
        rnsPrime: 97,
    },
    publicMatrixSeedHash: '7'.repeat(128),
    rnsLimbIndex: 0,
    rnsPrime: 97,
    ringDegree: 8,
    messageCoefficients: [1, 2, 3, 4, 5, 6, 7, 8],
    randomnessByColumn: [
        [0, 1, -1, 2, -2, 3, -3, 4],
        [5, -5, 6, -6, 7, -7, 8, -8],
    ],
});

const writeTestLittleEndianU64 = (
    bytes: Uint8Array,
    offset: number,
    value: number,
): void => {
    let remainingValue = BigInt(value);
    for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
        bytes[offset + byteIndex] = Number(remainingValue & 0xffn);
        remainingValue >>= 8n;
    }
};

type CompactVssSourceCoefficientCommitments =
    CompactVssCoefficientCommitmentSet['sourceTrusteeRecords'][number];
type CompactVssCoefficientCommitment =
    CompactVssSourceCoefficientCommitments['coefficientCommitments'][number];
type CompactVssSourceRecipientShareCommitments =
    CompactVssRecipientShareCommitmentSet['sourceTrusteeRecords'][number];
type CompactVssRecipientShareCommitment =
    CompactVssSourceRecipientShareCommitments['recipientShareCommitments'][number];
type CompactVssAggregateThresholdCommitment =
    CompactVssAggregateThresholdCommitmentSet['recipientRecords'][number];

const compactVssParticipantCount = 2;
const compactVssRnsLimbCount = 2;
const compactVssThresholdDegree = 2;
const compactVssRingDegree = 8;

const compactVssPublicMatrixSeedHash = (): string => '7'.repeat(128);
const canonicalTargetCiphertextLevel = 6;
const selectedEvaluatorWorkingLevel = 15;
const canonicalTargetBasisHash = (): string =>
    deriveProtocolHash('TargetBasisHash', {
        objectType: 'CanonicalTargetBasis',
        objectVersion: 1,
        basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
        targetLevel: canonicalTargetCiphertextLevel,
        primeOrder: 'profile-order-prefix',
        targetPrimes: acceptedBgvSetupQSharePrimes.slice(
            0,
            canonicalTargetCiphertextLevel + 1,
        ),
        modulusSwitchSchedule: {
            sourceWorkingLevel: selectedEvaluatorWorkingLevel,
            terminalLevel: canonicalTargetCiphertextLevel,
            rule: 'drop trailing data-basis primes until the terminal target level is reached',
        },
        scalingNormalization:
            'normalize ciphertext decrypt scaling to one before target roots are computed',
        targetCiphertextRule:
            'target id and target order ciphertexts must both use the canonical target level',
    });

const compactVssRnsPrime = (rnsLimbIndex: number): number =>
    rnsLimbIndex === 0 ? 97 : 193;

const compactVssSeed = (seedParts: readonly number[]): number =>
    seedParts.reduce((seed, seedPart) => seed * 31 + seedPart + 1, 0);

const compactVssTestHashFromSeed = (
    seed: number,
    domainOffset: number,
): string => ((seed + domainOffset) % 16).toString(16).repeat(128);

const compactVssMessageCoefficients = (
    seed: number,
    modulus: number,
): number[] =>
    Array.from(
        { length: compactVssRingDegree },
        (_unused, coefficientIndex) =>
            (seed * 17 + (coefficientIndex + 1) * 19) % modulus,
    );

const compactVssRandomnessByColumn = (seed: number): number[][] =>
    Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        (_unusedColumn, columnIndex) =>
            Array.from(
                { length: compactVssRingDegree },
                (_unusedCoefficient, coefficientIndex) => {
                    const magnitude =
                        (seed + columnIndex * 11 + coefficientIndex * 7) % 29;
                    return (seed + columnIndex + coefficientIndex) % 2 === 0
                        ? magnitude
                        : -magnitude;
                },
            ),
    );

const compactVssTestCommitment = (
    commitmentRole: CompactVssCommitmentRole,
    rnsLimbIndex: number,
    rnsPrime: number,
    seedParts: readonly number[],
): ReturnType<typeof computeCompactVssCommitmentFromOpening> &
    Readonly<{ openingRoot: string }> => {
    const seed = compactVssSeed(seedParts);
    const opening = {
        commitmentRole,
        commitmentContext: {
            objectType: 'CompactVssTestCommitmentContext',
            objectVersion: 1,
            commitmentRole,
            seedHash: compactVssTestHashFromSeed(seed, 9),
        },
        publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
        rnsLimbIndex,
        rnsPrime,
        ringDegree: compactVssRingDegree,
        messageCoefficients: compactVssMessageCoefficients(seed, rnsPrime),
        messageCoefficientBound: rnsPrime,
        randomnessByColumn: compactVssRandomnessByColumn(seed),
    } as const;
    const commitment = computeCompactVssCommitmentFromOpening(opening);

    return {
        ...commitment,
        openingRoot: compactVssCommitmentPrivateOpeningRoot(opening),
    };
};

const compactCoefficientCommitment = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): CompactVssCoefficientCommitment => {
    const rnsPrime = compactVssRnsPrime(rnsLimbIndex);
    const commitment = compactVssTestCommitment(
        'coefficient',
        rnsLimbIndex,
        rnsPrime,
        [sourceTrusteeRosterPosition, rnsLimbIndex, shamirCoefficientIndex, 0],
    );

    return {
        objectType: 'CompactVssCoefficientCommitment',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
        sourceTrusteeRosterPosition,
        publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
        rnsLimbIndex,
        rnsPrime,
        shamirCoefficientIndex,
        coefficientCommitmentRoot: commitment.commitmentRoot,
        coefficientOpeningRoot: commitment.openingRoot,
        commitment: commitment.commitment,
    };
};

const compactSourceCoefficientRecord = (
    sourceTrusteeRosterPosition: number,
): CompactVssSourceCoefficientCommitments => {
    const coefficientCommitments = [0, 1].flatMap((rnsLimbIndex) =>
        [0, 1].map((shamirCoefficientIndex) =>
            compactCoefficientCommitment(
                sourceTrusteeRosterPosition,
                rnsLimbIndex,
                shamirCoefficientIndex,
            ),
        ),
    );
    const sourceRecordWithoutRoot = {
        objectType: 'CompactVssSourceCoefficientCommitments',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
        sourceTrusteeRosterPosition,
        publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
        coefficientCommitments,
    } as const;

    return {
        ...sourceRecordWithoutRoot,
        sourceCoefficientCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
            sourceRecordWithoutRoot,
        ),
    };
};

const compactCoefficientCommitmentSet =
    (): CompactVssCoefficientCommitmentSet => {
        const sourceTrusteeRecords = [
            compactSourceCoefficientRecord(0),
            compactSourceCoefficientRecord(1),
        ];
        const setWithoutRoot = {
            objectType: 'CompactVssCoefficientCommitmentSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: compactVssCommitmentProfileId,
            publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
            participantCount: compactVssParticipantCount,
            rnsLimbCount: compactVssRnsLimbCount,
            thresholdDegree: compactVssThresholdDegree,
            ringDegree: compactVssRingDegree,
            sourceTrusteeRecords,
        } as const;

        return {
            ...setWithoutRoot,
            coefficientCommitmentRoot: deriveProtocolHash(
                'VssCoefficientCommitmentRoot',
                setWithoutRoot,
            ),
        };
    };

const compactRecipientShareCommitment = (
    sourceTrusteeRosterPosition: number,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): CompactVssRecipientShareCommitment => {
    const rnsPrime = compactVssRnsPrime(rnsLimbIndex);
    const commitment = compactVssTestCommitment(
        'recipient-share',
        rnsLimbIndex,
        rnsPrime,
        [sourceTrusteeRosterPosition, recipientRosterPosition, rnsLimbIndex, 1],
    );

    return {
        objectType: 'CompactVssRecipientShareCommitment',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
        sourceTrusteeRosterPosition,
        recipientIdentity: `recipient-${recipientRosterPosition}`,
        recipientRosterPosition,
        recipientTrusteePoint: recipientRosterPosition + 1,
        rnsLimbIndex,
        rnsPrime,
        shareCommitmentRoot: commitment.commitmentRoot,
        shareOpeningRoot: commitment.openingRoot,
        commitment: commitment.commitment,
    };
};

const compactSourceRecipientShareRecord = (
    sourceTrusteeRosterPosition: number,
): CompactVssSourceRecipientShareCommitments => {
    const recipientShareCommitments = [0, 1].flatMap(
        (recipientRosterPosition) =>
            [0, 1].map((rnsLimbIndex) =>
                compactRecipientShareCommitment(
                    sourceTrusteeRosterPosition,
                    recipientRosterPosition,
                    rnsLimbIndex,
                ),
            ),
    );
    const sourceRecordWithoutRoot = {
        objectType: 'CompactVssSourceRecipientShareCommitments',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        sourceTrusteeIdentity: `source-${sourceTrusteeRosterPosition}`,
        sourceTrusteeRosterPosition,
        recipientShareCommitments,
    } as const;

    return {
        ...sourceRecordWithoutRoot,
        sourceRecipientShareCommitmentRoot: deriveProtocolHash(
            'ThresholdShareCommitmentRoot',
            sourceRecordWithoutRoot,
        ),
    };
};

const compactRecipientShareCommitmentSet =
    (): CompactVssRecipientShareCommitmentSet => {
        const sourceTrusteeRecords = [
            compactSourceRecipientShareRecord(0),
            compactSourceRecipientShareRecord(1),
        ];
        const setWithoutRoot = {
            objectType: 'CompactVssRecipientShareCommitmentSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: compactVssCommitmentProfileId,
            publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
            participantCount: compactVssParticipantCount,
            rnsLimbCount: compactVssRnsLimbCount,
            ringDegree: compactVssRingDegree,
            sourceTrusteeRecords,
        } as const;

        return {
            ...setWithoutRoot,
            recipientShareCommitmentRoot: deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                setWithoutRoot,
            ),
        };
    };

const compactSourceShareRecordsForRecipient = (
    recipientSet: CompactVssRecipientShareCommitmentSet,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): CompactVssRecipientShareCommitment[] => {
    const recipientShareRecordIndex =
        recipientRosterPosition * compactVssRnsLimbCount + rnsLimbIndex;

    return recipientSet.sourceTrusteeRecords.map((sourceRecord) => {
        const recipientShareRecord =
            sourceRecord.recipientShareCommitments[recipientShareRecordIndex];
        if (recipientShareRecord === undefined) {
            throw new Error(
                'compact VSS fixture recipient-share record is missing.',
            );
        }

        return recipientShareRecord;
    });
};

const compactAggregateCommitmentBody = (
    recipientRosterPosition: number,
    rnsLimbIndex: number,
    rnsPrime: number,
    sourceShareRecords: readonly CompactVssRecipientShareCommitment[],
): ReturnType<typeof combineCompactVssCommitments>['commitment'] => {
    return combineCompactVssCommitments({
        commitmentRole: 'aggregate-threshold-share',
        commitmentContext: {
            objectType: 'CompactVssAggregateThresholdShareCommitmentContext',
            objectVersion: 1,
            recipientIdentity: `recipient-${recipientRosterPosition}`,
            recipientRosterPosition,
            recipientTrusteePoint: recipientRosterPosition + 1,
            rnsLimbIndex,
            rnsPrime,
        },
        terms: sourceShareRecords.map((sourceShareRecord) => ({
            commitment: sourceShareRecord.commitment,
            scalar: 1,
        })),
    }).commitment;
};

const compactAggregateThresholdCommitment = (
    recipientSet: CompactVssRecipientShareCommitmentSet,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): CompactVssAggregateThresholdCommitment => {
    const rnsPrime = compactVssRnsPrime(rnsLimbIndex);
    const sourceShareRecords = compactSourceShareRecordsForRecipient(
        recipientSet,
        recipientRosterPosition,
        rnsLimbIndex,
    );
    const commitment = compactAggregateCommitmentBody(
        recipientRosterPosition,
        rnsLimbIndex,
        rnsPrime,
        sourceShareRecords,
    );

    return {
        objectType: 'CompactVssAggregateThresholdCommitment',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        recipientIdentity: `recipient-${recipientRosterPosition}`,
        recipientRosterPosition,
        recipientTrusteePoint: recipientRosterPosition + 1,
        rnsLimbIndex,
        rnsPrime,
        aggregateCommitmentRoot: deriveProtocolHash(
            'SetupCommitmentRoot',
            commitment,
        ),
        aggregateOpeningRoot: compactVssTestHashFromSeed(
            compactVssSeed([recipientRosterPosition, rnsLimbIndex, 5]),
            0,
        ),
        commitment,
        sourceShareCommitmentRoots: sourceShareRecords.map(
            (sourceShareRecord) => sourceShareRecord.shareCommitmentRoot,
        ),
        sourceShareOpeningRoots: sourceShareRecords.map(
            (sourceShareRecord) => sourceShareRecord.shareOpeningRoot,
        ),
    };
};

const compactAggregateThresholdCommitmentSet =
    (): CompactVssAggregateThresholdCommitmentSet => {
        const recipientSet = compactRecipientShareCommitmentSet();
        const recipientRecords = [0, 1].flatMap((recipientRosterPosition) =>
            [0, 1].map((rnsLimbIndex) =>
                compactAggregateThresholdCommitment(
                    recipientSet,
                    recipientRosterPosition,
                    rnsLimbIndex,
                ),
            ),
        );
        const setWithoutRoot = {
            objectType: 'CompactVssAggregateThresholdCommitmentSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: compactVssCommitmentProfileId,
            publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
            participantCount: compactVssParticipantCount,
            rnsLimbCount: compactVssRnsLimbCount,
            ringDegree: compactVssRingDegree,
            recipientRecords,
        } as const;

        return {
            ...setWithoutRoot,
            aggregateThresholdCommitmentRoot: deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                setWithoutRoot,
            ),
        };
    };

type CompactShareLinkageEvidence = {
    readonly statement: CompactVssShareLinkageStatement;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
};

const compactShareLinkageEvidence = (): CompactShareLinkageEvidence => {
    const coefficientCommitmentSet = compactCoefficientCommitmentSet();
    const recipientShareCommitmentSet = compactRecipientShareCommitmentSet();
    const aggregateThresholdCommitmentSet =
        compactAggregateThresholdCommitmentSet();
    const statement = createCompactVssShareLinkageStatement({
        setupContext: compactVssSetupContext(),
        publicMatrixSeedHash: compactVssPublicMatrixSeedHash(),
        targetBasisHash: canonicalTargetBasisHash(),
        coefficientCommitmentSet,
        recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
    });

    return {
        statement,
        coefficientCommitmentSet,
        recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
    };
};

const compactSameSecretBridgeStatementRecord = (
    trusteeRosterPosition: number,
): CompactVssSameSecretBridgeStatementRecord => {
    const targetBasisHash = canonicalTargetBasisHash();
    const publicMatrixSeedHash = '8'.repeat(128);
    const targetConstantCoefficientRecords = [0, 1].map((rnsLimbIndex) => {
        const rnsPrime = acceptedBgvSetupQSharePrimes[rnsLimbIndex];
        if (rnsPrime === undefined) {
            throw new Error(
                'compact bridge statement fixture is missing a target RNS prime.',
            );
        }
        const seed = compactVssSeed([71, trusteeRosterPosition, rnsLimbIndex]);
        const targetConstantCommitment = computeCompactVssCommitmentFromOpening(
            {
                commitmentRole: 'coefficient',
                commitmentContext: {
                    objectType: 'CompactSameSecretBridgeTargetConstantContext',
                    objectVersion: 1,
                    sourceTrusteeRosterPosition: trusteeRosterPosition,
                    rnsLimbIndex,
                },
                publicMatrixSeedHash,
                rnsLimbIndex,
                rnsPrime,
                ringDegree: compactVssRingDegree,
                messageCoefficients: compactVssMessageCoefficients(
                    seed,
                    rnsPrime,
                ),
                messageCoefficientBound: rnsPrime,
                randomnessByColumn: compactVssRandomnessByColumn(seed),
            },
        );

        return {
            root: {
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex: 0 as const,
                coefficientCommitmentRoot:
                    targetConstantCommitment.commitmentRoot,
            },
            commitment: {
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex: 0 as const,
                commitment: targetConstantCommitment.commitment,
            },
        };
    });
    const statementWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        compactCommitmentProfileId:
            'sealed-lattice-compact-vss-sparse-linear-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'same-secret-linkage-anchor',
        ceremonyId: 'compact-vss-wasm-test',
        manifestHash: '1'.repeat(128),
        rosterHash: '2'.repeat(128),
        setupProfileHash: '3'.repeat(128),
        qShareHash: '4'.repeat(128),
        carryAwareVssShareRelationProfileHash: '5'.repeat(128),
        commitmentProfileHash: '6'.repeat(128),
        setupEpoch: 'setup-epoch',
        targetBasisHash,
        publicMatrixSeedHash,
        ringDegree: compactVssRingDegree,
        trusteeIdentity: `trustee-${trusteeRosterPosition}`,
        trusteeRosterPosition,
        sameSecretStatementRoot:
            trusteeRosterPosition === 0 ? '9'.repeat(128) : 'a'.repeat(128),
        sameSecretProofRoot:
            trusteeRosterPosition === 0 ? 'b'.repeat(128) : 'c'.repeat(128),
        trusteeSecretCommitmentRoot:
            trusteeRosterPosition === 0 ? 'd'.repeat(128) : 'e'.repeat(128),
        sameSecretProofFamilyBindingRoot: 'f'.repeat(128),
        dataBasisRelation:
            'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs',
        integerSupport: compactVssSameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            compactVssSameSecretBridgeSignedRepresentativeConvention,
        compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
        targetBasisLimbOrder: compactVssSameSecretBridgeTargetBasisLimbOrder,
        targetConstantCoefficientCommitmentRoots:
            targetConstantCoefficientRecords.map((record) => record.root),
        targetConstantCoefficientCommitments:
            targetConstantCoefficientRecords.map((record) => record.commitment),
        relation:
            'target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof',
    } as const;

    return {
        ...statementWithoutRoot,
        compactSameSecretBridgeStatementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementWithoutRoot,
        ),
    };
};

const compactSameSecretBridgeStatementSet =
    (): CompactVssSameSecretBridgeStatementSet => {
        const statementRecords = [
            compactSameSecretBridgeStatementRecord(0),
            compactSameSecretBridgeStatementRecord(1),
        ];
        const targetBasisHash = canonicalTargetBasisHash();
        const statementSetWithoutRoot = {
            objectType: 'CompactVssSameSecretBridgeStatementSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            compactCommitmentProfileId:
                'sealed-lattice-compact-vss-sparse-linear-v1',
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofFamily: 'same-secret-linkage-anchor',
            ceremonyId: 'compact-vss-wasm-test',
            manifestHash: '1'.repeat(128),
            rosterHash: '2'.repeat(128),
            setupProfileHash: '3'.repeat(128),
            qShareHash: '4'.repeat(128),
            carryAwareVssShareRelationProfileHash: '5'.repeat(128),
            commitmentProfileHash: '6'.repeat(128),
            setupEpoch: 'setup-epoch',
            targetBasisHash,
            publicMatrixSeedHash: '8'.repeat(128),
            ringDegree: compactVssRingDegree,
            participantCount: 2,
            targetRnsLimbCount: 2,
            thresholdDegree: 4,
            compactCoefficientCommitmentRoot: '9'.repeat(128),
            sameSecretConsistencyRoot: 'a'.repeat(128),
            sameSecretProofSetRoot: 'b'.repeat(128),
            sameSecretProofFamilyBindingRoot: 'f'.repeat(128),
            integerSupport: compactVssSameSecretBridgeIntegerSupport,
            signedRepresentativeConvention:
                compactVssSameSecretBridgeSignedRepresentativeConvention,
            compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
            targetBasisLimbOrder:
                compactVssSameSecretBridgeTargetBasisLimbOrder,
            statementRecords,
        } as const;

        return {
            ...statementSetWithoutRoot,
            compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
                'SetupProofRecordBindingHash',
                statementSetWithoutRoot,
            ),
        };
    };

const compactSameSecretBridgeContext = (
    statementSet: CompactVssSameSecretBridgeStatementSet,
): Readonly<Record<string, unknown>> => ({
    ceremonyId: statementSet.ceremonyId,
    manifestHash: statementSet.manifestHash,
    rosterHash: statementSet.rosterHash,
    setupProfileHash: statementSet.setupProfileHash,
    qShareHash: statementSet.qShareHash,
    carryAwareVssShareRelationProfileHash:
        statementSet.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: statementSet.commitmentProfileHash,
    setupEpoch: statementSet.setupEpoch,
});

const sameSecretProofBytesHashDomain =
    'sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1';

const sameSecretProofBytesHash = (proofBytesHex: string): string =>
    hash512Hex(sameSecretProofBytesHashDomain, [
        Buffer.from(proofBytesHex, 'hex'),
    ]);

const rebindCompactSameSecretBridgeStatementRecord = (
    statementRecord: Omit<
        CompactVssSameSecretBridgeStatementRecord,
        'compactSameSecretBridgeStatementRoot'
    >,
): CompactVssSameSecretBridgeStatementRecord =>
    ({
        ...statementRecord,
        compactSameSecretBridgeStatementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementRecord,
        ),
    }) as CompactVssSameSecretBridgeStatementRecord;

const rebindCompactSameSecretBridgeStatementSet = (
    statementSet: Omit<
        CompactVssSameSecretBridgeStatementSet,
        'compactSameSecretBridgeStatementSetRoot'
    >,
): CompactVssSameSecretBridgeStatementSet =>
    ({
        ...statementSet,
        compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementSet,
        ),
    }) as CompactVssSameSecretBridgeStatementSet;

const compactSameSecretBridgeStatementSetWithEvidence =
    (): CompactSameSecretBridgeEvidence => {
        const baseStatementSet = compactSameSecretBridgeStatementSet();
        const context = compactSameSecretBridgeContext(baseStatementSet);
        const sameSecretStatementRecords =
            baseStatementSet.statementRecords.map((bridgeStatement) => {
                const statementWithoutRoot = {
                    objectType: 'SameSecretConsistencyStatement',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
                    setupProofProfileId: 'SealedLattice-SetupProof-v1',
                    proofFamily: 'same-secret-linkage-anchor',
                    ...context,
                    trusteeIdentity: bridgeStatement.trusteeIdentity,
                    trusteeRosterPosition:
                        bridgeStatement.trusteeRosterPosition,
                    vssSourceTrusteeCommitmentRoot:
                        bridgeStatement.compactSameSecretBridgeStatementRoot,
                    constantCoefficientCommitmentRoots:
                        bridgeStatement.targetConstantCoefficientCommitmentRoots.map(
                            (targetConstantRoot) => ({
                                rnsLimbIndex: targetConstantRoot.rnsLimbIndex,
                                rnsPrime: targetConstantRoot.rnsPrime,
                                shamirCoefficientIndex: 0 as const,
                                commitmentRoot:
                                    targetConstantRoot.coefficientCommitmentRoot,
                            }),
                        ),
                    trusteeSecretCommitmentRoot:
                        bridgeStatement.trusteeSecretCommitmentRoot,
                    boundSecretDependentProofFamilies: [
                        'vss-constant-relation',
                        'public-key-share',
                        'relinearization-key-share',
                        'galois-key-share',
                    ],
                    sameSecretProofFamilyBindingRoot:
                        bridgeStatement.sameSecretProofFamilyBindingRoot,
                    sameSecretRelation:
                        'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs',
                } as const;

                return {
                    ...statementWithoutRoot,
                    sameSecretStatementRoot: deriveProtocolHash(
                        'SameSecretConsistencyRoot',
                        statementWithoutRoot,
                    ),
                };
            });
        const sameSecretProofRecords = sameSecretStatementRecords.map(
            (sameSecretStatement, statementIndex) => {
                const proofRecordWithoutRoot = {
                    objectType: 'SameSecretProof',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
                    setupProofProfileId: 'SealedLattice-SetupProof-v1',
                    proofFamily: 'same-secret-linkage-anchor',
                    ...context,
                    trusteeIdentity: sameSecretStatement.trusteeIdentity,
                    trusteeRosterPosition:
                        sameSecretStatement.trusteeRosterPosition,
                    ringDegree: compactVssRingDegree,
                    sameSecretStatementRoot:
                        sameSecretStatement.sameSecretStatementRoot,
                    trusteeSecretCommitmentRoot:
                        sameSecretStatement.trusteeSecretCommitmentRoot,
                    sameSecretProofFamilyBindingRoot:
                        sameSecretStatement.sameSecretProofFamilyBindingRoot,
                    statementHash: deriveProtocolHash('SameSecretProofRoot', {
                        fixture: 'compact-vss-wasm',
                        statementIndex,
                    }),
                    proofSizeBytes: 1,
                    proofBytesHash: sameSecretProofBytesHash('ab'),
                    proofBytesHex: 'ab',
                } as const;

                return {
                    ...proofRecordWithoutRoot,
                    sameSecretProofRoot: deriveProtocolHash(
                        'SameSecretProofRoot',
                        proofRecordWithoutRoot,
                    ),
                };
            },
        );
        const reboundBridgeStatementRecords =
            baseStatementSet.statementRecords.map(
                (bridgeStatement, statementIndex) => {
                    const sameSecretStatement =
                        sameSecretStatementRecords[statementIndex];
                    const sameSecretProof =
                        sameSecretProofRecords[statementIndex];
                    if (
                        sameSecretStatement === undefined ||
                        sameSecretProof === undefined
                    ) {
                        throw new Error(
                            'compact same-secret bridge evidence fixture is missing a statement.',
                        );
                    }
                    const {
                        compactSameSecretBridgeStatementRoot:
                            _removedStatementRoot,
                        ...bridgeStatementWithoutRoot
                    } = bridgeStatement;

                    return rebindCompactSameSecretBridgeStatementRecord({
                        ...bridgeStatementWithoutRoot,
                        sameSecretStatementRoot:
                            sameSecretStatement.sameSecretStatementRoot,
                        sameSecretProofRoot:
                            sameSecretProof.sameSecretProofRoot,
                        trusteeSecretCommitmentRoot:
                            sameSecretStatement.trusteeSecretCommitmentRoot,
                    });
                },
            );
        const sameSecretConsistencyWithoutRoot = {
            objectType: 'SameSecretConsistencyStatementSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofFamily: 'same-secret-linkage-anchor',
            ...context,
            participantCount: baseStatementSet.participantCount,
            rnsLimbCount: baseStatementSet.targetRnsLimbCount,
            thresholdDegree: baseStatementSet.thresholdDegree,
            vssCoefficientCommitmentRoot:
                baseStatementSet.compactCoefficientCommitmentRoot,
            sameSecretProofFamilyBindingRoot:
                baseStatementSet.sameSecretProofFamilyBindingRoot,
            trusteeSecretCommitmentRoots: sameSecretStatementRecords.map(
                (sameSecretStatement) => ({
                    trusteeIdentity: sameSecretStatement.trusteeIdentity,
                    trusteeRosterPosition:
                        sameSecretStatement.trusteeRosterPosition,
                    trusteeSecretCommitmentRoot:
                        sameSecretStatement.trusteeSecretCommitmentRoot,
                }),
            ),
            statementRecords: sameSecretStatementRecords,
        } as const;
        const sameSecretConsistency = {
            ...sameSecretConsistencyWithoutRoot,
            sameSecretConsistencyRoot: deriveProtocolHash(
                'SameSecretConsistencyRoot',
                sameSecretConsistencyWithoutRoot,
            ),
        } as SameSecretConsistencyStatementSet;
        const sameSecretProofsWithoutRoot = {
            objectType: 'SameSecretProofSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofFamily: 'same-secret-linkage-anchor',
            proofAccountingHash: deriveProtocolHash('SameSecretProofRoot', {
                fixture: 'compact-vss-wasm',
                label: 'proof-accounting',
            }),
            ...context,
            participantCount: baseStatementSet.participantCount,
            rnsLimbCount: baseStatementSet.targetRnsLimbCount,
            sameSecretConsistencyRoot:
                sameSecretConsistency.sameSecretConsistencyRoot,
            sameSecretProofFamilyBindingRoot:
                baseStatementSet.sameSecretProofFamilyBindingRoot,
            vssCoefficientCommitmentMaterialRoot:
                baseStatementSet.compactCoefficientCommitmentRoot,
            sameSecretProofRoots: sameSecretProofRecords.map(
                (sameSecretProof) => ({
                    trusteeIdentity: sameSecretProof.trusteeIdentity,
                    trusteeRosterPosition:
                        sameSecretProof.trusteeRosterPosition,
                    sameSecretProofRoot: sameSecretProof.sameSecretProofRoot,
                }),
            ),
            proofRecords: sameSecretProofRecords,
        } as const;
        const sameSecretProofs = {
            ...sameSecretProofsWithoutRoot,
            sameSecretProofSetRoot: deriveProtocolHash(
                'SameSecretProofRoot',
                sameSecretProofsWithoutRoot,
            ),
        } as SameSecretProofSet;
        const {
            compactSameSecretBridgeStatementSetRoot: _removedSetRoot,
            ...baseStatementSetWithoutRoot
        } = baseStatementSet;
        const statementSet = rebindCompactSameSecretBridgeStatementSet({
            ...baseStatementSetWithoutRoot,
            sameSecretConsistencyRoot:
                sameSecretConsistency.sameSecretConsistencyRoot,
            sameSecretProofSetRoot: sameSecretProofs.sameSecretProofSetRoot,
            statementRecords: reboundBridgeStatementRecords,
        });

        return {
            statementSet,
            sameSecretConsistency,
            sameSecretProofs,
        };
    };

type SameSecretProofRecordForFixture = Readonly<Record<string, unknown>> & {
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly sameSecretProofRoot: string;
};

const compactSameSecretBridgeStatementSetWithTransportedProofBytes =
    (): CompactSameSecretBridgeEvidence => {
        const evidence = compactSameSecretBridgeStatementSetWithEvidence();
        const proofTransport =
            createBinaryChunkedSameSecretProofMaterialTransport(
                evidence.sameSecretProofs.proofRecords,
            );
        const proofRecords = proofTransport.proofMaterials.map(
            (proofMaterial) => {
                const {
                    sameSecretProofRoot: _removedProofRoot,
                    ...proofRecordWithoutRoot
                } = proofMaterial as Readonly<Record<string, unknown>>;

                return {
                    ...proofRecordWithoutRoot,
                    sameSecretProofRoot: deriveProtocolHash(
                        'SameSecretProofRoot',
                        proofRecordWithoutRoot,
                    ),
                } as SameSecretProofRecordForFixture;
            },
        );
        const {
            sameSecretProofSetRoot: _removedProofSetRoot,
            ...sameSecretProofsWithoutRoot
        } = evidence.sameSecretProofs;
        const sameSecretProofsWithoutRecomputedRoot = {
            ...sameSecretProofsWithoutRoot,
            sameSecretProofRoots: proofRecords.map((proofRecord) => ({
                trusteeIdentity: proofRecord.trusteeIdentity,
                trusteeRosterPosition: proofRecord.trusteeRosterPosition,
                sameSecretProofRoot: proofRecord.sameSecretProofRoot,
            })),
            proofRecords,
        };
        const sameSecretProofs = {
            ...sameSecretProofsWithoutRecomputedRoot,
            sameSecretProofSetRoot: deriveProtocolHash(
                'SameSecretProofRoot',
                sameSecretProofsWithoutRecomputedRoot,
            ),
        } as unknown as SameSecretProofSet;
        const {
            compactSameSecretBridgeStatementSetRoot: _removedStatementSetRoot,
            ...statementSetWithoutRoot
        } = evidence.statementSet;
        const statementRecords = evidence.statementSet.statementRecords.map(
            (statementRecord, statementIndex) => {
                const proofRecord = proofRecords[statementIndex];
                if (proofRecord === undefined) {
                    throw new Error(
                        'compact same-secret bridge transported fixture is missing a proof record.',
                    );
                }
                const {
                    compactSameSecretBridgeStatementRoot: _removedStatementRoot,
                    ...statementRecordWithoutRoot
                } = statementRecord;

                return rebindCompactSameSecretBridgeStatementRecord({
                    ...statementRecordWithoutRoot,
                    sameSecretProofRoot: proofRecord.sameSecretProofRoot,
                });
            },
        );
        const statementSet = rebindCompactSameSecretBridgeStatementSet({
            ...statementSetWithoutRoot,
            sameSecretProofSetRoot: sameSecretProofs.sameSecretProofSetRoot,
            statementRecords,
        });

        return {
            statementSet,
            sameSecretConsistency: evidence.sameSecretConsistency,
            sameSecretProofs,
            transportedSameSecretProofMaterial:
                proofTransport.transportedSameSecretProofMaterial,
        };
    };

const compactVssProofRingDegree = 128;
const compactVssProofSourceMessageModulus =
    acceptedBgvSetupQSharePrimes[0] ?? 140_737_487_306_753;
const compactVssProofSourceMessageModulusForLimb = (
    sourceRnsLimbIndex: number,
): number =>
    acceptedBgvSetupQSharePrimes[sourceRnsLimbIndex] ??
    compactVssProofSourceMessageModulus;
const compactVssProofCoefficientCount = 3;
const compactVssProofRecipientRosterPosition = 0;

const compactVssProofHash = (hexDigit: string): string => hexDigit.repeat(128);

const compactVssProofTernaryRandomness = (seedOffset: number): number[][] =>
    Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        (_unusedColumn, columnIndex) =>
            Array.from(
                { length: compactVssProofRingDegree },
                (_unusedCoefficient, coefficientIndex) =>
                    ((seedOffset + columnIndex * 5 + coefficientIndex * 7) %
                        3) -
                    1,
            ),
    );

type CompactVssProofFixtureLinkageItem =
    | BgvCompactVssShareLinkageProofStatement
    | NonNullable<
          BgvCompactVssShareLinkageProofStatement['additionalLinkageItems']
      >[number];

type CompactVssCommitmentWithOpeningRoot = ReturnType<
    typeof computeCompactVssCommitmentFromOpening
> &
    Readonly<{
        readonly openingRoot: string;
    }>;

type CompactVssProofFixtureItem = CompactVssProofFixtureLinkageItem &
    Readonly<{
        readonly sourceMessageModulus: number;
        readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
        readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
        readonly recipientShareMessages: readonly number[];
        readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
        readonly carryWitnesses: readonly number[];
    }>;

const compactVssProofSourceCoefficientRecord = (input: {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly publicMatrixSeedHash: string;
    readonly targetRnsLimbCount: number;
    readonly proofItems: readonly CompactVssProofFixtureLinkageItem[];
}): CompactVssSourceCoefficientCommitments => {
    const proofItemsBySourceLimb = new Map(
        input.proofItems.map((proofItem) => [
            proofItem.sourceRnsLimbIndex,
            proofItem,
        ]),
    );
    const coefficientCommitments = Array.from(
        { length: input.targetRnsLimbCount },
        (_unusedLimb, sourceRnsLimbIndex) => {
            const proofItem = proofItemsBySourceLimb.get(sourceRnsLimbIndex);
            if (proofItem === undefined) {
                throw new Error(
                    'compact proof fixture is missing source-limb coefficient commitments.',
                );
            }

            return Array.from(
                { length: compactVssProofCoefficientCount },
                (_unusedCoefficient, shamirCoefficientIndex) =>
                    ({
                        objectType: 'CompactVssCoefficientCommitment',
                        objectVersion: 1,
                        profileId: compactVssCommitmentProfileId,
                        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            input.sourceTrusteeRosterPosition,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        rnsLimbIndex: sourceRnsLimbIndex,
                        rnsPrime: proofItem.sourceMessageModulus,
                        shamirCoefficientIndex,
                        coefficientCommitmentRoot:
                            proofItem.coefficientCommitmentRoots[
                                shamirCoefficientIndex
                            ],
                        coefficientOpeningRoot:
                            proofItem.coefficientOpeningRoots[
                                shamirCoefficientIndex
                            ],
                        commitment: proofItem.coefficientCommitments[
                            shamirCoefficientIndex
                        ] as CompactVssCommitmentValue,
                    }) as const,
            );
        },
    ).flat();
    const sourceRecordWithoutRoot = {
        objectType: 'CompactVssSourceCoefficientCommitments',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        coefficientCommitments,
    } as const;

    return {
        ...sourceRecordWithoutRoot,
        sourceCoefficientCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
            sourceRecordWithoutRoot,
        ),
    };
};

const compactVssProofSourceRecipientShareRecord = (input: {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
    readonly proofItems: readonly CompactVssProofFixtureLinkageItem[];
}): CompactVssSourceRecipientShareCommitments => {
    const proofItemsByCoverage = new Map(
        input.proofItems.map((proofItem) => [
            `${String(proofItem.recipientRosterPosition)}:${String(proofItem.sourceRnsLimbIndex)}`,
            proofItem,
        ]),
    );
    const recipientShareCommitments = Array.from(
        { length: input.participantCount },
        (_unusedRecipient, recipientRosterPosition) =>
            Array.from(
                { length: input.targetRnsLimbCount },
                (_unusedLimb, sourceRnsLimbIndex) => {
                    const proofItem = proofItemsByCoverage.get(
                        `${String(recipientRosterPosition)}:${String(sourceRnsLimbIndex)}`,
                    );
                    if (proofItem === undefined) {
                        throw new Error(
                            'compact proof fixture is missing recipient-share commitments.',
                        );
                    }

                    return {
                        objectType: 'CompactVssRecipientShareCommitment',
                        objectVersion: 1,
                        profileId: compactVssCommitmentProfileId,
                        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            input.sourceTrusteeRosterPosition,
                        recipientIdentity: proofItem.recipientIdentity,
                        recipientRosterPosition,
                        recipientTrusteePoint: recipientRosterPosition + 1,
                        rnsLimbIndex: sourceRnsLimbIndex,
                        rnsPrime: proofItem.sourceMessageModulus,
                        shareCommitmentRoot:
                            proofItem.recipientShareCommitmentRoot,
                        shareOpeningRoot: proofItem.recipientShareOpeningRoot,
                        commitment:
                            proofItem.recipientShareCommitment as CompactVssCommitmentValue,
                    } as const;
                },
            ),
    ).flat();
    const sourceRecordWithoutRoot = {
        objectType: 'CompactVssSourceRecipientShareCommitments',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        recipientShareCommitments,
    } as const;

    return {
        ...sourceRecordWithoutRoot,
        sourceRecipientShareCommitmentRoot: deriveProtocolHash(
            'ThresholdShareCommitmentRoot',
            sourceRecordWithoutRoot,
        ),
    };
};

const compactVssProofFixture = (
    input: {
        readonly includeSameSourceAdditional?: boolean;
    } = {},
): {
    readonly context: BgvTrusteeEvaluationKeyStatementContext;
    readonly compactVssShareLinkage: BgvCompactVssShareLinkageProofStatement;
    readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
    readonly recipientShareMessages: readonly number[];
    readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
    readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
    readonly carryWitnesses: readonly number[];
    readonly recipientShareMessagesByItem: readonly (readonly number[])[];
    readonly recipientShareOpeningRandomnessByItem: readonly (readonly (readonly number[])[])[];
    readonly carryWitnessesByItem: readonly (readonly number[])[];
} => {
    const publicMatrixSeedHash = compactVssProofHash('7');
    const coefficientComputationsForSourceLimb = (
        sourceRnsLimbIndex: number,
        sourceMessageModulus: number,
        coefficientMessagesByShamirIndex: readonly (readonly number[])[],
        coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[],
    ): readonly CompactVssCommitmentWithOpeningRoot[] =>
        coefficientMessagesByShamirIndex.map(
            (messages, shamirCoefficientIndex) => {
                const opening = {
                    commitmentRole: 'coefficient',
                    commitmentContext: {
                        objectType: 'CompactVssProofTestCommitmentContext',
                        objectVersion: 1,
                        shamirCoefficientIndex,
                    },
                    publicMatrixSeedHash,
                    rnsLimbIndex: sourceRnsLimbIndex,
                    rnsPrime: sourceMessageModulus,
                    ringDegree: compactVssProofRingDegree,
                    messageCoefficients: messages,
                    messageCoefficientBound: sourceMessageModulus,
                    randomnessByColumn:
                        coefficientOpeningRandomnessByShamirIndex[
                            shamirCoefficientIndex
                        ],
                } as const;

                return {
                    ...computeCompactVssCommitmentFromOpening(opening),
                    openingRoot:
                        compactVssCommitmentPrivateOpeningRoot(opening),
                };
            },
        );
    const proofItemForRecipient = (
        recipientRosterPosition: number,
        sourceRnsLimbIndex: number,
    ): CompactVssProofFixtureItem => {
        const sourceMessageModulus =
            compactVssProofSourceMessageModulusForLimb(sourceRnsLimbIndex);
        const coefficientMessagesByShamirIndex = Array.from(
            { length: compactVssProofCoefficientCount },
            (_unused, shamirCoefficientIndex) =>
                Array.from(
                    { length: compactVssProofRingDegree },
                    (_unusedCoefficient, coefficientIndex) =>
                        coefficientIndex % 11 === shamirCoefficientIndex
                            ? sourceMessageModulus - 4 - shamirCoefficientIndex
                            : (17 +
                                  sourceRnsLimbIndex * 29 +
                                  19 * shamirCoefficientIndex +
                                  23 * coefficientIndex) %
                              sourceMessageModulus,
                ),
        );
        const coefficientOpeningRandomnessByShamirIndex =
            coefficientMessagesByShamirIndex.map(
                (_messages, coefficientIndex) =>
                    compactVssProofTernaryRandomness(
                        10 + sourceRnsLimbIndex * 23 + coefficientIndex,
                    ),
            );
        const coefficientComputations = coefficientComputationsForSourceLimb(
            sourceRnsLimbIndex,
            sourceMessageModulus,
            coefficientMessagesByShamirIndex,
            coefficientOpeningRandomnessByShamirIndex,
        );
        const recipientTrusteePoint = recipientRosterPosition + 1;
        const trusteePointPowers = Array.from(
            { length: compactVssProofCoefficientCount },
            (_unusedPower, shamirCoefficientIndex) =>
                recipientTrusteePoint ** shamirCoefficientIndex,
        );
        const recipientShareMessages: number[] = [];
        const carryWitnesses: number[] = [];
        for (
            let coefficientIndex = 0;
            coefficientIndex < compactVssProofRingDegree;
            coefficientIndex += 1
        ) {
            const liftedShare = coefficientMessagesByShamirIndex.reduce(
                (sum, messages, shamirCoefficientIndex) =>
                    sum +
                    messages[coefficientIndex] *
                        trusteePointPowers[shamirCoefficientIndex],
                0,
            );
            recipientShareMessages.push(liftedShare % sourceMessageModulus);
            carryWitnesses.push(Math.floor(liftedShare / sourceMessageModulus));
        }
        const recipientShareOpeningRandomness =
            compactVssProofTernaryRandomness(
                41 + sourceRnsLimbIndex * 17 + recipientRosterPosition * 31,
            );
        const recipientShareOpening = {
            commitmentRole: 'recipient-share',
            commitmentContext: {
                objectType: 'CompactVssProofTestRecipientShareContext',
                objectVersion: 1,
                recipientRosterPosition,
            },
            publicMatrixSeedHash,
            rnsLimbIndex: sourceRnsLimbIndex,
            rnsPrime: sourceMessageModulus,
            ringDegree: compactVssProofRingDegree,
            messageCoefficients: recipientShareMessages,
            messageCoefficientBound: sourceMessageModulus,
            randomnessByColumn: recipientShareOpeningRandomness,
        } as const;
        const recipientShareComputation = {
            ...computeCompactVssCommitmentFromOpening(recipientShareOpening),
            openingRoot: compactVssCommitmentPrivateOpeningRoot(
                recipientShareOpening,
            ),
        };

        return {
            recipientIdentity: `recipient-${recipientRosterPosition}`,
            recipientRosterPosition,
            sourceRnsLimbIndex,
            sourceMessageModulus,
            coefficientCommitmentRoots: coefficientComputations.map(
                (computation) => computation.commitmentRoot,
            ),
            coefficientOpeningRoots: coefficientComputations.map(
                (computation) => computation.openingRoot,
            ),
            coefficientCommitments: coefficientComputations.map(
                (computation) => computation.commitment,
            ),
            recipientShareCommitmentRoot:
                recipientShareComputation.commitmentRoot,
            recipientShareOpeningRoot: recipientShareComputation.openingRoot,
            recipientShareCommitment: recipientShareComputation.commitment,
            recipientShareMessages,
            recipientShareOpeningRandomness,
            carryWitnesses,
            coefficientMessagesByShamirIndex,
            coefficientOpeningRandomnessByShamirIndex,
        };
    };
    const primaryProofItem = proofItemForRecipient(
        compactVssProofRecipientRosterPosition,
        0,
    );
    const sameSourceAdditionalProofItem = input.includeSameSourceAdditional
        ? proofItemForRecipient(compactVssProofRecipientRosterPosition + 1, 0)
        : undefined;
    const additionalProofItem = proofItemForRecipient(
        compactVssProofRecipientRosterPosition,
        1,
    );
    const additionalLinkageItems =
        sameSourceAdditionalProofItem === undefined
            ? [additionalProofItem]
            : [sameSourceAdditionalProofItem, additionalProofItem];
    let sourceCoefficientCommitmentRoot = compactVssProofHash('a');
    let sourceRecipientShareCommitmentRoot = compactVssProofHash('b');
    if (input.includeSameSourceAdditional !== true) {
        const proofItems = [primaryProofItem, ...additionalLinkageItems];
        const sourceTrusteeIdentity = 'trustee-0';
        const sourceTrusteeRosterPosition = 0;
        sourceCoefficientCommitmentRoot =
            compactVssProofSourceCoefficientRecord({
                sourceTrusteeIdentity,
                sourceTrusteeRosterPosition,
                publicMatrixSeedHash,
                targetRnsLimbCount: 2,
                proofItems,
            }).sourceCoefficientCommitmentRoot;
        sourceRecipientShareCommitmentRoot =
            compactVssProofSourceRecipientShareRecord({
                sourceTrusteeIdentity,
                sourceTrusteeRosterPosition,
                participantCount: 1,
                targetRnsLimbCount: 2,
                proofItems,
            }).sourceRecipientShareCommitmentRoot;
    }

    return {
        context: {
            ceremonyId: 'compact-vss-proof-wasm-test',
            manifestHash: compactVssProofHash('1'),
            rosterHash: compactVssProofHash('2'),
            trusteeIdentity: 'trustee-0',
            trusteeRosterPosition: 0,
            setupEpoch: 'setup-epoch-1',
            sourceCoefficientCommitmentRoot,
            sourceRecipientShareCommitmentRoot,
        },
        compactVssShareLinkage: {
            publicMatrixSeedHash,
            sourceTrusteeIdentity: 'trustee-0',
            sourceTrusteeRosterPosition: 0,
            sourceCoefficientCommitmentRoot,
            sourceRecipientShareCommitmentRoot,
            ...primaryProofItem,
            additionalLinkageItems,
        },
        coefficientMessagesByShamirIndex: [
            ...primaryProofItem.coefficientMessagesByShamirIndex,
            ...additionalProofItem.coefficientMessagesByShamirIndex,
        ],
        recipientShareMessages: primaryProofItem.recipientShareMessages,
        coefficientOpeningRandomnessByShamirIndex: [
            ...primaryProofItem.coefficientOpeningRandomnessByShamirIndex,
            ...additionalProofItem.coefficientOpeningRandomnessByShamirIndex,
        ],
        recipientShareOpeningRandomness:
            primaryProofItem.recipientShareOpeningRandomness,
        carryWitnesses: primaryProofItem.carryWitnesses,
        recipientShareMessagesByItem: [
            primaryProofItem.recipientShareMessages,
            ...(sameSourceAdditionalProofItem === undefined
                ? []
                : [sameSourceAdditionalProofItem.recipientShareMessages]),
            additionalProofItem.recipientShareMessages,
        ],
        recipientShareOpeningRandomnessByItem: [
            primaryProofItem.recipientShareOpeningRandomness,
            ...(sameSourceAdditionalProofItem === undefined
                ? []
                : [
                      sameSourceAdditionalProofItem.recipientShareOpeningRandomness,
                  ]),
            additionalProofItem.recipientShareOpeningRandomness,
        ],
        carryWitnessesByItem: [
            primaryProofItem.carryWitnesses,
            ...(sameSourceAdditionalProofItem === undefined
                ? []
                : [sameSourceAdditionalProofItem.carryWitnesses]),
            additionalProofItem.carryWitnesses,
        ],
    };
};

const compactSameSecretBridgeProofFixture = (): {
    readonly context: BgvTrusteeEvaluationKeyStatementContext;
    readonly compactSameSecretBridge: BgvCompactSameSecretBridgeProofStatement;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
    readonly secretCoefficients: readonly number[];
    readonly negativeIndicatorCoefficients: readonly number[];
    readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
} => {
    const publicMatrixSeedHash = compactVssProofHash('8');
    const targetBasisHash = canonicalTargetBasisHash();
    const targetRnsPrimes = [compactVssProofSourceMessageModulus];
    const secretCoefficients = Array.from(
        { length: compactVssProofRingDegree },
        (_unusedCoefficient, coefficientIndex) => {
            if (coefficientIndex % 3 === 0) {
                return -1;
            }
            return coefficientIndex % 3 === 1 ? 0 : 1;
        },
    );
    const negativeIndicatorCoefficients = secretCoefficients.map(
        (coefficient) => (coefficient < 0 ? 1 : 0),
    );
    const openingRandomnessByLimb = targetRnsPrimes.map(
        (_targetRnsPrime, targetRnsLimbIndex) =>
            compactVssProofTernaryRandomness(67 + targetRnsLimbIndex),
    );
    const targetConstantComputations = targetRnsPrimes.map(
        (targetRnsPrime, targetRnsLimbIndex) => {
            const messageCoefficients = secretCoefficients.map(
                (coefficient, coefficientIndex) =>
                    coefficient +
                    negativeIndicatorCoefficients[coefficientIndex] *
                        targetRnsPrime,
            );

            return computeCompactVssCommitmentFromOpening({
                commitmentRole: 'coefficient',
                commitmentContext: {
                    objectType: 'CompactSameSecretBridgeProofTestContext',
                    objectVersion: 1,
                    targetRnsLimbIndex,
                },
                publicMatrixSeedHash,
                rnsLimbIndex: targetRnsLimbIndex,
                rnsPrime: targetRnsPrime,
                ringDegree: compactVssProofRingDegree,
                messageCoefficients,
                messageCoefficientBound: targetRnsPrime,
                randomnessByColumn: openingRandomnessByLimb[targetRnsLimbIndex],
            });
        },
    );
    const sameSecretProofFamilyBindingRoot = compactVssProofHash('d');
    const trusteeSecretCommitmentRoot = compactVssProofHash('7');
    const targetConstantCoefficientCommitmentRoots = targetRnsPrimes.map(
        (rnsPrime, rnsLimbIndex) => ({
            rnsLimbIndex,
            rnsPrime,
            shamirCoefficientIndex: 0 as const,
            coefficientCommitmentRoot:
                targetConstantComputations[rnsLimbIndex]?.commitmentRoot ??
                (() => {
                    throw new Error(
                        'compact same-secret bridge proof fixture is missing a target commitment root.',
                    );
                })(),
        }),
    );
    const targetConstantCoefficientCommitments = targetRnsPrimes.map(
        (rnsPrime, rnsLimbIndex) => ({
            rnsLimbIndex,
            rnsPrime,
            shamirCoefficientIndex: 0 as const,
            commitment:
                targetConstantComputations[rnsLimbIndex]?.commitment ??
                (() => {
                    throw new Error(
                        'compact same-secret bridge proof fixture is missing a target commitment.',
                    );
                })(),
        }),
    );
    const sameSecretContext = {
        ceremonyId: 'compact-same-secret-bridge-proof-wasm-test',
        manifestHash: compactVssProofHash('1'),
        rosterHash: compactVssProofHash('2'),
        setupProfileHash: compactVssProofHash('3'),
        qShareHash: compactVssProofHash('4'),
        carryAwareVssShareRelationProfileHash: compactVssProofHash('5'),
        commitmentProfileHash: compactVssProofHash('6'),
        setupEpoch: 'setup-epoch-1',
    } as const;
    const sameSecretStatementWithoutRoot = {
        objectType: 'SameSecretConsistencyStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'same-secret-linkage-anchor',
        ...sameSecretContext,
        trusteeIdentity: 'trustee-0',
        trusteeRosterPosition: 0,
        vssSourceTrusteeCommitmentRoot: compactVssProofHash('9'),
        constantCoefficientCommitmentRoots:
            targetConstantCoefficientCommitmentRoots.map(
                (targetConstantRoot) => ({
                    rnsLimbIndex: targetConstantRoot.rnsLimbIndex,
                    rnsPrime: targetConstantRoot.rnsPrime,
                    shamirCoefficientIndex: 0 as const,
                    commitmentRoot:
                        targetConstantRoot.coefficientCommitmentRoot,
                }),
            ),
        trusteeSecretCommitmentRoot,
        boundSecretDependentProofFamilies: [
            'vss-constant-relation',
            'public-key-share',
            'relinearization-key-share',
            'galois-key-share',
        ],
        sameSecretProofFamilyBindingRoot,
        sameSecretRelation:
            'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs',
    } as const;
    const sameSecretStatementRoot = deriveProtocolHash(
        'SameSecretConsistencyRoot',
        sameSecretStatementWithoutRoot,
    );
    const sameSecretStatementRecord = {
        ...sameSecretStatementWithoutRoot,
        sameSecretStatementRoot,
    } as const;
    const sameSecretProofRecordWithoutRoot = {
        objectType: 'SameSecretProof',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'same-secret-linkage-anchor',
        ...sameSecretContext,
        trusteeIdentity: 'trustee-0',
        trusteeRosterPosition: 0,
        ringDegree: compactVssProofRingDegree,
        sameSecretStatementRoot,
        trusteeSecretCommitmentRoot,
        sameSecretProofFamilyBindingRoot,
        statementHash: deriveProtocolHash('SameSecretProofRoot', {
            fixture: 'compact-same-secret-bridge-proof-wasm',
        }),
        proofSizeBytes: 1,
        proofBytesHash: sameSecretProofBytesHash('ab'),
        proofBytesHex: 'ab',
    } as const;
    const sameSecretProofRoot = deriveProtocolHash(
        'SameSecretProofRoot',
        sameSecretProofRecordWithoutRoot,
    );
    const sameSecretProofRecord = {
        ...sameSecretProofRecordWithoutRoot,
        sameSecretProofRoot,
    } as const;
    const sameSecretConsistencyWithoutRoot = {
        objectType: 'SameSecretConsistencyStatementSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'same-secret-linkage-anchor',
        ...sameSecretContext,
        participantCount: 1,
        rnsLimbCount: targetRnsPrimes.length,
        thresholdDegree: 1,
        vssCoefficientCommitmentRoot: compactVssProofHash('9'),
        sameSecretProofFamilyBindingRoot,
        trusteeSecretCommitmentRoots: [
            {
                trusteeIdentity: 'trustee-0',
                trusteeRosterPosition: 0,
                trusteeSecretCommitmentRoot,
            },
        ],
        statementRecords: [sameSecretStatementRecord],
    } as const;
    const sameSecretConsistency = {
        ...sameSecretConsistencyWithoutRoot,
        sameSecretConsistencyRoot: deriveProtocolHash(
            'SameSecretConsistencyRoot',
            sameSecretConsistencyWithoutRoot,
        ),
    } as SameSecretConsistencyStatementSet;
    const sameSecretProofsWithoutRoot = {
        objectType: 'SameSecretProofSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'same-secret-linkage-anchor',
        proofAccountingHash: deriveProtocolHash('SameSecretProofRoot', {
            fixture: 'compact-same-secret-bridge-proof-accounting',
        }),
        ...sameSecretContext,
        participantCount: 1,
        rnsLimbCount: targetRnsPrimes.length,
        sameSecretConsistencyRoot:
            sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofFamilyBindingRoot,
        vssCoefficientCommitmentMaterialRoot: compactVssProofHash('9'),
        sameSecretProofRoots: [
            {
                trusteeIdentity: 'trustee-0',
                trusteeRosterPosition: 0,
                sameSecretProofRoot,
            },
        ],
        proofRecords: [sameSecretProofRecord],
    } as const;
    const sameSecretProofs = {
        ...sameSecretProofsWithoutRoot,
        sameSecretProofSetRoot: deriveProtocolHash(
            'SameSecretProofRoot',
            sameSecretProofsWithoutRoot,
        ),
    } as SameSecretProofSet;
    const compactSameSecretBridgeStatementRoot = deriveProtocolHash(
        'SetupProofRecordBindingHash',
        {
            objectType: 'CompactVssSameSecretBridgeStatement',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            compactCommitmentProfileId: compactVssCommitmentProfileId,
            setupProofProfileId: 'SealedLattice-SetupProof-v1',
            proofFamily: 'same-secret-linkage-anchor',
            ceremonyId: 'compact-same-secret-bridge-proof-wasm-test',
            manifestHash: compactVssProofHash('1'),
            rosterHash: compactVssProofHash('2'),
            setupProfileHash: compactVssProofHash('3'),
            qShareHash: compactVssProofHash('4'),
            carryAwareVssShareRelationProfileHash: compactVssProofHash('5'),
            commitmentProfileHash: compactVssProofHash('6'),
            setupEpoch: 'setup-epoch-1',
            targetBasisHash,
            publicMatrixSeedHash,
            ringDegree: compactVssProofRingDegree,
            trusteeIdentity: 'trustee-0',
            trusteeRosterPosition: 0,
            sameSecretStatementRoot,
            sameSecretProofRoot,
            trusteeSecretCommitmentRoot,
            sameSecretProofFamilyBindingRoot,
            dataBasisRelation:
                'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs',
            integerSupport: compactVssSameSecretBridgeIntegerSupport,
            signedRepresentativeConvention:
                compactVssSameSecretBridgeSignedRepresentativeConvention,
            compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
            targetBasisLimbOrder:
                compactVssSameSecretBridgeTargetBasisLimbOrder,
            targetConstantCoefficientCommitmentRoots,
            targetConstantCoefficientCommitments,
            relation:
                'target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof',
        },
    );

    return {
        context: {
            ceremonyId: 'compact-same-secret-bridge-proof-wasm-test',
            manifestHash: compactVssProofHash('1'),
            rosterHash: compactVssProofHash('2'),
            trusteeIdentity: 'trustee-0',
            trusteeRosterPosition: 0,
            setupEpoch: 'setup-epoch-1',
            compactSameSecretBridgeStatementRoot,
            sameSecretStatementRoot,
            sameSecretProofRoot,
            sameSecretProofFamilyBindingRoot,
        },
        compactSameSecretBridge: {
            compactSameSecretBridgeStatementRoot,
            sameSecretStatementRoot,
            sameSecretProofRoot,
            sameSecretProofFamilyBindingRoot,
            publicMatrixSeedHash,
            sourceTrusteeIdentity: 'trustee-0',
            sourceTrusteeRosterPosition: 0,
            targetBasisHash,
            targetRnsPrimes,
            targetConstantCommitmentRoots: targetConstantComputations.map(
                (computation) => computation.commitmentRoot,
            ),
            targetConstantCommitments: targetConstantComputations.map(
                (computation) => computation.commitment,
            ),
        },
        sameSecretConsistency,
        sameSecretProofs,
        secretCoefficients,
        negativeIndicatorCoefficients,
        openingRandomnessByLimb,
    };
};

const compactSameSecretBridgeStatementSetFromProofFixture = (
    fixture: ReturnType<typeof compactSameSecretBridgeProofFixture>,
): CompactVssSameSecretBridgeStatementSet => {
    const targetConstantCoefficientCommitmentRoots =
        fixture.compactSameSecretBridge.targetRnsPrimes.map(
            (rnsPrime, rnsLimbIndex) => ({
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex: 0 as const,
                coefficientCommitmentRoot:
                    fixture.compactSameSecretBridge
                        .targetConstantCommitmentRoots[rnsLimbIndex] ??
                    (() => {
                        throw new Error(
                            'compact same-secret bridge proof fixture is missing a target root.',
                        );
                    })(),
            }),
        );
    const targetConstantCoefficientCommitments =
        fixture.compactSameSecretBridge.targetRnsPrimes.map(
            (rnsPrime, rnsLimbIndex) => ({
                rnsLimbIndex,
                rnsPrime,
                shamirCoefficientIndex: 0 as const,
                commitment:
                    (fixture.compactSameSecretBridge.targetConstantCommitments[
                        rnsLimbIndex
                    ] as CompactVssCommitmentValue | undefined) ??
                    (() => {
                        throw new Error(
                            'compact same-secret bridge proof fixture is missing a target commitment.',
                        );
                    })(),
            }),
        );
    const statementRecordWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        compactCommitmentProfileId: compactVssCommitmentProfileId,
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'same-secret-linkage-anchor',
        ceremonyId: fixture.context.ceremonyId,
        manifestHash: fixture.context.manifestHash,
        rosterHash: fixture.context.rosterHash,
        setupProfileHash: compactVssProofHash('3'),
        qShareHash: compactVssProofHash('4'),
        carryAwareVssShareRelationProfileHash: compactVssProofHash('5'),
        commitmentProfileHash: compactVssProofHash('6'),
        setupEpoch: fixture.context.setupEpoch,
        targetBasisHash: fixture.compactSameSecretBridge.targetBasisHash,
        publicMatrixSeedHash:
            fixture.compactSameSecretBridge.publicMatrixSeedHash,
        ringDegree: compactVssProofRingDegree,
        trusteeIdentity: fixture.context.trusteeIdentity,
        trusteeRosterPosition: fixture.context.trusteeRosterPosition,
        sameSecretStatementRoot:
            fixture.compactSameSecretBridge.sameSecretStatementRoot,
        sameSecretProofRoot:
            fixture.compactSameSecretBridge.sameSecretProofRoot,
        trusteeSecretCommitmentRoot: compactVssProofHash('7'),
        sameSecretProofFamilyBindingRoot:
            fixture.compactSameSecretBridge.sameSecretProofFamilyBindingRoot,
        dataBasisRelation:
            'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs',
        integerSupport: compactVssSameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            compactVssSameSecretBridgeSignedRepresentativeConvention,
        compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
        targetBasisLimbOrder: compactVssSameSecretBridgeTargetBasisLimbOrder,
        targetConstantCoefficientCommitmentRoots,
        targetConstantCoefficientCommitments,
        relation:
            'target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof',
    } as const;
    const statementRecord = {
        ...statementRecordWithoutRoot,
        compactSameSecretBridgeStatementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementRecordWithoutRoot,
        ),
    };
    const statementSetWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeStatementSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        compactCommitmentProfileId: compactVssCommitmentProfileId,
        setupProofProfileId: 'SealedLattice-SetupProof-v1',
        proofFamily: 'same-secret-linkage-anchor',
        ceremonyId: fixture.context.ceremonyId,
        manifestHash: fixture.context.manifestHash,
        rosterHash: fixture.context.rosterHash,
        setupProfileHash: compactVssProofHash('3'),
        qShareHash: compactVssProofHash('4'),
        carryAwareVssShareRelationProfileHash: compactVssProofHash('5'),
        commitmentProfileHash: compactVssProofHash('6'),
        setupEpoch: fixture.context.setupEpoch,
        targetBasisHash: fixture.compactSameSecretBridge.targetBasisHash,
        publicMatrixSeedHash:
            fixture.compactSameSecretBridge.publicMatrixSeedHash,
        ringDegree: compactVssProofRingDegree,
        participantCount: 1,
        targetRnsLimbCount:
            fixture.compactSameSecretBridge.targetRnsPrimes.length,
        thresholdDegree: 1,
        compactCoefficientCommitmentRoot: compactVssProofHash('9'),
        sameSecretConsistencyRoot:
            fixture.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: fixture.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            fixture.compactSameSecretBridge.sameSecretProofFamilyBindingRoot,
        integerSupport: compactVssSameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            compactVssSameSecretBridgeSignedRepresentativeConvention,
        compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
        targetBasisLimbOrder: compactVssSameSecretBridgeTargetBasisLimbOrder,
        statementRecords: [statementRecord],
    } as const;

    return {
        ...statementSetWithoutRoot,
        compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementSetWithoutRoot,
        ),
    };
};

describe('compact VSS commitment kernel commands', () => {
    it('match the TypeScript compact commitment implementation', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const opening = compactVssOpening();
        const protocolComputation =
            computeCompactVssCommitmentFromOpening(opening);

        const kernelComputation =
            kernel.computeCompactVssCommitmentFromOpening(opening);

        expect(kernelComputation.operation).toBe(
            'computeCompactVssCommitmentFromOpening',
        );
        expect(kernelComputation.encodedCommitmentByteLength).toBe(384);
        expect(kernelComputation.commitmentRoot).toBe(
            protocolComputation.commitmentRoot,
        );
        expect(kernelComputation.commitmentContextHash).toBe(
            protocolComputation.commitmentContextHash,
        );
        expect(kernelComputation.commitment).toEqual(
            protocolComputation.commitment,
        );

        const protocolCommitmentBodyBytes = encodeCompactVssCommitmentBody(
            protocolComputation.commitment,
        );
        const kernelCommitmentBodyEncoding =
            kernel.encodeCompactVssCommitmentBody({
                commitment: kernelComputation.commitment,
            });
        const compactCommitmentBodyMetadata: CompactVssCommitmentBodyMetadata =
            {
                commitmentRole: protocolComputation.commitment.commitmentRole,
                commitmentContextHash:
                    protocolComputation.commitment.commitmentContextHash,
                publicMatrixSeedHash:
                    protocolComputation.commitment.publicMatrixSeedHash,
                rnsLimbIndex: protocolComputation.commitment.rnsLimbIndex,
                rnsPrime: protocolComputation.commitment.rnsPrime,
                ringDegree: protocolComputation.commitment.ringDegree,
            };

        expect(kernelCommitmentBodyEncoding).toMatchObject({
            operation: 'encodeCompactVssCommitmentBody',
            binaryFormat: compactVssCommitmentBinaryFormat,
            encodedCommitmentByteLength:
                compactVssEncodedCommitmentByteLength(),
        });
        expect(kernelCommitmentBodyEncoding.commitmentBodyBytes).toEqual(
            protocolCommitmentBodyBytes,
        );

        const kernelCommitmentBodyDecoding =
            kernel.decodeCompactVssCommitmentBody({
                metadata: compactCommitmentBodyMetadata,
                commitmentBodyBytes:
                    kernelCommitmentBodyEncoding.commitmentBodyBytes,
            });
        expect(kernelCommitmentBodyDecoding).toMatchObject({
            operation: 'decodeCompactVssCommitmentBody',
            commitmentRoot: protocolComputation.commitmentRoot,
        });
        expect(kernelCommitmentBodyDecoding.commitment).toEqual(
            decodeCompactVssCommitmentBody({
                metadata: compactCommitmentBodyMetadata,
                commitmentBodyBytes: protocolCommitmentBodyBytes,
            }),
        );

        expect(() =>
            kernel.decodeCompactVssCommitmentBody({
                metadata: compactCommitmentBodyMetadata,
                commitmentBodyBytes:
                    kernelCommitmentBodyEncoding.commitmentBodyBytes.slice(
                        0,
                        -8,
                    ),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        const outOfRangeCommitmentBodyBytes =
            kernelCommitmentBodyEncoding.commitmentBodyBytes.slice();
        const firstCommitmentLimb =
            protocolComputation.commitment.commitmentLimbs[0];
        if (firstCommitmentLimb === undefined) {
            throw new Error(
                'compact VSS fixture is missing a commitment limb.',
            );
        }
        writeTestLittleEndianU64(
            outOfRangeCommitmentBodyBytes,
            0,
            firstCommitmentLimb.modulus,
        );
        expect(() =>
            kernel.decodeCompactVssCommitmentBody({
                metadata: compactCommitmentBodyMetadata,
                commitmentBodyBytes: outOfRangeCommitmentBodyBytes,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        const verification = kernel.verifyCompactVssCommitmentOpening({
            opening,
            expectedCommitmentRoot: protocolComputation.commitmentRoot,
        });
        expect(verification).toMatchObject({
            operation: 'verifyCompactVssCommitmentOpening',
            commitmentRoot: protocolComputation.commitmentRoot,
        });

        expect(() =>
            kernel.verifyCompactVssCommitmentOpening({
                opening: {
                    ...opening,
                    messageCoefficients: [
                        ...opening.messageCoefficients.slice(0, 3),
                        12,
                        ...opening.messageCoefficients.slice(4),
                    ],
                },
                expectedCommitmentRoot: protocolComputation.commitmentRoot,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('generates and verifies restricted compact share-linkage proofs through WASM', async () => {
        const kernel: TranscriptCoreKernel = await loadTranscriptCoreKernel();
        const fixture = compactVssProofFixture({
            includeSameSourceAdditional: true,
        });
        const generation = kernel.generateCompactVssShareLinkageProof({
            ...fixture,
            ringDegree: compactVssProofRingDegree,
            proofRandomnessSeedHex: 'ab'.repeat(64),
            proofRandomnessNonceHex: 'cd'.repeat(64),
        });

        expect(generation).toMatchObject({
            operation: 'generateCompactVssShareLinkageProof',
            proofFamily: 'compact-vss-share-linkage',
            coefficientCommitmentCount: compactVssProofCoefficientCount * 3,
            coefficientWitnessColumnCount: compactVssProofCoefficientCount * 2,
        });
        expect(generation.proofByteLength).toBeGreaterThan(0);

        const verification = kernel.verifyCompactVssShareLinkageProof({
            context: fixture.context,
            ringDegree: compactVssProofRingDegree,
            compactVssShareLinkage: fixture.compactVssShareLinkage,
            proofBytesHex: generation.proofBytesHex,
        });
        expect(verification).toMatchObject({
            operation: 'verifyCompactVssShareLinkageProof',
            proofFamily: 'compact-vss-share-linkage',
            statementHash: generation.statementHash,
            coefficientWitnessColumnCount:
                generation.coefficientWitnessColumnCount,
            proofByteLength: generation.proofByteLength,
        });

        expect(() =>
            kernel.verifyCompactVssShareLinkageProof({
                context: fixture.context,
                ringDegree: compactVssProofRingDegree,
                compactVssShareLinkage: {
                    ...fixture.compactVssShareLinkage,
                    coefficientCommitmentRoots: [
                        compactVssProofHash('f'),
                        ...fixture.compactVssShareLinkage.coefficientCommitmentRoots.slice(
                            1,
                        ),
                    ],
                },
                proofBytesHex: generation.proofBytesHex,
            }),
        ).toThrow(/root does not match/u);

        const recipientShareCommitmentWithWrongSeed = {
            ...fixture.compactVssShareLinkage.recipientShareCommitment,
            publicMatrixSeedHash: compactVssProofHash('e'),
        };
        expect(() =>
            kernel.verifyCompactVssShareLinkageProof({
                context: fixture.context,
                ringDegree: compactVssProofRingDegree,
                compactVssShareLinkage: {
                    ...fixture.compactVssShareLinkage,
                    recipientShareCommitmentRoot: deriveProtocolHash(
                        'SetupCommitmentRoot',
                        recipientShareCommitmentWithWrongSeed,
                    ),
                    recipientShareCommitment:
                        recipientShareCommitmentWithWrongSeed,
                },
                proofBytesHex: generation.proofBytesHex,
            }),
        ).toThrow(/metadata must match/u);

        const firstCoefficientCommitment =
            fixture.compactVssShareLinkage.coefficientCommitments[0];
        if (firstCoefficientCommitment === undefined) {
            throw new Error(
                'compact proof fixture is missing a coefficient commitment.',
            );
        }
        const coefficientCommitmentWithWrongProfile = {
            ...firstCoefficientCommitment,
            profileId: 'SealedLattice-CompactLinearCommitment-Other-v1',
        };
        expect(() =>
            kernel.verifyCompactVssShareLinkageProof({
                context: fixture.context,
                ringDegree: compactVssProofRingDegree,
                compactVssShareLinkage: {
                    ...fixture.compactVssShareLinkage,
                    coefficientCommitmentRoots: [
                        deriveProtocolHash(
                            'SetupCommitmentRoot',
                            coefficientCommitmentWithWrongProfile,
                        ),
                        ...fixture.compactVssShareLinkage.coefficientCommitmentRoots.slice(
                            1,
                        ),
                    ],
                    coefficientCommitments: [
                        coefficientCommitmentWithWrongProfile,
                        ...fixture.compactVssShareLinkage.coefficientCommitments.slice(
                            1,
                        ),
                    ],
                },
                proofBytesHex: generation.proofBytesHex,
            }),
        ).toThrow(/profile metadata must match/u);

        const recipientShareCommitment =
            fixture.compactVssShareLinkage.recipientShareCommitment;
        if (
            !isCompactVssCommitmentWithLimbs(recipientShareCommitment) ||
            recipientShareCommitment.commitmentLimbs[0] === undefined
        ) {
            throw new Error(
                'compact proof fixture is missing recipient commitment limbs.',
            );
        }
        const recipientShareFirstLimb =
            recipientShareCommitment.commitmentLimbs[0];
        const recipientShareCommitmentWithWrongLimbModulus = {
            ...recipientShareCommitment,
            commitmentLimbs: [
                {
                    ...recipientShareFirstLimb,
                    modulus: 17,
                },
                ...recipientShareCommitment.commitmentLimbs.slice(1),
            ],
        };
        expect(() =>
            kernel.verifyCompactVssShareLinkageProof({
                context: fixture.context,
                ringDegree: compactVssProofRingDegree,
                compactVssShareLinkage: {
                    ...fixture.compactVssShareLinkage,
                    recipientShareCommitmentRoot: deriveProtocolHash(
                        'SetupCommitmentRoot',
                        recipientShareCommitmentWithWrongLimbModulus,
                    ),
                    recipientShareCommitment:
                        recipientShareCommitmentWithWrongLimbModulus,
                },
                proofBytesHex: generation.proofBytesHex,
            }),
        ).toThrow(/commitmentLimbs modulus must match/u);

        const tamperedStatement = structuredClone(
            fixture.compactVssShareLinkage,
        );
        const tamperedRecipientCommitment =
            tamperedStatement.recipientShareCommitment as {
                readonly commitmentLimbs: {
                    readonly modulus: number;
                    readonly coordinates: number[];
                }[];
            };
        const firstLimb = tamperedRecipientCommitment.commitmentLimbs[0];
        if (firstLimb === undefined) {
            throw new Error('compact proof fixture is missing a limb.');
        }
        firstLimb.coordinates[0] =
            (firstLimb.coordinates[0] + 1) % firstLimb.modulus;

        expect(() =>
            kernel.verifyCompactVssShareLinkageProof({
                context: fixture.context,
                ringDegree: compactVssProofRingDegree,
                compactVssShareLinkage: tamperedStatement,
                proofBytesHex: generation.proofBytesHex,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('generates and verifies compact same-secret bridge proofs through WASM', async () => {
        const kernel: TranscriptCoreKernel = await loadTranscriptCoreKernel();
        const fixture = compactSameSecretBridgeProofFixture();
        const generation = kernel.generateCompactSameSecretBridgeProof({
            ...fixture,
            ringDegree: compactVssProofRingDegree,
            proofRandomnessSeedHex: '12'.repeat(64),
            proofRandomnessNonceHex: '34'.repeat(64),
        });

        expect(generation).toMatchObject({
            operation: 'generateCompactSameSecretBridgeProof',
            proofFamily: 'compact-same-secret-bridge',
            targetRnsLimbCount: 1,
        });
        expect(generation.proofByteLength).toBeGreaterThan(0);

        const verification = kernel.verifyCompactSameSecretBridgeProof({
            context: fixture.context,
            ringDegree: compactVssProofRingDegree,
            compactSameSecretBridge: fixture.compactSameSecretBridge,
            proofBytesHex: generation.proofBytesHex,
        });
        expect(verification).toMatchObject({
            operation: 'verifyCompactSameSecretBridgeProof',
            proofFamily: 'compact-same-secret-bridge',
            statementHash: generation.statementHash,
            proofByteLength: generation.proofByteLength,
        });
        const bridgeStatementSet =
            compactSameSecretBridgeStatementSetFromProofFixture(fixture);
        const bridgeProofMaterialSet =
            createCompactVssSameSecretBridgeProofMaterialSet({
                statementSet: bridgeStatementSet,
                sameSecretConsistency: fixture.sameSecretConsistency,
                sameSecretProofs: fixture.sameSecretProofs,
                proofRecordInputs: [
                    {
                        compactSameSecretBridgeStatementRoot:
                            bridgeStatementSet.statementRecords[0]
                                ?.compactSameSecretBridgeStatementRoot ??
                            (() => {
                                throw new Error(
                                    'compact bridge proof fixture is missing a statement record.',
                                );
                            })(),
                        proofBytesHex: generation.proofBytesHex,
                    },
                ],
            });
        expect(
            verifyCompactVssSameSecretBridgeProofMaterialSet({
                statementSet: bridgeStatementSet,
                sameSecretConsistency: fixture.sameSecretConsistency,
                sameSecretProofs: fixture.sameSecretProofs,
                proofMaterialSet: bridgeProofMaterialSet,
            }),
        ).toBe(bridgeProofMaterialSet);
        const materialVerification =
            kernel.verifyCompactVssSameSecretBridgeProofMaterialSet({
                statementSet: bridgeStatementSet,
                sameSecretConsistency: fixture.sameSecretConsistency,
                sameSecretProofs: fixture.sameSecretProofs,
                proofMaterialSet: bridgeProofMaterialSet,
            });
        expect(materialVerification).toMatchObject({
            operation: 'verifyCompactVssSameSecretBridgeProofMaterialSet',
            compactSameSecretBridgeStatementSetRoot:
                bridgeStatementSet.compactSameSecretBridgeStatementSetRoot,
            proofMaterialSetRoot: bridgeProofMaterialSet.proofMaterialSetRoot,
            proofRecordCount: 1,
            proofVerificationCount: 1,
        });
        const [firstBridgeProofRecord, ...remainingBridgeProofRecords] =
            bridgeProofMaterialSet.proofRecords;
        if (firstBridgeProofRecord === undefined) {
            throw new Error(
                'compact bridge proof material fixture is missing a proof record.',
            );
        }
        const tamperedBridgeProofMaterialSet = {
            ...bridgeProofMaterialSet,
            proofRecords: [
                {
                    ...firstBridgeProofRecord,
                    proofBytesBase64: 'AA==',
                },
                ...remainingBridgeProofRecords,
            ],
        };
        expect(() =>
            kernel.verifyCompactVssSameSecretBridgeProofMaterialSet({
                statementSet: bridgeStatementSet,
                sameSecretConsistency: fixture.sameSecretConsistency,
                sameSecretProofs: fixture.sameSecretProofs,
                proofMaterialSet: tamperedBridgeProofMaterialSet,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        const invalidSecretCoefficients = [...fixture.secretCoefficients];
        invalidSecretCoefficients[0] = 1;
        const invalidNegativeIndicators = [
            ...fixture.negativeIndicatorCoefficients,
        ];
        invalidNegativeIndicators[0] = 0;
        expect(() =>
            kernel.generateCompactSameSecretBridgeProof({
                ...fixture,
                secretCoefficients: invalidSecretCoefficients,
                negativeIndicatorCoefficients: invalidNegativeIndicators,
                ringDegree: compactVssProofRingDegree,
                proofRandomnessSeedHex: '12'.repeat(64),
                proofRandomnessNonceHex: '34'.repeat(64),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        expect(() =>
            kernel.verifyCompactSameSecretBridgeProof({
                context: {
                    ...fixture.context,
                    compactSameSecretBridgeStatementRoot:
                        compactVssProofHash('e'),
                },
                ringDegree: compactVssProofRingDegree,
                compactSameSecretBridge: fixture.compactSameSecretBridge,
                proofBytesHex: generation.proofBytesHex,
            }),
        ).toThrow(/context roots must match/u);

        const tamperedStatement = structuredClone(
            fixture.compactSameSecretBridge,
        );
        const tamperedTargetCommitment = tamperedStatement
            .targetConstantCommitments[0] as {
            readonly commitmentLimbs: {
                readonly modulus: number;
                readonly coordinates: number[];
            }[];
        };
        const firstLimb = tamperedTargetCommitment.commitmentLimbs[0];
        if (firstLimb === undefined) {
            throw new Error(
                'compact bridge proof fixture is missing a commitment limb.',
            );
        }
        firstLimb.coordinates[0] =
            (firstLimb.coordinates[0] + 1) % firstLimb.modulus;

        expect(() =>
            kernel.verifyCompactSameSecretBridgeProof({
                context: fixture.context,
                ringDegree: compactVssProofRingDegree,
                compactSameSecretBridge: tamperedStatement,
                proofBytesHex: generation.proofBytesHex,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('accepts carried aggregate messages within the explicit coefficient bound', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const opening = {
            ...compactVssOpening(),
            messageCoefficients: [1, 2, 98, 4, 5, 6, 7, 8],
            messageCoefficientBound: 194,
        } satisfies BgvCompactVssCommitmentOpeningInput;
        const protocolComputation =
            computeCompactVssCommitmentFromOpening(opening);

        const kernelComputation =
            kernel.computeCompactVssCommitmentFromOpening(opening);

        expect(kernelComputation.commitmentRoot).toBe(
            protocolComputation.commitmentRoot,
        );

        expect(
            kernel.verifyCompactVssCommitmentOpening({
                opening,
                expectedCommitmentRoot: protocolComputation.commitmentRoot,
            }).commitmentRoot,
        ).toBe(protocolComputation.commitmentRoot);

        expect(() =>
            kernel.computeCompactVssCommitmentFromOpening({
                ...opening,
                messageCoefficients: [
                    ...opening.messageCoefficients.slice(0, 3),
                    194,
                    ...opening.messageCoefficients.slice(4),
                ],
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact share-linkage statement roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const linkageEvidence = compactShareLinkageEvidence();
        const { statement } = linkageEvidence;
        const protocolStatement = verifyCompactVssShareLinkageStatement({
            statement,
            coefficientCommitmentSet: linkageEvidence.coefficientCommitmentSet,
            recipientShareCommitmentSet:
                linkageEvidence.recipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                linkageEvidence.aggregateThresholdCommitmentSet,
        });

        const verification = kernel.verifyCompactVssShareLinkageStatement({
            statement,
            coefficientCommitmentSet: linkageEvidence.coefficientCommitmentSet,
            recipientShareCommitmentSet:
                linkageEvidence.recipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                linkageEvidence.aggregateThresholdCommitmentSet,
        });

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssShareLinkageStatement',
            statementRoot: protocolStatement.statementRoot,
            publicMatrixSeedHash: protocolStatement.publicMatrixSeedHash,
            targetBasisHash: protocolStatement.targetBasisHash,
            coefficientCommitmentRoot:
                protocolStatement.coefficientCommitmentRoot,
            recipientShareCommitmentRoot:
                protocolStatement.recipientShareCommitmentRoot,
            aggregateThresholdCommitmentRoot:
                protocolStatement.aggregateThresholdCommitmentRoot,
            participantCount: protocolStatement.participantCount,
            targetRnsLimbCount: protocolStatement.targetRnsLimbCount,
            thresholdDegree: protocolStatement.thresholdDegree,
            proofBatchingRule: compactVssShareLinkageProofBatchingRule,
            shamirEvaluationRule: compactVssShareLinkageShamirEvaluationRule,
            aggregateThresholdRule:
                compactVssShareLinkageAggregateThresholdRule,
            commonKeyRule: compactVssShareLinkageCommonKeyRule,
        });

        const verifyStatementWithoutEvidence = (
            input: Readonly<{ statement: typeof statement }>,
        ): unknown =>
            kernel.verifyCompactVssShareLinkageStatement(
                input as unknown as Parameters<
                    typeof kernel.verifyCompactVssShareLinkageStatement
                >[0],
            );
        expect(() =>
            verifyStatementWithoutEvidence({
                statement,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        expect(() =>
            kernel.verifyCompactVssShareLinkageStatement({
                statement: {
                    ...statement,
                    aggregateThresholdCommitmentRoot: 'c'.repeat(128),
                },
                coefficientCommitmentSet:
                    linkageEvidence.coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    linkageEvidence.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    linkageEvidence.aggregateThresholdCommitmentSet,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact coefficient commitment set roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const coefficientCommitmentSet = compactCoefficientCommitmentSet();
        const protocolCommitmentSet = verifyCompactVssCoefficientCommitmentSet({
            coefficientCommitmentSet,
        });

        const verification = kernel.verifyCompactVssCoefficientCommitmentSet({
            coefficientCommitmentSet,
        });

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssCoefficientCommitmentSet',
            coefficientCommitmentRoot:
                protocolCommitmentSet.coefficientCommitmentRoot,
            publicMatrixSeedHash: protocolCommitmentSet.publicMatrixSeedHash,
            participantCount: protocolCommitmentSet.participantCount,
            rnsLimbCount: protocolCommitmentSet.rnsLimbCount,
            thresholdDegree: protocolCommitmentSet.thresholdDegree,
            ringDegree: protocolCommitmentSet.ringDegree,
        });

        const [firstSourceRecord, secondSourceRecord] =
            coefficientCommitmentSet.sourceTrusteeRecords;
        if (
            firstSourceRecord === undefined ||
            secondSourceRecord === undefined
        ) {
            throw new Error(
                'compact coefficient commitment set must include two source records',
            );
        }
        const targetCoefficient = secondSourceRecord.coefficientCommitments[2];
        if (targetCoefficient === undefined) {
            throw new Error(
                'compact coefficient source record must include the target coefficient',
            );
        }

        expect(() =>
            kernel.verifyCompactVssCoefficientCommitmentSet({
                coefficientCommitmentSet: {
                    ...coefficientCommitmentSet,
                    sourceTrusteeRecords: [
                        firstSourceRecord,
                        {
                            ...secondSourceRecord,
                            coefficientCommitments: [
                                ...secondSourceRecord.coefficientCommitments.slice(
                                    0,
                                    2,
                                ),
                                {
                                    ...targetCoefficient,
                                    coefficientCommitmentRoot: '0'.repeat(128),
                                },
                                ...secondSourceRecord.coefficientCommitments.slice(
                                    3,
                                ),
                            ],
                        },
                    ],
                },
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact recipient-share commitment set roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const recipientShareCommitmentSet =
            compactRecipientShareCommitmentSet();
        const protocolCommitmentSet =
            verifyCompactVssRecipientShareCommitmentSet({
                recipientShareCommitmentSet,
            });

        const verification = kernel.verifyCompactVssRecipientShareCommitmentSet(
            {
                recipientShareCommitmentSet,
            },
        );

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssRecipientShareCommitmentSet',
            recipientShareCommitmentRoot:
                protocolCommitmentSet.recipientShareCommitmentRoot,
            publicMatrixSeedHash: protocolCommitmentSet.publicMatrixSeedHash,
            participantCount: protocolCommitmentSet.participantCount,
            rnsLimbCount: protocolCommitmentSet.rnsLimbCount,
            ringDegree: protocolCommitmentSet.ringDegree,
        });

        const [firstSourceRecord, secondSourceRecord] =
            recipientShareCommitmentSet.sourceTrusteeRecords;
        if (
            firstSourceRecord === undefined ||
            secondSourceRecord === undefined
        ) {
            throw new Error(
                'compact recipient-share commitment set must include two source records',
            );
        }
        const firstRecipientShareCommitment =
            firstSourceRecord.recipientShareCommitments[0];
        const targetRecipientShareCommitment =
            firstSourceRecord.recipientShareCommitments[1];
        if (
            firstRecipientShareCommitment === undefined ||
            targetRecipientShareCommitment === undefined
        ) {
            throw new Error(
                'compact recipient-share source record must include the target share',
            );
        }

        expect(() =>
            kernel.verifyCompactVssRecipientShareCommitmentSet({
                recipientShareCommitmentSet: {
                    ...recipientShareCommitmentSet,
                    sourceTrusteeRecords: [
                        {
                            ...firstSourceRecord,
                            recipientShareCommitments: [
                                firstRecipientShareCommitment,
                                {
                                    ...targetRecipientShareCommitment,
                                    shareCommitmentRoot: 'f'.repeat(128),
                                },
                                ...firstSourceRecord.recipientShareCommitments.slice(
                                    2,
                                ),
                            ],
                        },
                        secondSourceRecord,
                    ],
                },
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact aggregate-threshold commitment set roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const aggregateThresholdCommitmentSet =
            compactAggregateThresholdCommitmentSet();
        const protocolCommitmentSet =
            verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet,
            });

        const verification =
            kernel.verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet,
            });

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssAggregateThresholdCommitmentSet',
            aggregateThresholdCommitmentRoot:
                protocolCommitmentSet.aggregateThresholdCommitmentRoot,
            publicMatrixSeedHash: protocolCommitmentSet.publicMatrixSeedHash,
            participantCount: protocolCommitmentSet.participantCount,
            rnsLimbCount: protocolCommitmentSet.rnsLimbCount,
            ringDegree: protocolCommitmentSet.ringDegree,
        });

        const [firstRecipientRecord, ...remainingRecipientRecords] =
            aggregateThresholdCommitmentSet.recipientRecords;
        if (firstRecipientRecord === undefined) {
            throw new Error(
                'compact aggregate-threshold commitment set must include one recipient record',
            );
        }

        expect(() =>
            kernel.verifyCompactVssAggregateThresholdCommitmentSet({
                aggregateThresholdCommitmentSet: {
                    ...aggregateThresholdCommitmentSet,
                    recipientRecords: [
                        {
                            ...firstRecipientRecord,
                            aggregateCommitmentRoot: 'f'.repeat(128),
                        },
                        ...remainingRecipientRecords,
                    ],
                },
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('verifies compact same-secret bridge statement-set roots through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const evidenceFixture =
            compactSameSecretBridgeStatementSetWithEvidence();
        const statementSet = evidenceFixture.statementSet;
        const protocolStatementSet =
            verifyCompactVssSameSecretBridgeStatementSet({
                statementSet,
                sameSecretConsistency: evidenceFixture.sameSecretConsistency,
                sameSecretProofs: evidenceFixture.sameSecretProofs,
            });

        const verification =
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet,
                sameSecretConsistency: evidenceFixture.sameSecretConsistency,
                sameSecretProofs: evidenceFixture.sameSecretProofs,
            });

        expect(verification).toMatchObject({
            operation: 'verifyCompactVssSameSecretBridgeStatementSet',
            compactSameSecretBridgeStatementSetRoot:
                protocolStatementSet.compactSameSecretBridgeStatementSetRoot,
            participantCount: protocolStatementSet.participantCount,
            targetRnsLimbCount: protocolStatementSet.targetRnsLimbCount,
            thresholdDegree: protocolStatementSet.thresholdDegree,
            targetBasisHash: protocolStatementSet.targetBasisHash,
            publicMatrixSeedHash: protocolStatementSet.publicMatrixSeedHash,
            compactCoefficientCommitmentRoot:
                protocolStatementSet.compactCoefficientCommitmentRoot,
            sameSecretConsistencyRoot:
                protocolStatementSet.sameSecretConsistencyRoot,
            sameSecretProofSetRoot: protocolStatementSet.sameSecretProofSetRoot,
            sameSecretProofFamilyBindingRoot:
                protocolStatementSet.sameSecretProofFamilyBindingRoot,
            integerSupport: compactVssSameSecretBridgeIntegerSupport,
            signedRepresentativeConvention:
                compactVssSameSecretBridgeSignedRepresentativeConvention,
            compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
            targetBasisLimbOrder:
                compactVssSameSecretBridgeTargetBasisLimbOrder,
        });

        const verifyStatementSetWithoutEvidence = (
            input: Readonly<{ statementSet: typeof statementSet }>,
        ): unknown =>
            kernel.verifyCompactVssSameSecretBridgeStatementSet(
                input as unknown as Parameters<
                    typeof kernel.verifyCompactVssSameSecretBridgeStatementSet
                >[0],
            );
        expect(() =>
            verifyStatementSetWithoutEvidence({ statementSet }),
        ).toThrow(TranscriptCoreKernelCommandError);

        const [firstStatementRecord, ...remainingStatementRecords] =
            statementSet.statementRecords;
        if (firstStatementRecord === undefined) {
            throw new Error(
                'compact same-secret bridge statement set must include one statement record',
            );
        }
        const [firstTargetConstantRoot, ...remainingTargetConstantRoots] =
            firstStatementRecord.targetConstantCoefficientCommitmentRoots;
        if (firstTargetConstantRoot === undefined) {
            throw new Error(
                'compact same-secret bridge statement must include one target constant root',
            );
        }

        expect(() =>
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: {
                    ...statementSet,
                    statementRecords: [
                        {
                            ...firstStatementRecord,
                            targetConstantCoefficientCommitmentRoots: [
                                {
                                    ...firstTargetConstantRoot,
                                    coefficientCommitmentRoot: '0'.repeat(128),
                                },
                                ...remainingTargetConstantRoots,
                            ],
                        },
                        ...remainingStatementRecords,
                    ],
                },
                sameSecretConsistency: evidenceFixture.sameSecretConsistency,
                sameSecretProofs: evidenceFixture.sameSecretProofs,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        const evidenceVerification =
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: evidenceFixture.statementSet,
                sameSecretConsistency: evidenceFixture.sameSecretConsistency,
                sameSecretProofs: evidenceFixture.sameSecretProofs,
            });
        expect(evidenceVerification).toMatchObject({
            operation: 'verifyCompactVssSameSecretBridgeStatementSet',
            compactSameSecretBridgeStatementSetRoot:
                evidenceFixture.statementSet
                    .compactSameSecretBridgeStatementSetRoot,
            sameSecretConsistencyRoot:
                evidenceFixture.sameSecretConsistency.sameSecretConsistencyRoot,
            sameSecretProofSetRoot:
                evidenceFixture.sameSecretProofs.sameSecretProofSetRoot,
        });

        const transportedEvidenceFixture =
            compactSameSecretBridgeStatementSetWithTransportedProofBytes();
        if (
            transportedEvidenceFixture.transportedSameSecretProofMaterial ===
            undefined
        ) {
            throw new Error(
                'compact same-secret bridge transported fixture is missing transported proof material.',
            );
        }
        const transportedSameSecretProofMaterial =
            transportedEvidenceFixture.transportedSameSecretProofMaterial;
        const transportedEvidenceVerification =
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: transportedEvidenceFixture.statementSet,
                sameSecretConsistency:
                    transportedEvidenceFixture.sameSecretConsistency,
                sameSecretProofs: transportedEvidenceFixture.sameSecretProofs,
                transportedSameSecretProofMaterial:
                    transportedSameSecretProofMaterial,
            });
        expect(transportedEvidenceVerification).toMatchObject({
            operation: 'verifyCompactVssSameSecretBridgeStatementSet',
            compactSameSecretBridgeStatementSetRoot:
                transportedEvidenceFixture.statementSet
                    .compactSameSecretBridgeStatementSetRoot,
            sameSecretProofSetRoot:
                transportedEvidenceFixture.sameSecretProofs
                    .sameSecretProofSetRoot,
        });

        let missingTransportedMaterialError: unknown;
        try {
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: transportedEvidenceFixture.statementSet,
                sameSecretConsistency:
                    transportedEvidenceFixture.sameSecretConsistency,
                sameSecretProofs: transportedEvidenceFixture.sameSecretProofs,
            });
        } catch (error: unknown) {
            missingTransportedMaterialError = error;
        }
        expect(missingTransportedMaterialError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (
                missingTransportedMaterialError as TranscriptCoreKernelCommandError
            ).message,
        ).toContain('transportedSameSecretProofMaterial');

        const tamperedTransportedSameSecretProofMaterial = structuredClone(
            transportedSameSecretProofMaterial,
        );
        const [tamperedProofMaterial] =
            tamperedTransportedSameSecretProofMaterial.proofMaterials as {
                chunks: { bytesBase64: string }[];
            }[];
        if (tamperedProofMaterial === undefined) {
            throw new Error(
                'compact same-secret bridge transported fixture is missing proof material.',
            );
        }
        const [tamperedChunk] = tamperedProofMaterial.chunks;
        if (tamperedChunk === undefined) {
            throw new Error(
                'compact same-secret bridge transported fixture is missing a proof chunk.',
            );
        }
        tamperedChunk.bytesBase64 = '/w==';
        let tamperedTransportedMaterialError: unknown;
        try {
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: transportedEvidenceFixture.statementSet,
                sameSecretConsistency:
                    transportedEvidenceFixture.sameSecretConsistency,
                sameSecretProofs: transportedEvidenceFixture.sameSecretProofs,
                transportedSameSecretProofMaterial:
                    tamperedTransportedSameSecretProofMaterial,
            });
        } catch (error: unknown) {
            tamperedTransportedMaterialError = error;
        }
        expect(tamperedTransportedMaterialError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (
                tamperedTransportedMaterialError as TranscriptCoreKernelCommandError
            ).message,
        ).toContain('fullObjectHash');

        const [
            evidenceFirstStatementRecord,
            ...remainingEvidenceStatementRecords
        ] = evidenceFixture.statementSet.statementRecords;
        if (evidenceFirstStatementRecord === undefined) {
            throw new Error(
                'compact same-secret bridge evidence fixture must include one statement record',
            );
        }
        const {
            compactSameSecretBridgeStatementRoot: _removedEvidenceStatementRoot,
            ...evidenceFirstStatementRecordWithoutRoot
        } = evidenceFirstStatementRecord;
        const forgedEvidenceStatementRecord =
            rebindCompactSameSecretBridgeStatementRecord({
                ...evidenceFirstStatementRecordWithoutRoot,
                sameSecretProofRoot: '0'.repeat(128),
            });
        const {
            compactSameSecretBridgeStatementSetRoot: _removedEvidenceSetRoot,
            ...evidenceStatementSetWithoutRoot
        } = evidenceFixture.statementSet;

        const sameSecretProofsWithWrongProofBytesHash = structuredClone(
            evidenceFixture.sameSecretProofs,
        ) as unknown as Record<string, unknown> & {
            proofRecords: Record<string, unknown>[];
            sameSecretProofSetRoot: string;
        };
        const proofRecordWithWrongProofBytesHash =
            sameSecretProofsWithWrongProofBytesHash.proofRecords[0];
        if (proofRecordWithWrongProofBytesHash === undefined) {
            throw new Error(
                'compact same-secret bridge evidence fixture must include one proof record',
            );
        }
        proofRecordWithWrongProofBytesHash.proofBytesHash = '0'.repeat(128);
        const {
            sameSecretProofSetRoot: _wrongProofBytesHashSetRoot,
            ...sameSecretProofsWithWrongProofBytesHashWithoutRoot
        } = sameSecretProofsWithWrongProofBytesHash;
        sameSecretProofsWithWrongProofBytesHash.sameSecretProofSetRoot =
            deriveProtocolHash(
                'SameSecretProofRoot',
                sameSecretProofsWithWrongProofBytesHashWithoutRoot,
            );
        const statementSetWithWrongProofBytesHash =
            rebindCompactSameSecretBridgeStatementSet({
                ...evidenceStatementSetWithoutRoot,
                sameSecretProofSetRoot:
                    sameSecretProofsWithWrongProofBytesHash.sameSecretProofSetRoot,
            });
        let wrongProofBytesHashError: unknown;
        try {
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: statementSetWithWrongProofBytesHash,
                sameSecretConsistency: evidenceFixture.sameSecretConsistency,
                sameSecretProofs: sameSecretProofsWithWrongProofBytesHash,
            });
        } catch (error: unknown) {
            wrongProofBytesHashError = error;
        }
        expect(wrongProofBytesHashError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (wrongProofBytesHashError as TranscriptCoreKernelCommandError).code,
        ).toBe('ProfileComponentMismatch');
        expect(
            (wrongProofBytesHashError as TranscriptCoreKernelCommandError)
                .message,
        ).toContain('proofBytesHash');

        const forgedEvidenceStatementSet =
            rebindCompactSameSecretBridgeStatementSet({
                ...evidenceStatementSetWithoutRoot,
                statementRecords: [
                    forgedEvidenceStatementRecord,
                    ...remainingEvidenceStatementRecords,
                ],
            });

        expect(() =>
            verifyStatementSetWithoutEvidence({
                statementSet: forgedEvidenceStatementSet,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        let forgedEvidenceError: unknown;
        try {
            kernel.verifyCompactVssSameSecretBridgeStatementSet({
                statementSet: forgedEvidenceStatementSet,
                sameSecretConsistency: evidenceFixture.sameSecretConsistency,
                sameSecretProofs: evidenceFixture.sameSecretProofs,
            });
        } catch (error: unknown) {
            forgedEvidenceError = error;
        }
        expect(forgedEvidenceError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (forgedEvidenceError as TranscriptCoreKernelCommandError).code,
        ).toBe('ProfileComponentMismatch');
        expect(
            (forgedEvidenceError as TranscriptCoreKernelCommandError).message,
        ).toContain('sameSecretProofRoot');
    });
});
