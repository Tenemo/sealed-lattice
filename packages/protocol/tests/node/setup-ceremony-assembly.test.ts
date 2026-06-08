import {
    createPrivateVssMailboxKeyPair,
    deriveProtocolHash,
    hash512Hex,
} from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    collectForbiddenLocalTrusteeSetupStateFieldPaths,
    collectForbiddenSetupContributionAssemblyFieldPaths,
    collectForbiddenSetupPackageAssemblyFieldPaths,
    createEvaluatorKeySchedule,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createSameSecretConsistencyStatementSet,
    createSetupCeremonyAssembly,
    createSetupPhaseRecord,
    createBinaryChunkedVssCoefficientCommitmentMaterialTransport,
    createVssCoefficientCommitmentBundle,
    type CollectiveBgvSetupContext,
    type EvaluatorKeySchedule,
    type GaloisKeyShareBatchContribution,
    type GaloisKeyShareProofMaterial,
    type PrivateVssMailboxDeliveryKernel,
    type PrivateVssMailboxDeliverySet,
    type PrivateVssShareProofFactory,
    type ProtocolRootSigner,
    type PublicKeyShareContributionInput,
    type PublicKeyShareLnpProofMaterial,
    type PublicKeyShareMaterialContributionInput,
    type RelinearizationKeyShareProofMaterial,
    type RelinearizationRoundOneContribution,
    type RelinearizationRoundTwoContribution,
    type RequiredGaloisKeyScheduleEntry,
    type SameSecretProofMaterial,
    type SetupCeremonyAssemblyInput,
    type SetupCeremonyTrusteeInput,
    type SetupCommonRandomness,
    type SetupPackageCertificateInput,
    type SetupPhaseParticipantObject,
    type SetupPhaseRecord,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
    publicKeyShareCoefficientVectorHashDomain,
    publicKeyShareLnpProofModelStatus,
    publicKeyShareLnpProofVerificationStatus,
    sameSecretLnpProofModelStatus,
    sameSecretLnpProofVerificationStatus,
} from '#packages/protocol/src/index';
import {
    privateVssShareLnpProofModelStatus,
    privateVssShareLnpProofVerificationStatus,
} from '#packages/protocol/src/setup/private-vss-mailbox-delivery';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#tests/support/protocol-signature-fixtures';

const qSharePrimes = [65_537, 114_689, 147_457] as const;
const setupCommitmentModulusLimbs = qSharePrimes;
const ringDegree = 2;
const thresholdDegree = 2;

const fixtureHash = (label: string): string =>
    deriveProtocolHash('ActionContextHash', {
        fixture: 'setup-ceremony-assembly',
        label,
    });

type JsonRecord = Record<string, unknown>;

const jsonRecord = (value: unknown, label: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${label} must be an object.`);
    }

    return value as JsonRecord;
};

const textEncoder = new TextEncoder();

const qShare = {
    objectType: 'QSharePrimeList',
    objectVersion: 1,
    sharingDomain: 'per-rns-prime',
    primeOrder: 'profile-order',
    primes: qSharePrimes,
} as const;

const setupContext = {
    ceremonyId: 'ceremony-1',
    manifestHash: fixtureHash('manifest'),
    rosterHash: fixtureHash('roster'),
    setupProfileHash: fixtureHash('setup-profile'),
    qShareHash: deriveProtocolHash('QSharePrimeListHash', qShare),
    carryAwareVssShareRelationProfileHash: fixtureHash(
        'carry-aware-vss-share-relation-profile',
    ),
    commitmentProfileHash: fixtureHash('commitment-profile'),
    setupEpoch: 'setup-epoch-1',
} satisfies CollectiveBgvSetupContext;

const requiredGaloisKeySchedule = [
    {
        rotation: 3,
        level: 1,
        purpose: 'direct-score-packing-basis',
        proofFamily: 'galois-key-share',
    },
    {
        rotation: 7,
        level: 1,
        purpose: 'packed-rank-return-basis',
        proofFamily: 'galois-key-share',
    },
] as const satisfies readonly RequiredGaloisKeyScheduleEntry[];

const setupProofBinding = {
    objectType: 'SetupCeremonyAssemblyProofBindingFixture',
    objectVersion: 1,
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    setupEpoch: setupContext.setupEpoch,
} as const;

const sameSecretTboxParameterProfileHash = fixtureHash('same-secret-tbox');
const publicKeyShareTboxParameterProfileHash = fixtureHash(
    'public-key-share-tbox',
);
const privateVssShareTboxParameterProfileHash = fixtureHash(
    'private-vss-share-tbox',
);
const relinearizationKeyShareTboxParameterProfileHash = fixtureHash(
    'relinearization-key-share-tbox',
);
const galoisKeyShareTboxParameterProfileHash = fixtureHash(
    'galois-key-share-tbox',
);
const setupProofFamilies = [
    'vss-opening-carry',
    'same-secret-consistency',
    'public-key-share',
    'relinearization-key-share',
    'galois-key-share',
] as const;
const setupProofChallengeDifferenceInvertibilityStatus =
    'repo-owned-lnp22-small-coefficient-challenge-differences-invertible';
const setupProofLnpTboxProofRingDegree = 128;
const setupProofLnpTboxChallengeLog2Range = 3;
const setupProofLnpTboxChallengeEncodedBits =
    setupProofLnpTboxProofRingDegree * setupProofLnpTboxChallengeLog2Range;
const setupProofLnpTboxChallengeSpaceBits = 147;
const setupProofChallengeSamplePositions = [0, 1, 63, 64, 65, 127] as const;
const setupProofChallengeDifferenceInvertibilityAccounting = {
    objectType: 'SetupProofChallengeDifferenceInvertibilityAccounting',
    objectVersion: 1,
    setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
    proofRing: 'Z_qproof[X]/(X^d+1)',
    proofRingDegree: 128,
    proofModulusDecimal:
        '57896044618658097711785492504343953926634992332820282019728792003956564819949',
    proofModulusBitCount: 255,
    challengeCoefficientBound: 2,
    challengeDifferenceCoefficientBound: '4',
    condition: '4 * challengeCoefficientBound^2 < proofModulus',
    conditionLeftDecimal: '16',
    conditionRightDecimal:
        '57896044618658097711785492504343953926634992332820282019728792003956564819949',
    conditionSatisfied: true,
    referenceRows: [
        {
            document:
                'LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General',
            localReferencePath:
                'reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt',
            sections: [
                'Section 2.7 Challenge Space',
                'Appendix A, Theorem A.2 knowledge soundness',
            ],
        },
    ],
    status: setupProofChallengeDifferenceInvertibilityStatus,
} as const;

const setupPhaseOrder = [
    ['rosterFreeze', 1],
    ['setupIntent', 2],
    ['commonRandomnessCommit', 3],
    ['commonRandomnessReveal', 4],
    ['vssCoefficientCommitments', 5],
    ['privateVssEnvelopeDelivery', 6],
    ['recipientVssVerification', 7],
    ['vssAcceptanceOrComplaint', 8],
    ['publicKeyShareProofs', 9],
    ['relinearizationRoundOne', 10],
    ['relinearizationRoundTwo', 11],
    ['galoisKeyBatchProofs', 12],
    ['setupPackageAssembly', 13],
    ['setupPackageVerification', 14],
] as const;

type CeremonyKernelFixture = Readonly<{
    readonly kernel: PrivateVssMailboxDeliveryKernel;
    readonly verifiedExpectedEnvelopeCount: () => number;
}>;

type CeremonyEvaluationKeyFixture = Readonly<{
    readonly relinearizationRoundOneContributions: readonly RelinearizationRoundOneContribution[];
    readonly relinearizationRoundTwoContributions: readonly RelinearizationRoundTwoContribution[];
    readonly galoisKeyShareBatchContributions: readonly GaloisKeyShareBatchContribution[];
}>;

const proofBytesHex = (
    sourceTrusteeRosterPosition: number,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): string =>
    [sourceTrusteeRosterPosition, recipientRosterPosition, rnsLimbIndex]
        .map((value) => value.toString(16).padStart(2, '0'))
        .join('');

const proofBytes = (bytesHex: string): Uint8Array =>
    Uint8Array.from(
        Array.from({ length: bytesHex.length / 2 }, (_unused, byteIndex) =>
            Number.parseInt(
                bytesHex.slice(byteIndex * 2, byteIndex * 2 + 2),
                16,
            ),
        ),
    );

const sameSecretProofMaterial = (
    trusteeRosterPosition: number,
): SameSecretProofMaterial => {
    const proofMaterialBytesHex = `aa55${trusteeRosterPosition.toString(16).padStart(4, '0')}`;

    return {
        setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
        proofFamily: 'same-secret-consistency',
        proofVerificationStatus: sameSecretLnpProofVerificationStatus,
        proofModelStatus: sameSecretLnpProofModelStatus,
        sameSecretTboxParameterProfileHash,
        trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
        trusteeRosterPosition,
        statementHash: fixtureHash(
            `same-secret-statement-${String(trusteeRosterPosition)}`,
        ),
        relationCommitmentHash: fixtureHash(
            `same-secret-relation-${String(trusteeRosterPosition)}`,
        ),
        tboxCommitmentPrefixHash: fixtureHash(
            `same-secret-tbox-prefix-${String(trusteeRosterPosition)}`,
        ),
        challenge: 17 + trusteeRosterPosition,
        proofSizeBytes: proofMaterialBytesHex.length / 2,
        proofBytesHash: fixtureHash(
            `same-secret-proof-bytes-${String(trusteeRosterPosition)}`,
        ),
        proofBytesHex: proofMaterialBytesHex,
    };
};

const publicKeyShareLnpProofMaterial = (
    trusteeRosterPosition: number,
): PublicKeyShareLnpProofMaterial => {
    const proofMaterialBytesHex = `bb66${trusteeRosterPosition.toString(16).padStart(4, '0')}`;

    return {
        setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
        proofFamily: 'public-key-share',
        proofVerificationStatus: publicKeyShareLnpProofVerificationStatus,
        proofModelStatus: publicKeyShareLnpProofModelStatus,
        publicKeyShareTboxParameterProfileHash,
        trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
        trusteeRosterPosition,
        statementHash: fixtureHash(
            `public-key-lnp-statement-${String(trusteeRosterPosition)}`,
        ),
        relationCommitmentHash: fixtureHash(
            `public-key-lnp-relation-${String(trusteeRosterPosition)}`,
        ),
        tboxCommitmentPrefixHash: fixtureHash(
            `public-key-lnp-tbox-prefix-${String(trusteeRosterPosition)}`,
        ),
        challenge: 29 + trusteeRosterPosition,
        proofSizeBytes: proofMaterialBytesHex.length / 2,
        proofBytesHash: fixtureHash(
            `public-key-lnp-proof-bytes-${String(trusteeRosterPosition)}`,
        ),
        proofBytesHex: proofMaterialBytesHex,
    };
};

const privateVssShareProofFactory: PrivateVssShareProofFactory = (input) => {
    const proofMaterialBytesHex = proofBytesHex(
        input.sourceTrusteeContributionState.sourceTrusteeRosterPosition,
        input.recipient.recipientRosterPosition,
        input.rnsLimbIndex,
    );
    const proofMaterialBytesHash = hash512Hex(
        'sealed-lattice/setup/private-vss-share/lnp-proof-bytes-v1',
        [proofBytes(proofMaterialBytesHex)],
    );

    return {
        objectType: 'PrivateVssShareProof',
        objectVersion: 1,
        proofProfileId: 'sealed-lattice-private-vss-share-proof-lnp-v1',
        setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
        proofFamily: 'vss-opening-carry',
        proofBytesEncoding: 'embedded-binary-proof-bytes-hex',
        privateVssShareTboxParameterProfileHash,
        proofVerificationStatus: privateVssShareLnpProofVerificationStatus,
        proofModelStatus: privateVssShareLnpProofModelStatus,
        proofStatementRoot: deriveProtocolHash(
            'PrivateVssShareProofStatementRoot',
            {
                sourceTrusteeRosterPosition:
                    input.sourceTrusteeContributionState
                        .sourceTrusteeRosterPosition,
                recipientRosterPosition:
                    input.recipient.recipientRosterPosition,
                rnsLimbIndex: input.rnsLimbIndex,
                privateEnvelopeAadHash: input.privateEnvelopeAadHash,
            },
        ),
        statementHash: fixtureHash('private-vss-statement'),
        relationCommitmentHash: fixtureHash('private-vss-relation'),
        tboxCommitmentPrefixHash: fixtureHash('private-vss-tbox-prefix'),
        challenge: 17,
        proofSizeBytes: proofMaterialBytesHex.length / 2,
        proofBytesHash: proofMaterialBytesHash,
        proofMaterialRoot: deriveProtocolHash(
            'PrivateVssShareProofMaterialRoot',
            { proofBytesHash: proofMaterialBytesHash },
        ),
        proofBytesHex: proofMaterialBytesHex,
    };
};

const createKernelFixture = (): CeremonyKernelFixture => {
    let verifiedExpectedEnvelopeCount = 0;

    return {
        verifiedExpectedEnvelopeCount: () => verifiedExpectedEnvelopeCount,
        kernel: {
            deriveProtocolHash: ({ namespace, value }) =>
                deriveProtocolHash(namespace, value),
            verifyPrivateVssShareEnvelope: (input) => {
                const privateEnvelope = input.privateEnvelope as Record<
                    string,
                    unknown
                >;
                const privateEnvelopeHash = deriveProtocolHash(
                    'PrivateVssShareEnvelopeHash',
                    privateEnvelope,
                );
                const sourceTrusteeRecord =
                    input.sourceTrusteeCoefficientCommitmentRecord as Record<
                        string,
                        unknown
                    >;
                const materialRecords =
                    input.sourceTrusteeCoefficientCommitmentMaterialRecords as readonly Record<
                        string,
                        unknown
                    >[];
                const sourceTrusteeRosterPosition =
                    sourceTrusteeRecord.sourceTrusteeRosterPosition;

                if (input.expectedPrivateEnvelopeHash !== undefined) {
                    verifiedExpectedEnvelopeCount += 1;
                }
                if (
                    materialRecords.some(
                        (record) =>
                            record.sourceTrusteeRosterPosition !==
                            sourceTrusteeRosterPosition,
                    )
                ) {
                    return {
                        ok: false,
                        privateEnvelopeHash,
                        localVerificationRoot: null,
                        refusedObjects: [
                            {
                                reasonCode: 'mixed-source-material',
                                message:
                                    'private VSS verification received public material for a different source trustee',
                            },
                        ],
                    };
                }

                const localVerificationRoot = deriveProtocolHash(
                    'PrivateVssLocalVerificationRoot',
                    {
                        fixture:
                            'setup-ceremony-assembly-local-verification-root',
                        privateEnvelopeHash,
                        sourceTrusteeCommitmentRoot:
                            sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
                    },
                );

                if (
                    input.expectedPrivateEnvelopeHash !== undefined &&
                    input.expectedPrivateEnvelopeHash !== privateEnvelopeHash
                ) {
                    return {
                        ok: false,
                        privateEnvelopeHash,
                        localVerificationRoot,
                        refusedObjects: [
                            {
                                reasonCode: 'private-envelope-hash-mismatch',
                                message:
                                    'expected private envelope hash did not match the decrypted envelope',
                            },
                        ],
                    };
                }
                if (
                    input.expectedLocalVerificationRoot !== undefined &&
                    input.expectedLocalVerificationRoot !==
                        localVerificationRoot
                ) {
                    return {
                        ok: false,
                        privateEnvelopeHash,
                        localVerificationRoot,
                        refusedObjects: [
                            {
                                reasonCode: 'local-verification-root-mismatch',
                                message:
                                    'expected local verification root did not match the verifier output',
                            },
                        ],
                    };
                }

                return {
                    ok: true,
                    privateEnvelopeHash,
                    localVerificationRoot,
                    refusedObjects: [],
                };
            },
        },
    };
};

const createRefusingKernelFixture = (): CeremonyKernelFixture => {
    const kernelFixture = createKernelFixture();

    return {
        verifiedExpectedEnvelopeCount:
            kernelFixture.verifiedExpectedEnvelopeCount,
        kernel: {
            ...kernelFixture.kernel,
            verifyPrivateVssShareEnvelope: (input) => {
                const result =
                    kernelFixture.kernel.verifyPrivateVssShareEnvelope(input);
                const privateEnvelope = input.privateEnvelope as Record<
                    string,
                    unknown
                >;
                if (
                    input.expectedPrivateEnvelopeHash !== undefined &&
                    privateEnvelope.sourceTrusteeRosterPosition === 0 &&
                    privateEnvelope.recipientRosterPosition === 0
                ) {
                    return {
                        ...result,
                        ok: false,
                        refusedObjects: [
                            {
                                reasonCode:
                                    'recipient-local-verification-refused',
                                message:
                                    'recipient re-verification refused the decrypted private VSS envelope',
                            },
                        ],
                    };
                }

                return result;
            },
        },
    };
};

const coefficientMessage = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    rnsPrime: number,
): readonly number[] =>
    Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
        const value =
            (sourceTrusteeRosterPosition + 1) * 31 +
            (rnsLimbIndex + 1) * 17 +
            (shamirCoefficientIndex + 1) * 7 +
            coefficientIndex * 3;

        return value % rnsPrime;
    });

const randomnessByColumn = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): readonly (readonly number[])[] =>
    Array.from({ length: 5 }, (_unusedColumn, randomnessColumnIndex) =>
        Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
            const selector =
                (sourceTrusteeRosterPosition +
                    rnsLimbIndex +
                    shamirCoefficientIndex +
                    randomnessColumnIndex +
                    coefficientIndex) %
                3;

            return selector === 0 ? -1 : selector === 1 ? 0 : 1;
        }),
    );

const coefficientOpening = (
    sourceTrusteeRosterPosition: number,
    rnsPrime: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => ({
    rnsLimbIndex,
    rnsPrime,
    shamirCoefficientIndex,
    coefficientMessage: coefficientMessage(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
        rnsPrime,
    ),
    randomnessByColumn: randomnessByColumn(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
    ),
});

const sourceTrusteeOpeningState = (
    sourceTrusteeRosterPosition: number,
): VssSourceTrusteeCoefficientOpeningState => ({
    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
    sourceTrusteeRosterPosition,
    coefficientOpenings: qSharePrimes.flatMap((rnsPrime, rnsLimbIndex) =>
        Array.from({ length: thresholdDegree }, (_unused, coefficientIndex) =>
            coefficientOpening(
                sourceTrusteeRosterPosition,
                rnsPrime,
                rnsLimbIndex,
                coefficientIndex,
            ),
        ),
    ),
});

const publicKeyShareContribution = (
    materialContribution: PublicKeyShareMaterialContributionInput,
): PublicKeyShareContributionInput => ({
    trusteeIdentity: materialContribution.trusteeIdentity,
    trusteeRosterPosition: materialContribution.trusteeRosterPosition,
    shareCoefficientVectorHash512ByLimb:
        materialContribution.shareCoefficientVectorsByLimb.map(
            (coefficientVector) => ({
                rnsLimbIndex: coefficientVector.rnsLimbIndex,
                rnsPrime: coefficientVector.rnsPrime,
                component: coefficientVector.component,
                coefficientVectorHash512:
                    coefficientVector.coefficientVectorHash512,
            }),
        ),
});

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        let value = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(value & 0xffn);
            value >>= 8n;
        }
    });

    return bytes;
};

const coefficientVectorLeHex = (coefficients: readonly number[]): string =>
    Array.from(coefficientVectorBytes(coefficients), (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');

const publicKeyShareCoefficientVectorHash = (
    coefficients: readonly number[],
): string =>
    hash512Hex(publicKeyShareCoefficientVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

const publicKeyShareCoefficients = (
    trusteeRosterPosition: number,
    rnsLimbIndex: number,
    rnsPrime: number,
): readonly number[] =>
    Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
        const value =
            (trusteeRosterPosition + 1) * 101 +
            (rnsLimbIndex + 1) * 29 +
            coefficientIndex * 13;

        return value % rnsPrime;
    });

const publicKeyShareMaterialContribution = (
    trusteeRosterPosition: number,
): PublicKeyShareMaterialContributionInput => ({
    trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
    trusteeRosterPosition,
    shareCoefficientVectorsByLimb: qSharePrimes.map(
        (rnsPrime, rnsLimbIndex) => {
            const coefficients = publicKeyShareCoefficients(
                trusteeRosterPosition,
                rnsLimbIndex,
                rnsPrime,
            );

            return {
                rnsLimbIndex,
                rnsPrime,
                component: 'b_i',
                coefficientByteLength: ringDegree * 8,
                coefficientVectorHash512:
                    publicKeyShareCoefficientVectorHash(coefficients),
                coefficientsLeHex: coefficientVectorLeHex(coefficients),
            };
        },
    ),
});

const relinearizationKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    round: 'round-one' | 'round-two',
    level: number,
): string =>
    deriveProtocolHash('RelinearizationKeyShareSeed', {
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
        proofFamily: 'relinearization-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-level-and-round',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        relinearizationCrpRoot: evaluatorKeySchedule.relinearizationCrpRoot,
        round,
        level,
    });

const galoisKeySwitchSeed = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    rotation: number,
    level: number,
): string =>
    deriveProtocolHash('GaloisKeyShareSeed', {
        objectType: 'GaloisKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
        proofFamily: 'galois-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-rotation-and-level',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        galoisKeyCrpRoot: evaluatorKeySchedule.galoisKeyCrpRoot,
        requiredGaloisSetHash: evaluatorKeySchedule.requiredGaloisSetHash,
        rotation,
        level,
    });

const relinearizationProofMaterial = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    shareRoot: string,
    label: string,
    round: 'round-one' | 'round-two',
    level: number,
): RelinearizationKeyShareProofMaterial => ({
    proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1',
    setupProofBinding: {
        objectType: 'SetupCeremonyAssemblyProofBindingFixture',
        label,
    },
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: 'relinearization',
    keySwitchSeedHex: relinearizationKeySwitchSeed(
        evaluatorKeySchedule,
        round,
        level,
    ),
    ringDegree,
    keySwitchComponentVectorRoot: shareRoot,
    keySwitchComponentVectors: [
        {
            component: 'b',
            digitIndex: 0,
            vectorHash: fixtureHash(`component-vector-${label}`),
        },
    ],
    relinearizationKeyShareTboxParameterProfileHash: fixtureHash(
        `relinearization-tbox-${label}`,
    ),
    statementHash: fixtureHash(`statement-${label}`),
    relationCommitmentHash: fixtureHash(`relation-commitment-${label}`),
    tboxCommitmentPrefixHash: fixtureHash(`tbox-commitment-${label}`),
    challenge: 17,
    proofSizeBytes: 4,
    proofBytesHash: fixtureHash(`proof-bytes-${label}`),
    proofBytesHex: '00112233',
});

const galoisProofMaterial = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    shareRoot: string,
    label: string,
    rotation: number,
    level: number,
): GaloisKeyShareProofMaterial => ({
    proofProfileId: 'sealed-lattice-galois-key-share-proof-lnp-v1',
    setupProofBinding: {
        objectType: 'SetupCeremonyAssemblyProofBindingFixture',
        label,
    },
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: `galois-${String(rotation)}`,
    keySwitchSeedHex: galoisKeySwitchSeed(
        evaluatorKeySchedule,
        rotation,
        level,
    ),
    ringDegree,
    keySwitchComponentVectorRoot: shareRoot,
    keySwitchComponentVectors: [
        {
            component: 'b',
            digitIndex: 0,
            vectorHash: fixtureHash(`galois-component-vector-${label}`),
        },
    ],
    galoisKeyShareTboxParameterProfileHash: fixtureHash(`galois-tbox-${label}`),
    statementHash: fixtureHash(`galois-statement-${label}`),
    relationCommitmentHash: fixtureHash(`galois-relation-commitment-${label}`),
    tboxCommitmentPrefixHash: fixtureHash(`galois-tbox-commitment-${label}`),
    challenge: 19,
    proofSizeBytes: 4,
    proofBytesHash: fixtureHash(`galois-proof-bytes-${label}`),
    proofBytesHex: '44556677',
});

const evaluationKeyFixture = (
    participantCount: number,
    sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[],
    publicKeyShareContributions: readonly PublicKeyShareContributionInput[],
): CeremonyEvaluationKeyFixture => {
    const vssCoefficientCommitmentBundle = createVssCoefficientCommitmentBundle(
        {
            setupContext,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes,
            ringDegree,
            participantCount,
            thresholdDegree,
            sourceTrusteeOpeningStates,
        },
    );
    const sameSecretConsistency = createSameSecretConsistencyStatementSet({
        setupContext,
        qSharePrimes,
        participantCount,
        thresholdDegree,
        vssCoefficientCommitments: vssCoefficientCommitmentBundle.commitmentSet,
    });
    const publicKeyShares = createPublicKeyShareSet({
        setupContext,
        qSharePrimes,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        sameSecretConsistency,
        shareContributions: publicKeyShareContributions,
    });
    const publicKeyShareProofs = createPublicKeyShareProofSet({
        setupContext,
        qSharePrimes,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        sameSecretConsistency,
        publicKeyShares,
    });
    const evaluatorKeySchedule = createEvaluatorKeySchedule({
        setupContext,
        qSharePrimes,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        relinearizationCrpRoot: fixtureHash('relinearization-crp'),
        galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
        sameSecretConsistency,
        publicKeyShares,
        publicKeyShareProofs,
        requiredGaloisKeySchedule,
    });
    const sameSecretProofReferences =
        sameSecretConsistency.statementRecords.map((statementRecord) => ({
            trusteeIdentity: statementRecord.trusteeIdentity,
            trusteeRosterPosition: statementRecord.trusteeRosterPosition,
            sameSecretStatementRoot: statementRecord.sameSecretStatementRoot,
            trusteeSecretCommitmentRoot:
                statementRecord.trusteeSecretCommitmentRoot,
            sameSecretProofRoot: fixtureHash(
                `same-secret-proof-${String(
                    statementRecord.trusteeRosterPosition,
                )}`,
            ),
        }));

    return {
        relinearizationRoundOneContributions:
            evaluatorKeySchedule.relinearizationLevelSchedule.flatMap(
                (scheduleEntry) =>
                    sameSecretProofReferences.map((reference) => {
                        const roundOneShareRoot = fixtureHash(
                            `round-one-share-${String(
                                reference.trusteeRosterPosition,
                            )}-${String(scheduleEntry.level)}`,
                        );

                        return {
                            trusteeRosterPosition:
                                reference.trusteeRosterPosition,
                            level: scheduleEntry.level,
                            roundOneShareRoot,
                            proofMaterial: relinearizationProofMaterial(
                                evaluatorKeySchedule,
                                roundOneShareRoot,
                                `round-one-${String(
                                    reference.trusteeRosterPosition,
                                )}-${String(scheduleEntry.level)}`,
                                'round-one',
                                scheduleEntry.level,
                            ),
                        };
                    }),
            ),
        relinearizationRoundTwoContributions:
            evaluatorKeySchedule.relinearizationLevelSchedule.flatMap(
                (scheduleEntry) =>
                    sameSecretProofReferences.map((reference) => {
                        const roundTwoShareRoot = fixtureHash(
                            `round-two-share-${String(
                                reference.trusteeRosterPosition,
                            )}-${String(scheduleEntry.level)}`,
                        );

                        return {
                            trusteeRosterPosition:
                                reference.trusteeRosterPosition,
                            level: scheduleEntry.level,
                            roundTwoShareRoot,
                            proofMaterial: relinearizationProofMaterial(
                                evaluatorKeySchedule,
                                roundTwoShareRoot,
                                `round-two-${String(
                                    reference.trusteeRosterPosition,
                                )}-${String(scheduleEntry.level)}`,
                                'round-two',
                                scheduleEntry.level,
                            ),
                        };
                    }),
            ),
        galoisKeyShareBatchContributions: sameSecretProofReferences.map(
            (reference) => ({
                trusteeRosterPosition: reference.trusteeRosterPosition,
                galoisKeyShareProofs: requiredGaloisKeySchedule.map(
                    (scheduleEntry) => {
                        const galoisKeyShareRoot = fixtureHash(
                            `galois-share-${String(
                                reference.trusteeRosterPosition,
                            )}-${String(scheduleEntry.rotation)}-${String(
                                scheduleEntry.level,
                            )}`,
                        );

                        return {
                            rotation: scheduleEntry.rotation,
                            level: scheduleEntry.level,
                            galoisKeyShareRoot,
                            proofMaterial: galoisProofMaterial(
                                evaluatorKeySchedule,
                                galoisKeyShareRoot,
                                `${String(
                                    reference.trusteeRosterPosition,
                                )}-${String(scheduleEntry.rotation)}-${String(
                                    scheduleEntry.level,
                                )}`,
                                scheduleEntry.rotation,
                                scheduleEntry.level,
                            ),
                        };
                    },
                ),
            }),
        ),
    };
};

const phaseParticipantObjectFixture = (
    trustee: Readonly<{
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly recoveryEpoch: number;
        readonly deviceEpoch: number;
        readonly signingPublicKeyHash: string;
    }>,
    phaseId: string,
    phaseNumber: number,
): SetupPhaseParticipantObject =>
    ({
        objectType: 'SetupPhaseParticipantObject',
        objectVersion: 1,
        phaseId,
        phaseNumber,
        ceremonyId: setupContext.ceremonyId,
        manifestHash: setupContext.manifestHash,
        rosterHash: setupContext.rosterHash,
        setupProfileHash: setupContext.setupProfileHash,
        commitmentProfileHash: setupContext.commitmentProfileHash,
        setupEpoch: setupContext.setupEpoch,
        signerRole: 'Trustee',
        trusteeIdentity: trustee.trusteeIdentity,
        rosterPosition: trustee.trusteeRosterPosition,
        recoveryEpoch: trustee.recoveryEpoch,
        deviceEpoch: trustee.deviceEpoch,
        signingPublicKeyHash: trustee.signingPublicKeyHash,
        phaseObjectRoot: fixtureHash(
            `phase-object-${phaseId}-${String(trustee.trusteeRosterPosition)}`,
        ),
        phaseObjectByteLength: 256 + phaseNumber,
        phaseSignatureContextHash: fixtureHash(
            `phase-context-${phaseId}-${String(trustee.trusteeRosterPosition)}`,
        ),
        signatureEnvelopeHash: fixtureHash(
            `phase-signature-envelope-${phaseId}-${String(
                trustee.trusteeRosterPosition,
            )}`,
        ),
        signatureEnvelope: {
            signatureHash: fixtureHash(
                `phase-signature-${phaseId}-${String(
                    trustee.trusteeRosterPosition,
                )}`,
            ),
        },
    }) as unknown as SetupPhaseParticipantObject;

const phaseTranscriptFixture = (
    trustees: readonly SetupCeremonyTrusteeInput[],
): readonly SetupPhaseRecord[] => {
    let previousPhaseRoot: string | null = null;

    return setupPhaseOrder.map(([phaseId, phaseNumber]) => {
        const phaseRecord = createSetupPhaseRecord({
            setupContext,
            phaseId,
            phaseNumber,
            previousPhaseRoot,
            participantPhaseObjects: trustees.map((trustee) => {
                const phaseObject = trustee.setupPhaseParticipantObjects?.find(
                    (candidatePhaseObject) =>
                        candidatePhaseObject.phaseId === phaseId,
                );
                if (phaseObject === undefined) {
                    throw new Error(
                        `phase participant object for ${phaseId} is missing.`,
                    );
                }

                return phaseObject;
            }),
        });
        previousPhaseRoot = phaseRecord.phaseRoot;

        return phaseRecord;
    });
};

const commonRandomnessFixture = (): SetupCommonRandomness => {
    const publicDerivationsWithoutRoot = {
        objectType: 'SetupPublicDerivations',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
    } as const;
    const publicDerivations = {
        ...publicDerivationsWithoutRoot,
        publicDerivationRoot: deriveProtocolHash(
            'SetupPublicDerivationRoot',
            publicDerivationsWithoutRoot,
        ),
    };
    const commonRandomnessWithoutRoot = {
        objectType: 'SetupCommonRandomness',
        objectVersion: 1,
        ceremonyId: setupContext.ceremonyId,
        manifestHash: setupContext.manifestHash,
        rosterHash: setupContext.rosterHash,
        setupProfileHash: setupContext.setupProfileHash,
        setupEpoch: setupContext.setupEpoch,
        commitRecords: [],
        revealRecords: [],
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicDerivations,
    } as const;

    return {
        ...commonRandomnessWithoutRoot,
        commonRandomnessRoot: deriveProtocolHash(
            'SetupCommonRandomnessRoot',
            commonRandomnessWithoutRoot,
        ),
    };
};

const setupProofChallengeSampleValue = (
    proofFamilyIndex: number,
    sampleIndex: number,
): number => ((proofFamilyIndex * 2 + sampleIndex * 3) % 5) - 2;

const setupProofChallengeFamilySamples = (): Record<string, unknown>[] =>
    setupProofFamilies.map((proofFamily, proofFamilyIndex) => ({
        proofFamily,
        statementHash: hash512Hex(
            'sealed-lattice/collective-bgv-setup/challenge-audit-statement-v1',
            [textEncoder.encode(proofFamily)],
        ),
        relationCommitmentHash: hash512Hex(
            'sealed-lattice/collective-bgv-setup/challenge-audit-relation-commitment-v1',
            [textEncoder.encode(proofFamily)],
        ),
        sampledCoefficients: setupProofChallengeSamplePositions.map(
            (coefficientPosition, sampleIndex) => ({
                coefficientPosition,
                coefficientValue: setupProofChallengeSampleValue(
                    proofFamilyIndex,
                    sampleIndex,
                ),
            }),
        ),
    }));

const setupProofSampledDifferenceChecks = (): Record<string, unknown>[] => {
    const checks: Record<string, unknown>[] = [];
    for (
        let leftProofFamilyIndex = 0;
        leftProofFamilyIndex < setupProofFamilies.length;
        leftProofFamilyIndex += 1
    ) {
        for (
            let rightProofFamilyIndex = leftProofFamilyIndex + 1;
            rightProofFamilyIndex < setupProofFamilies.length;
            rightProofFamilyIndex += 1
        ) {
            checks.push({
                leftProofFamily: setupProofFamilies[leftProofFamilyIndex],
                rightProofFamily: setupProofFamilies[rightProofFamilyIndex],
                coefficientInfinityNorm: 4,
                differenceCoefficientBound: 4,
                sampledDifferenceCoefficients:
                    setupProofChallengeSamplePositions.map(
                        (coefficientPosition, sampleIndex) => ({
                            coefficientPosition,
                            coefficientValue:
                                setupProofChallengeSampleValue(
                                    leftProofFamilyIndex,
                                    sampleIndex,
                                ) -
                                setupProofChallengeSampleValue(
                                    rightProofFamilyIndex,
                                    sampleIndex,
                                ),
                        }),
                    ),
                invertibleOverProofRing: true,
            });
        }
    }

    return checks;
};

const setupCertificateInputFixture = (
    participantCount: number,
    fullMaterialCoefficientBytes = 1,
): SetupPackageCertificateInput => {
    const commitmentProfile = {
        objectType: 'SetupCommitmentProfile',
        objectVersion: 1,
        messageEncoding: {
            commitmentModulusLimbs: setupCommitmentModulusLimbs,
        },
    };
    const setupProofProfile = {
        objectType: 'SetupProofProfile',
        objectVersion: 1,
        profileId: 'SealedLattice-LNP-SetupProof-v1',
        setupProfileId: 'CollectiveBgvSetup-v1',
        proofSystem: 'fixed-lnp-linear-relation-subset',
        relationModel: {
            applicationRingDegree: ringDegree,
        },
        challengeBinding: {
            transform: 'Fiat-Shamir',
            challengeBits: 128,
            challengeCount: 1,
            challengeDomain:
                'sealed-lattice/collective-bgv-setup/lnp-challenge-v1',
            challengeDomainHash: fixtureHash('setup-proof-challenge-domain'),
            challengeCoefficientBound: 2,
            lnpTboxProofRingDegree: 128,
            lnpTboxChallengeLog2Range: 3,
            lnpTboxChallengeEncodedBits: 384,
            lnpTboxChallengeSpaceBits: 147,
            challengeSpace:
                'fixed-lnp-small-coefficient-polynomial-challenge-set',
            challengeSampler:
                'sealed-lattice-shake256-lazer-autostable-rejection-v1',
            challengeDifferenceInvertibilityStatus:
                setupProofChallengeDifferenceInvertibilityStatus,
            challengeDifferenceInvertibilityAccounting:
                setupProofChallengeDifferenceInvertibilityAccounting,
            qromStatus:
                'repo-owned-qrom-accounting-required-before-claim-closure',
            transcriptBinding: [
                'setupProfileHash',
                'manifestHash',
                'rosterHash',
                'setupEpoch',
                'publicMatrixSeedHash',
                'proofFamily',
                'statementRoot',
                'proofChunkRoot',
            ],
        },
        challengeSpaceAudit: {
            objectType: 'SetupProofChallengeSpaceAudit',
            objectVersion: 1,
            setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
            proofFamilies: setupProofFamilies,
            applicationRingDegree: ringDegree,
            lnpTboxProofRingDegree: 128,
            challengeCoefficientBound: 2,
            lnpTboxChallengeLog2Range: 3,
            lnpTboxChallengeEncodedBits: 384,
            lnpTboxChallengeSpaceBits: 147,
            challengeSpace:
                'fixed-lnp-small-coefficient-polynomial-challenge-set',
            challengeSampler:
                'sealed-lattice-shake256-lazer-autostable-rejection-v1',
            challengeSeedDomain:
                'sealed-lattice/collective-bgv-setup/lnp-challenge-seed-v1',
            challengeStreamDomain:
                'sealed-lattice/collective-bgv-setup/lnp-challenge-stream-v1',
            challengeDifferenceInvertibilityStatus:
                setupProofChallengeDifferenceInvertibilityStatus,
            challengeDifferenceInvertibilityAccounting:
                setupProofChallengeDifferenceInvertibilityAccounting,
            familySamples: setupProofChallengeFamilySamples(),
            sampledDifferenceChecks: setupProofSampledDifferenceChecks(),
        },
        proofFamilies: setupProofFamilies.map((proofFamily) => ({
            proofFamily,
        })),
        privateVssShareTboxParameterProfileHash,
        sameSecretTboxParameterProfileHash,
        publicKeyShareTboxParameterProfileHash,
        relinearizationKeyShareTboxParameterProfileHash,
        galoisKeyShareTboxParameterProfileHash,
        verificationPolicy: {
            proofBytesAcceptedStatus:
                'private-vss-same-secret-public-key-share-relinearization-and-galois-proof-bytes-accepted-for-setup-proof-accounting',
        },
    };
    const setupTransportProfile = {
        objectType: 'SetupTransportProfile',
        objectVersion: 1,
        transportProfileId: 'sealed-lattice-setup-binary-chunked-transport-v1',
    };
    const evaluatorKeyScheduleProfile = {
        objectType: 'EvaluatorKeyScheduleProfile',
        objectVersion: 1,
        relinearizationLevelSchedule: [{ level: 1 }],
        requiredGaloisKeySchedule,
    };
    const setupProfile = {
        objectType: 'CollectiveBgvSetupProfile',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProfileHash: setupContext.setupProfileHash,
        participantCount,
        qDec: thresholdDegree,
        qShare,
        qShareHash: setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfile,
        commitmentProfileHash: deriveProtocolHash(
            'SetupCommitmentProfileHash',
            commitmentProfile,
        ),
        publicVssCommitmentMaterialSizeProfile: {
            objectType: 'PublicVssCommitmentMaterialSizeProfile',
            objectVersion: 1,
            fullMaterialCoefficientBytes,
        },
        setupProofProfile,
        setupProofProfileHash: deriveProtocolHash(
            'SetupProofProfileHash',
            setupProofProfile,
        ),
        setupTransportProfile,
        setupTransportProfileHash: deriveProtocolHash(
            'SetupTransportProfileHash',
            setupTransportProfile,
        ),
        evaluatorKeyScheduleProfile,
        evaluatorKeyScheduleProfileHash: deriveProtocolHash(
            'EvaluatorKeyScheduleProfileHash',
            evaluatorKeyScheduleProfile,
        ),
    };

    return {
        setupProfile,
        bgvProfile: {
            profile: {
                profileId: 'fixture-bgv-profile',
                backendProfileId: 'fixture-bgv-backend',
                polynomialDegree: ringDegree,
                plaintextModulus: 65_537,
                dataBasisId: 'fixture-data-basis',
                dataPrimes: qSharePrimes,
                specialPrime: 147_457,
            },
            securityEstimatorInputHash: fixtureHash('security-estimator-input'),
        },
        transport: {
            fullObjectHash: fixtureHash('transport-full-object'),
            chunkHashes: [fixtureHash('transport-chunk-0')],
        },
    };
};

const createTrusteeInput = (
    trusteeRosterPosition: number,
): SetupCeremonyTrusteeInput => {
    const mailboxKeyPair = createPrivateVssMailboxKeyPair(
        fixtureHash(`mailbox-key-${String(trusteeRosterPosition)}`),
    );
    const signingKeyPair = createMlDsaKeyPairFixture(
        `setup-ceremony-signing-${String(trusteeRosterPosition)}`,
    );
    const signRoot: ProtocolRootSigner = (signedRoot) =>
        createProtocolSignatureFixture({
            profile: createMlDsaSignatureProfileFixture(),
            publicKeyBytesHex: signingKeyPair.publicKeyBytesHex,
            publicKeyHash: signingKeyPair.publicKeyHash,
            secretKeyBytesHex: signingKeyPair.secretKeyBytesHex,
            signedRoot,
        });

    const trusteeWithoutPhaseObjects: Omit<
        SetupCeremonyTrusteeInput,
        'setupPhaseParticipantObjects'
    > = {
        trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
        trusteeRosterPosition,
        mailboxPublicKeyBytesHex: mailboxKeyPair.publicKeyBytesHex,
        mailboxSecretKeyBytesHex: mailboxKeyPair.secretKeyBytesHex,
        signingPublicKeyHash: signingKeyPair.publicKeyHash,
        signRoot,
        recoveryEpoch: 0,
        deviceEpoch: trusteeRosterPosition,
        storageKeyBytesHex: fixtureHash(
            `storage-key-${String(trusteeRosterPosition)}`,
        ).slice(0, 64),
        localStateAeadNonceBytesHex: fixtureHash(
            `local-state-nonce-${String(trusteeRosterPosition)}`,
        ).slice(0, 24),
        sealedAggregateThresholdShareAeadNonceBytesHex: fixtureHash(
            `sealed-aggregate-nonce-${String(trusteeRosterPosition)}`,
        ).slice(0, 24),
        commonRandomnessCommitRoot: fixtureHash('common-randomness-commit'),
        commonRandomnessRevealRoot: fixtureHash('common-randomness-reveal'),
    };

    return {
        ...trusteeWithoutPhaseObjects,
        setupPhaseParticipantObjects: setupPhaseOrder.map(
            ([phaseId, phaseNumber]) =>
                phaseParticipantObjectFixture(
                    trusteeWithoutPhaseObjects,
                    phaseId,
                    phaseNumber,
                ),
        ),
    };
};

const createAssemblyInput = (
    participantCount: number,
    kernel: PrivateVssMailboxDeliveryKernel,
): SetupCeremonyAssemblyInput => {
    const publicKeyShareMaterialContributions = Array.from(
        { length: participantCount },
        (_unused, position) => publicKeyShareMaterialContribution(position),
    );
    const publicKeyShareContributions = publicKeyShareMaterialContributions.map(
        (materialContribution) =>
            publicKeyShareContribution(materialContribution),
    );
    const sourceTrusteeOpeningStates = Array.from(
        { length: participantCount },
        (_unused, position) => sourceTrusteeOpeningState(position),
    );
    const evaluationKeyInputs = evaluationKeyFixture(
        participantCount,
        sourceTrusteeOpeningStates,
        publicKeyShareContributions,
    );
    const trustees = Array.from(
        { length: participantCount },
        (_unused, position) => createTrusteeInput(position),
    );

    return {
        kernel,
        setupContext,
        qShare,
        phaseTranscript: phaseTranscriptFixture(trustees),
        commonRandomness: commonRandomnessFixture(),
        phaseOrderHash: fixtureHash('phase-order'),
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        setupProofBinding,
        sameSecretTboxParameterProfileHash,
        sameSecretProofMaterials: Array.from(
            { length: participantCount },
            (_unused, position) => sameSecretProofMaterial(position),
        ),
        publicKeyShareMaterialContributions,
        publicKeyShareTboxParameterProfileHash,
        publicKeyShareLnpProofMaterials: Array.from(
            { length: participantCount },
            (_unused, position) => publicKeyShareLnpProofMaterial(position),
        ),
        relinearizationCrpRoot: fixtureHash('relinearization-crp'),
        galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
        requiredGaloisKeySchedule,
        relinearizationRoundOneContributions:
            evaluationKeyInputs.relinearizationRoundOneContributions,
        relinearizationRoundTwoContributions:
            evaluationKeyInputs.relinearizationRoundTwoContributions,
        galoisKeyShareBatchContributions:
            evaluationKeyInputs.galoisKeyShareBatchContributions,
        setupCertificateInput: setupCertificateInputFixture(participantCount),
        qSharePrimes,
        ringDegree,
        thresholdDegree,
        trustees,
        sourceTrusteeOpeningStates,
        deliveryPhaseNumber: 6,
        verificationPhaseNumber: 7,
        privateVssShareProofFactory,
    };
};

const binaryVssMaterialByteLengthForInput = (
    input: SetupCeremonyAssemblyInput,
): number => {
    const commitmentBundle = createVssCoefficientCommitmentBundle({
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        qSharePrimes: input.qSharePrimes,
        ringDegree: input.ringDegree,
        participantCount: input.trustees.length,
        thresholdDegree: input.thresholdDegree,
        sourceTrusteeOpeningStates: input.sourceTrusteeOpeningStates,
    });
    const transport =
        createBinaryChunkedVssCoefficientCommitmentMaterialTransport(
            commitmentBundle.materialSet,
        );

    return transport.transportedVssCoefficientCommitmentMaterial
        .totalByteLength;
};

describe('setup ceremony assembly', () => {
    it('assembles full-roster VSS delivery, acceptances, local state, and contributions', async () => {
        const participantCount = 10;
        const kernelFixture = createKernelFixture();
        const assembly = await createSetupCeremonyAssembly(
            createAssemblyInput(participantCount, kernelFixture.kernel),
        );

        expect(assembly).toMatchObject({
            objectType: 'SetupCeremonyAssembly',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupContext,
        });
        expect(
            assembly.vssCoefficientCommitments.sourceTrusteeRecords,
        ).toHaveLength(participantCount);
        expect(
            assembly.privateVssEnvelopeCommitments.envelopeReferences,
        ).toHaveLength(participantCount * participantCount);
        expect(assembly.vssShareAcceptances.acceptanceRecords).toHaveLength(
            participantCount * participantCount,
        );
        expect(
            assembly.thresholdShareCommitments.recipientRecords,
        ).toHaveLength(participantCount);
        expect(assembly.sameSecretConsistency.statementRecords).toHaveLength(
            participantCount,
        );
        expect(assembly.sameSecretProofs).toMatchObject({
            objectType: 'SameSecretProofSet',
            proofVerificationStatus: sameSecretLnpProofVerificationStatus,
        });
        expect(assembly.sameSecretProofs.proofRecords).toHaveLength(
            participantCount,
        );
        expect(assembly.publicKeyShares.shareRecords).toHaveLength(
            participantCount,
        );
        expect(assembly.publicKeyShareProofs.proofRecords).toHaveLength(
            participantCount,
        );
        expect(assembly.publicKeyShareMaterial).toMatchObject({
            objectType: 'PublicKeyShareMaterialSet',
            publicKeyShareSetRoot:
                assembly.publicKeyShares.publicKeyShareSetRoot,
        });
        expect(
            assembly.publicKeyShareMaterial.shareMaterialRecords,
        ).toHaveLength(participantCount);
        expect(assembly.publicKeyShareLnpProofs).toMatchObject({
            objectType: 'PublicKeyShareLnpProofSet',
            proofVerificationStatus: publicKeyShareLnpProofVerificationStatus,
            sameSecretProofSetRoot:
                assembly.sameSecretProofs.sameSecretProofSetRoot,
            publicKeyShareMaterialSetRoot:
                assembly.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        });
        expect(assembly.publicKeyShareLnpProofs.proofRecords).toHaveLength(
            participantCount,
        );
        expect(assembly.evaluatorKeySchedule.requiredGaloisKeySchedule).toEqual(
            requiredGaloisKeySchedule,
        );
        expect(
            assembly.relinearizationKeyShareRounds.sameSecretProofSetRoot,
        ).toBe(assembly.sameSecretProofs.sameSecretProofSetRoot);
        expect(
            assembly.relinearizationKeyShareRounds
                .publicKeyShareLnpProofSetRoot,
        ).toBe(assembly.publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot);
        expect(
            assembly.relinearizationKeyShareRounds.roundOneRecords,
        ).toHaveLength(
            assembly.evaluatorKeySchedule.relinearizationLevelSchedule.length *
                participantCount,
        );
        expect(
            assembly.relinearizationKeyShareRounds.roundTwoRecords,
        ).toHaveLength(
            assembly.evaluatorKeySchedule.relinearizationLevelSchedule.length *
                participantCount,
        );
        expect(assembly.galoisKeyShareBatches).toHaveLength(participantCount);
        expect(
            assembly.galoisKeyShareBatches.every(
                (batch) =>
                    batch.sameSecretProofSetRoot ===
                        assembly.sameSecretProofs.sameSecretProofSetRoot &&
                    batch.publicKeyShareLnpProofSetRoot ===
                        assembly.publicKeyShareLnpProofs
                            .publicKeyShareLnpProofSetRoot,
            ),
        ).toBe(true);
        expect(assembly.evaluationKeys.publicKeyShareLnpProofSetRoot).toBe(
            assembly.publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot,
        );
        expect(assembly.evaluationKeys.relinearizationKeyRoots).toHaveLength(
            assembly.evaluatorKeySchedule.relinearizationLevelSchedule.length,
        );
        expect(assembly.evaluationKeys.galoisKeyRoots).toHaveLength(
            requiredGaloisKeySchedule.length,
        );
        expect(assembly.evaluationKeys.genericKeySwitchKeyRoots).toEqual([]);
        expect(assembly.evaluationKeys.rawKeyBytesEmbedded).toBe(false);
        expect(assembly.evaluationKeys.verifierGeneratedKeyMaterial).toBe(
            false,
        );
        expect(assembly.setupPackage).toMatchObject({
            objectType: 'SetupPackage',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupContext,
            sameSecretProofs: assembly.sameSecretProofs,
            publicKeyShareMaterial: assembly.publicKeyShareMaterial,
            publicKeyShareLnpProofs: assembly.publicKeyShareLnpProofs,
            collectivePublicKey: assembly.collectivePublicKey,
            collectivePublicKeyRoot:
                assembly.collectivePublicKey.collectivePublicKeyRoot,
            evaluationKeys: assembly.evaluationKeys,
            relinearizationKeyShareRounds:
                assembly.relinearizationKeyShareRounds,
            galoisKeyShareBatches: assembly.galoisKeyShareBatches,
        });
        expect(assembly.setupPackage.setupPackageHash).toMatch(
            /^[0-9a-f]{128}$/u,
        );
        expect(assembly.collectivePublicKey).toMatchObject({
            objectType: 'CollectivePublicKey',
            setupProfileId: 'CollectiveBgvSetup-v1',
            publicKeyShareSetRoot:
                assembly.publicKeyShares.publicKeyShareSetRoot,
            publicKeyShareMaterialSetRoot:
                assembly.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
            publicKeyShareLnpProofSetRoot:
                assembly.publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot,
        });
        expect(
            assembly.collectivePublicKey.sourceShareMaterialRoots,
        ).toHaveLength(participantCount);
        expect(
            assembly.collectivePublicKey.aggregateCoefficientVectorsByLimb,
        ).toHaveLength(qSharePrimes.length);
        const {
            collectivePublicKeyRoot: derivedCollectivePublicKeyRoot,
            ...collectivePublicKeyHashInput
        } = assembly.collectivePublicKey;
        expect(assembly.collectivePublicKey.collectivePublicKeyRoot).toBe(
            deriveProtocolHash(
                'CollectivePublicKeyRoot',
                collectivePublicKeyHashInput,
            ),
        );
        expect(derivedCollectivePublicKeyRoot).toBe(
            assembly.setupPackage.collectivePublicKeyRoot,
        );
        const setupProofAccountingCertificate = assembly.setupPackage
            .setupProofAccountingCertificate as Record<string, unknown>;
        const challengeAccounting =
            setupProofAccountingCertificate.challengeAccounting as Record<
                string,
                unknown
            >;
        const proofFamilyAccounting =
            setupProofAccountingCertificate.proofFamilyAccounting as readonly Record<
                string,
                unknown
            >[];
        expect(proofFamilyAccounting).toHaveLength(setupProofFamilies.length);
        expect(proofFamilyAccounting[0]).toMatchObject({
            proofFamily: 'vss-opening-carry',
            verifierClosedStatus:
                'relation-transcript-and-bound-checks-verifier-closed',
            accountingStatus:
                'repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted',
            claimAccounting: {
                soundness:
                    'LNP22 commit-and-prove extractor accounting is accepted for the recipient-local carry-aware VSS relation because statement binding, first-message commitments, generated tbox bytes, coefficient openings, carry relations, and response bounds are verified before acceptance',
                zeroKnowledge:
                    'LNP22 simulator accounting is accepted for centered 112-bit coefficient masks, opening-randomness masks, carry masks, verifier-bound no-wrap bounds, and transcript-bound tbox bytes; private coefficients, openings, and carries are not exposed in accepted public artifacts',
            },
        });
        expect(JSON.stringify(proofFamilyAccounting)).not.toContain(
            'full LNP tbox proof closure',
        );
        expect(
            proofFamilyAccounting.map((entry) => entry.proofFamily),
        ).toStrictEqual([...setupProofFamilies]);
        const responseMaskingAccounting =
            setupProofAccountingCertificate.responseMaskingAccounting as Record<
                string,
                unknown
            >;
        expect(responseMaskingAccounting).toMatchObject({
            objectType: 'SetupProofResponseMaskingAccounting',
            accountingStatus:
                'response-mask-bounds-strengthened-verifier-bound-and-zk-accounting-accepted',
            zeroKnowledgeAccountingStatus:
                'response masking, witness-dependent support commitments, committed-secret response distributions, fixed-width signed relation commitments, and no-wrap response bounds are accepted by the setup proof theorem accounting object',
        });
        expect(JSON.stringify(responseMaskingAccounting)).not.toContain(
            'full LNP tbox proof closure',
        );
        const responseMaskingFamilies =
            responseMaskingAccounting.families as readonly Record<
                string,
                unknown
            >[];
        expect(responseMaskingFamilies).toHaveLength(setupProofFamilies.length);
        expect(responseMaskingFamilies[0]).toMatchObject({
            proofFamily: 'vss-opening-carry',
            fullWidthCoefficientMaskingStatus:
                'centered-signed-private-vss-message-response-masking-verifier-bound-and-simulator-accounting-accepted',
            commitmentNoWrapStatus: 'three-limb-big-int-no-wrap-bound-recorded',
        });
        const privateVssResponseProfiles = responseMaskingFamilies[0]
            .responseProfiles as readonly Record<string, unknown>[];
        expect(privateVssResponseProfiles[0]).toMatchObject({
            responseKind: 'coefficient-message',
            maskRandomBits: 112,
            scalarChallengeBits: 63,
        });
        expect(
            privateVssResponseProfiles[0].maskingSlackBits as number,
        ).toBeGreaterThan(0);
        const relinearizationResponseProfiles = responseMaskingFamilies[3]
            .responseProfiles as readonly Record<string, unknown>[];
        expect(relinearizationResponseProfiles[2]).toMatchObject({
            responseKind: 'round-two-source',
            maskRandomBits: 80,
        });
        const tboxAccounting =
            setupProofAccountingCertificate.tboxAccounting as Record<
                string,
                unknown
            >;
        expect(tboxAccounting).toMatchObject({
            accountingStatus:
                'generated-lower-protocol-tbox-profile-verifier-and-prover-closed',
            closedProofFamilies: [...setupProofFamilies],
            proofRingDegree: setupProofLnpTboxProofRingDegree,
            challengeLog2Range: setupProofLnpTboxChallengeLog2Range,
            challengeEncodedBits: setupProofLnpTboxChallengeEncodedBits,
            challengeSpaceBits: setupProofLnpTboxChallengeSpaceBits,
        });
        expect(tboxAccounting.closedVerifierChecks).toContain(
            'generated lower-protocol tbox suffix byte-for-byte enforcement',
        );
        const challengeSpaceAudit =
            challengeAccounting.challengeSpaceAudit as Record<string, unknown>;
        expect(challengeSpaceAudit).toMatchObject({
            objectType: 'SetupProofChallengeSpaceAudit',
            proofFamilies: [...setupProofFamilies],
            challengeDifferenceInvertibilityStatus:
                setupProofChallengeDifferenceInvertibilityStatus,
            challengeSampler:
                'sealed-lattice-shake256-lazer-autostable-rejection-v1',
        });
        expect(challengeSpaceAudit.familySamples).toHaveLength(
            setupProofFamilies.length,
        );
        expect(challengeSpaceAudit.sampledDifferenceChecks).toHaveLength(10);
        expect(challengeAccounting.challengeSpaceAuditHash).toBe(
            deriveProtocolHash(
                'SetupProofChallengeSpaceAuditHash',
                challengeSpaceAudit,
            ),
        );
        expect(
            assembly.setupPackage.setupKeyCorrectnessCertificate,
        ).toMatchObject({
            objectType: 'SetupKeyCorrectnessCertificate',
            setupProfileId: 'CollectiveBgvSetup-v1',
            keyCorrectnessTheorem: {
                theoremStatus:
                    'repo-owned-key-correctness-theorem-accepted-for-verifier-recomputed-roots',
            },
            collectivePublicKey: {
                status: 'collective-public-key-coefficients-recomputed-from-public-key-share-material-and-LNP-proof-roots',
                collectivePublicKeyRoot:
                    assembly.collectivePublicKey.collectivePublicKeyRoot,
                sourceRoots: {
                    publicKeyShareSetRoot:
                        assembly.publicKeyShares.publicKeyShareSetRoot,
                    publicKeyShareProofSetRoot:
                        assembly.publicKeyShareProofs
                            .publicKeyShareProofSetRoot,
                    publicKeyShareMaterialSetRoot:
                        assembly.publicKeyShareMaterial
                            .publicKeyShareMaterialSetRoot,
                    publicKeyShareLnpProofSetRoot:
                        assembly.publicKeyShareLnpProofs
                            .publicKeyShareLnpProofSetRoot,
                },
            },
            publicEvaluationKeys: {
                status: 'public-evaluation-key-roots-recomputed-from-frozen-schedule-and-proof-bearing-relinearization-and-galois-records',
                evaluationKeySetHash:
                    assembly.evaluationKeys.evaluationKeySetHash,
                evaluatorKeyScheduleRoot:
                    assembly.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                relinearizationKeyShareRoundsRoot:
                    assembly.relinearizationKeyShareRounds
                        .relinearizationKeyShareRoundsRoot,
                requiredGaloisSetHash:
                    assembly.evaluatorKeySchedule.requiredGaloisSetHash,
            },
            certificateDependencies: {
                setupProofAccountingCertificateHash:
                    assembly.setupPackage.setupProofAccountingCertificateHash,
                heSecurityCertificateHash:
                    assembly.setupPackage.heSecurityCertificateHash,
            },
        });
        const setupKeyCorrectnessCertificate = jsonRecord(
            assembly.setupPackage.setupKeyCorrectnessCertificate,
            'setupPackage.setupKeyCorrectnessCertificate',
        );
        const setupKeyCorrectnessPublicEvaluationKeys = jsonRecord(
            setupKeyCorrectnessCertificate.publicEvaluationKeys,
            'setupPackage.setupKeyCorrectnessCertificate.publicEvaluationKeys',
        );
        expect(
            setupKeyCorrectnessPublicEvaluationKeys.galoisKeyShareBatchRoots,
        ).toHaveLength(assembly.galoisKeyShareBatches.length);
        expect(assembly.setupPackage.setupKeyCorrectnessCertificateHash).toBe(
            setupKeyCorrectnessCertificate.setupKeyCorrectnessCertificateHash,
        );
        expect(assembly.setupPackage.thresholdShareCommitments).toEqual(
            assembly.thresholdShareCommitments,
        );
        const setupPackagePrivateVssEnvelopeCommitments = assembly.setupPackage
            .privateVssEnvelopeCommitments as PrivateVssMailboxDeliverySet;
        expect(
            setupPackagePrivateVssEnvelopeCommitments.envelopeReferences[0],
        ).not.toHaveProperty('encryptedEnvelope');
        expect(
            collectForbiddenSetupPackageAssemblyFieldPaths(
                assembly.setupPackage,
            ),
        ).toEqual([]);
        expect(assembly.localTrusteeSetupStates).toHaveLength(participantCount);
        expect(assembly.setupContributions).toHaveLength(participantCount);
        expect(kernelFixture.verifiedExpectedEnvelopeCount()).toBe(
            participantCount * participantCount,
        );

        for (const [
            trusteeIndex,
            localState,
        ] of assembly.localTrusteeSetupStates.entries()) {
            expect(localState.trusteeIdentity).toBe(
                `trustee-${String(trusteeIndex)}`,
            );
            expect(localState.trusteeRosterPosition).toBe(trusteeIndex);
            expect(
                collectForbiddenLocalTrusteeSetupStateFieldPaths(
                    localState.localStateCommitment,
                ),
            ).toEqual([]);
        }

        for (const contribution of assembly.setupContributions) {
            expect(contribution.privateVssEnvelopeReferences).toHaveLength(
                participantCount,
            );
            expect(contribution.issuedVssAcceptanceRoots).toHaveLength(
                participantCount,
            );
            expect(contribution.vssSourceTrusteeCommitmentRoot).not.toBeNull();
            expect(
                contribution.thresholdShareCommitmentRecipientRoot,
            ).not.toBeNull();
            expect(contribution.aggregateThresholdShareRoot).not.toBeNull();
            expect(contribution.localStateRoot).not.toBeNull();
            expect(contribution.publicKeyShareRoot).toBe(
                assembly.publicKeyShares.shareRecords.find(
                    (shareRecord) =>
                        shareRecord.trusteeRosterPosition ===
                        contribution.trusteeRosterPosition,
                )?.publicKeyShareRoot,
            );
            expect(contribution.publicKeyShareProofRoot).toBe(
                assembly.publicKeyShareProofs.proofRecords.find(
                    (proofRecord) =>
                        proofRecord.trusteeRosterPosition ===
                        contribution.trusteeRosterPosition,
                )?.publicKeyShareProofRoot,
            );
            expect(
                collectForbiddenSetupContributionAssemblyFieldPaths(
                    contribution,
                ),
            ).toEqual([]);
        }

        const exportedLocalStateJson = JSON.stringify(
            assembly.localTrusteeSetupStates,
        );
        expect(exportedLocalStateJson).not.toContain('"localStatePlaintext":');
        expect(exportedLocalStateJson).not.toContain('"coefficientMessage":');
        expect(exportedLocalStateJson).not.toContain('"randomnessByColumn":');

        const contributionJson = JSON.stringify(assembly.setupContributions);
        expect(contributionJson).not.toContain('"shareValues":');
        expect(contributionJson).not.toContain('"privateEnvelope":');
        expect(contributionJson).not.toContain('"coefficientOpenings":');
    });

    it('assembles a setup package bound to binary-chunked VSS material', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const fullMaterialCoefficientBytes =
            binaryVssMaterialByteLengthForInput(input);
        const assembly = await createSetupCeremonyAssembly({
            ...input,
            setupCertificateInput: setupCertificateInputFixture(
                participantCount,
                fullMaterialCoefficientBytes,
            ),
            vssCoefficientCommitmentMaterialEncoding:
                'binary-chunked-full-public-setup-commitment-values',
        });

        expect(assembly.vssCoefficientCommitmentMaterial).toMatchObject({
            objectType: 'VssCoefficientCommitmentMaterialSet',
            materialEncoding:
                'binary-chunked-full-public-setup-commitment-values',
            transport: {
                totalByteLength: fullMaterialCoefficientBytes,
                fullObjectHash:
                    assembly.transportedVssCoefficientCommitmentMaterial
                        ?.fullObjectHash,
                chunkRoot:
                    assembly.transportedVssCoefficientCommitmentMaterial
                        ?.chunkRoot,
            },
        });
        expect(assembly.vssCoefficientCommitmentMaterial).not.toHaveProperty(
            'coefficientCommitments',
        );
        expect(
            assembly.transportedVssCoefficientCommitmentMaterial,
        ).toMatchObject({
            objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
            totalByteLength: fullMaterialCoefficientBytes,
        });
        expect(assembly.setupPackage.vssCoefficientCommitmentMaterial).toEqual(
            assembly.vssCoefficientCommitmentMaterial,
        );
        expect(assembly.setupPackage.setupTransportCertificate).toMatchObject({
            fullObjectHash:
                assembly.transportedVssCoefficientCommitmentMaterial
                    ?.fullObjectHash,
            chunkRoot:
                assembly.transportedVssCoefficientCommitmentMaterial?.chunkRoot,
            totalByteLength: fullMaterialCoefficientBytes,
        });
        expect(
            assembly.sameSecretProofs.vssCoefficientCommitmentMaterialRoot,
        ).toBe(
            assembly.vssCoefficientCommitmentMaterial
                .vssCoefficientCommitmentMaterialRoot,
        );
        expect(assembly.setupPackage.thresholdShareCommitments).toEqual(
            assembly.thresholdShareCommitments,
        );
    });

    it('rejects opening states rebound to another trustee identity', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                sourceTrusteeOpeningStates:
                    input.sourceTrusteeOpeningStates.map(
                        (sourceTrusteeState) =>
                            sourceTrusteeState.sourceTrusteeRosterPosition === 1
                                ? {
                                      ...sourceTrusteeState,
                                      sourceTrusteeIdentity: 'trustee-0',
                                  }
                                : sourceTrusteeState,
                    ),
            }),
        ).rejects.toThrow(/identities must match trustees/u);
    });

    it('rejects public-key share material whose coefficients do not match the accepted hash', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                publicKeyShareMaterialContributions:
                    input.publicKeyShareMaterialContributions.map(
                        (contribution) =>
                            contribution.trusteeRosterPosition === 1
                                ? {
                                      ...contribution,
                                      shareCoefficientVectorsByLimb:
                                          contribution.shareCoefficientVectorsByLimb.map(
                                              (
                                                  coefficientVector,
                                                  rnsLimbIndex,
                                              ) =>
                                                  rnsLimbIndex === 0
                                                      ? {
                                                            ...coefficientVector,
                                                            coefficientsLeHex:
                                                                '00000000000000000000000000000000',
                                                        }
                                                      : coefficientVector,
                                          ),
                                  }
                                : contribution,
                    ),
            }),
        ).rejects.toThrow(/coefficient hash must match/u);
    });

    it('rejects same-secret proof material rebound to another trustee identity', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                sameSecretProofMaterials: input.sameSecretProofMaterials.map(
                    (proofMaterial) =>
                        proofMaterial.trusteeRosterPosition === 1
                            ? {
                                  ...proofMaterial,
                                  trusteeIdentity: 'trustee-0',
                              }
                            : proofMaterial,
                ),
            }),
        ).rejects.toThrow(/bind the derived same-secret statements/u);
    });

    it('rejects public-key LNP proof material rebound to another trustee identity', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                publicKeyShareLnpProofMaterials:
                    input.publicKeyShareLnpProofMaterials.map(
                        (proofMaterial) =>
                            proofMaterial.trusteeRosterPosition === 1
                                ? {
                                      ...proofMaterial,
                                      trusteeIdentity: 'trustee-0',
                                  }
                                : proofMaterial,
                    ),
            }),
        ).rejects.toThrow(/bind accepted public-key and same-secret records/u);
    });

    it('rejects missing scheduled Galois proof contributions', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                galoisKeyShareBatchContributions:
                    input.galoisKeyShareBatchContributions.map(
                        (batchContribution) =>
                            batchContribution.trusteeRosterPosition === 1
                                ? {
                                      ...batchContribution,
                                      galoisKeyShareProofs:
                                          batchContribution.galoisKeyShareProofs.slice(
                                              0,
                                              1,
                                          ),
                                  }
                                : batchContribution,
                    ),
            }),
        ).rejects.toThrow(/one proof per required Galois key/u);
    });

    it('rejects recipient-local private VSS re-verification failure before acceptance export', async () => {
        const participantCount = 3;
        const kernelFixture = createRefusingKernelFixture();

        await expect(
            createSetupCeremonyAssembly(
                createAssemblyInput(participantCount, kernelFixture.kernel),
            ),
        ).rejects.toThrow(/recipient-local verification/u);
    });
});
