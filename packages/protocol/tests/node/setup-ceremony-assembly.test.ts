import {
    createPrivateVssMailboxKeyPair,
    deriveProtocolHash,
    hash512Hex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    collectForbiddenLocalTrusteeSetupStateFieldPaths,
    collectForbiddenSetupContributionAssemblyFieldPaths,
    collectForbiddenSetupPackageAssemblyFieldPaths,
    acceptedBgvProfileRingDegree,
    acceptedBgvSetupQShare,
    acceptedBgvSetupQShareHash,
    acceptedBgvSetupQSharePrimes,
    binaryVssCoefficientCommitmentMaterialByteLength,
    createEvaluatorKeySchedule,
    createBinaryChunkedPublicKeyShareProofMaterialTransport,
    createBinaryChunkedPublicEvaluationKeyMaterialTransport,
    createBinaryChunkedSameSecretProofMaterialTransport,
    createBinaryChunkedEvaluationKeyShareMaterialTransport,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createSameSecretConsistencyStatementSet,
    createSetupCeremonyAssembly,
    createSetupPackageVerificationInput,
    createSetupPhaseRecord,
    createBinaryChunkedVssCoefficientCommitmentMaterialTransport,
    createVssCoefficientCommitmentBundle,
    deriveThresholdShareCommitments,
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
    publicKeyShareMaterialTransportEncoding,
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
const ringDegree = 2;
const thresholdDegree = 2;
const firstProfileThresholdDegree = 4;

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

const setupTransportCertificateTransportedObjects = (
    setupPackage: Readonly<{ readonly setupTransportCertificate: unknown }>,
): readonly JsonRecord[] => {
    const setupTransportCertificate = jsonRecord(
        setupPackage.setupTransportCertificate,
        'setupTransportCertificate',
    );
    const transportedObjects = setupTransportCertificate.transportedObjects;
    if (!Array.isArray(transportedObjects)) {
        throw new Error(
            'setupTransportCertificate.transportedObjects must be an array.',
        );
    }

    return transportedObjects.map((transportedObject, transportedObjectIndex) =>
        jsonRecord(
            transportedObject,
            `setupTransportCertificate.transportedObjects.${String(transportedObjectIndex)}`,
        ),
    );
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

const acceptedQShareSetupContext = {
    ...setupContext,
    qShareHash: acceptedBgvSetupQShareHash,
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

const setupProofBindingFixture = (
    context: CollectiveBgvSetupContext,
): JsonRecord => ({
    objectType: 'SetupCeremonyAssemblyProofBindingFixture',
    objectVersion: 1,
    ceremonyId: context.ceremonyId,
    manifestHash: context.manifestHash,
    rosterHash: context.rosterHash,
    setupProfileHash: context.setupProfileHash,
    qShareHash: context.qShareHash,
    setupEpoch: context.setupEpoch,
});

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

const evaluationKeyCoefficientVectorBytes = (
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

const evaluationKeyCoefficientVectorLeHex = (
    coefficients: readonly number[],
): string =>
    Array.from(evaluationKeyCoefficientVectorBytes(coefficients), (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');

const evaluationKeyComponentVector = (
    label: string,
    digitIndex: number,
    rnsLimbIndex: number,
    applicationRingDegree = ringDegree,
    qSharePrimeList: readonly number[] = qSharePrimes,
): JsonRecord => {
    const rnsPrime = qSharePrimeList[rnsLimbIndex];
    const coefficients = Array.from(
        { length: applicationRingDegree },
        (_unused, coefficientIndex) =>
            ((label.length + 1) * 31 +
                digitIndex * 17 +
                rnsLimbIndex * 11 +
                coefficientIndex * 7) %
            rnsPrime,
    );
    const coefficientBytes = evaluationKeyCoefficientVectorBytes(coefficients);

    return {
        digitIndex,
        rnsLimbIndex,
        rnsPrime,
        component: 'b',
        coefficientByteLength: coefficientBytes.byteLength,
        coefficientVectorHash512: hash512Hex(
            'sealed-lattice-bgv-rns/evaluation-key-share-component-vector-v1',
            [coefficientBytes],
        ),
        coefficientsLeHex: evaluationKeyCoefficientVectorLeHex(coefficients),
    };
};

const evaluationKeyComponentVectors = (
    label: string,
    level: number,
    applicationRingDegree = ringDegree,
    qSharePrimeList: readonly number[] = qSharePrimes,
): readonly JsonRecord[] => {
    const componentVectors: JsonRecord[] = [];
    for (let digitIndex = 0; digitIndex <= level; digitIndex += 1) {
        for (let rnsLimbIndex = 0; rnsLimbIndex <= level; rnsLimbIndex += 1) {
            componentVectors.push(
                evaluationKeyComponentVector(
                    label,
                    digitIndex,
                    rnsLimbIndex,
                    applicationRingDegree,
                    qSharePrimeList,
                ),
            );
        }
    }

    return componentVectors;
};

const evaluationKeyComponentVectorRoot = (
    proofFamily: 'relinearization-key-share' | 'galois-key-share',
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    level: number,
    componentVectors: readonly JsonRecord[],
    applicationRingDegree = ringDegree,
): string =>
    deriveProtocolHash('EvaluationKeyShareComponentVectorRoot', {
        objectType: 'EvaluationKeyShareComponentVectorSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
        proofFamily,
        keySwitchDomain,
        keySwitchSeedHex,
        level,
        ringDegree: applicationRingDegree,
        digitCount: level + 1,
        rnsLimbCount: level + 1,
        componentVectors,
    });

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

const embeddedProofMaterialBytesHex = (
    material: SameSecretProofMaterial | PublicKeyShareLnpProofMaterial,
): string => {
    const embeddedMaterial = material as Readonly<{ proofBytesHex?: unknown }>;
    if (typeof embeddedMaterial.proofBytesHex !== 'string') {
        throw new Error('fixture proof material must contain proofBytesHex.');
    }

    return embeddedMaterial.proofBytesHex;
};

const hashBoundSameSecretProofMaterial = (
    trusteeRosterPosition: number,
): SameSecretProofMaterial => {
    const material = sameSecretProofMaterial(trusteeRosterPosition);
    const bytesHex = embeddedProofMaterialBytesHex(material);

    return {
        ...material,
        proofBytesHash: hash512Hex(
            'sealed-lattice/setup/same-secret/lnp-proof-bytes-v1',
            [proofBytes(bytesHex)],
        ),
    };
};

const hashBoundPublicKeyShareProofMaterial = (
    trusteeRosterPosition: number,
): PublicKeyShareLnpProofMaterial => {
    const material = publicKeyShareLnpProofMaterial(trusteeRosterPosition);
    const bytesHex = embeddedProofMaterialBytesHex(material);

    return {
        ...material,
        proofBytesHash: hash512Hex(
            'sealed-lattice/setup/public-key-share/lnp-proof-bytes-v1',
            [proofBytes(bytesHex)],
        ),
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
    applicationRingDegree = ringDegree,
): readonly number[] =>
    Array.from(
        { length: applicationRingDegree },
        (_unused, coefficientIndex) => {
            const value =
                (sourceTrusteeRosterPosition + 1) * 31 +
                (rnsLimbIndex + 1) * 17 +
                (shamirCoefficientIndex + 1) * 7 +
                coefficientIndex * 3;

            return value % rnsPrime;
        },
    );

const randomnessByColumn = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    applicationRingDegree = ringDegree,
): readonly (readonly number[])[] =>
    Array.from({ length: 5 }, (_unusedColumn, randomnessColumnIndex) =>
        Array.from(
            { length: applicationRingDegree },
            (_unused, coefficientIndex) => {
                const selector =
                    (sourceTrusteeRosterPosition +
                        rnsLimbIndex +
                        shamirCoefficientIndex +
                        randomnessColumnIndex +
                        coefficientIndex) %
                    3;

                return selector === 0 ? -1 : selector === 1 ? 0 : 1;
            },
        ),
    );

const coefficientOpening = (
    sourceTrusteeRosterPosition: number,
    rnsPrime: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    applicationRingDegree = ringDegree,
): VssCoefficientOpeningInput => ({
    rnsLimbIndex,
    rnsPrime,
    shamirCoefficientIndex,
    coefficientMessage: coefficientMessage(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
        rnsPrime,
        applicationRingDegree,
    ),
    randomnessByColumn: randomnessByColumn(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
        applicationRingDegree,
    ),
});

const sourceTrusteeOpeningState = (
    sourceTrusteeRosterPosition: number,
    applicationRingDegree = ringDegree,
    applicationThresholdDegree = thresholdDegree,
    qSharePrimeList: readonly number[] = qSharePrimes,
): VssSourceTrusteeCoefficientOpeningState => ({
    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
    sourceTrusteeRosterPosition,
    coefficientOpenings: qSharePrimeList.flatMap((rnsPrime, rnsLimbIndex) =>
        Array.from(
            { length: applicationThresholdDegree },
            (_unused, coefficientIndex) => {
                return coefficientOpening(
                    sourceTrusteeRosterPosition,
                    rnsPrime,
                    rnsLimbIndex,
                    coefficientIndex,
                    applicationRingDegree,
                );
            },
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
    applicationRingDegree = ringDegree,
): readonly number[] =>
    Array.from(
        { length: applicationRingDegree },
        (_unused, coefficientIndex) => {
            const value =
                (trusteeRosterPosition + 1) * 101 +
                (rnsLimbIndex + 1) * 29 +
                coefficientIndex * 13;

            return value % rnsPrime;
        },
    );

const publicKeyShareMaterialContribution = (
    trusteeRosterPosition: number,
    applicationRingDegree = ringDegree,
    qSharePrimeList: readonly number[] = qSharePrimes,
): PublicKeyShareMaterialContributionInput => ({
    trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
    trusteeRosterPosition,
    shareCoefficientVectorsByLimb: qSharePrimeList.map(
        (rnsPrime, rnsLimbIndex) => {
            const coefficients = publicKeyShareCoefficients(
                trusteeRosterPosition,
                rnsLimbIndex,
                rnsPrime,
                applicationRingDegree,
            );

            return {
                rnsLimbIndex,
                rnsPrime,
                component: 'b_i',
                coefficientByteLength: applicationRingDegree * 8,
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
    label: string,
    round: 'round-one' | 'round-two',
    level: number,
    applicationRingDegree = ringDegree,
    qSharePrimeList: readonly number[] = qSharePrimes,
): RelinearizationKeyShareProofMaterial => {
    const keySwitchDomain = 'relinearization';
    const keySwitchSeedHex = relinearizationKeySwitchSeed(
        evaluatorKeySchedule,
        round,
        level,
    );
    const keySwitchComponentVectors = evaluationKeyComponentVectors(
        `relinearization-${label}`,
        level,
        applicationRingDegree,
        qSharePrimeList,
    );
    const proofMaterialBytesHex = '00112233';

    return {
        proofProfileId: 'sealed-lattice-relinearization-key-share-proof-lnp-v1',
        setupProofBinding: {
            objectType: 'SetupCeremonyAssemblyProofBindingFixture',
            label,
        },
        keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
        keySwitchDomain,
        keySwitchSeedHex,
        ringDegree: applicationRingDegree,
        keySwitchComponentVectorRoot: evaluationKeyComponentVectorRoot(
            'relinearization-key-share',
            keySwitchDomain,
            keySwitchSeedHex,
            level,
            keySwitchComponentVectors,
            applicationRingDegree,
        ),
        keySwitchComponentVectors,
        relinearizationKeyShareTboxParameterProfileHash: fixtureHash(
            `relinearization-tbox-${label}`,
        ),
        statementHash: fixtureHash(`statement-${label}`),
        relationCommitmentHash: fixtureHash(`relation-commitment-${label}`),
        tboxCommitmentPrefixHash: fixtureHash(`tbox-commitment-${label}`),
        challenge: 17,
        proofSizeBytes: proofMaterialBytesHex.length / 2,
        proofBytesHash: hash512Hex(
            'sealed-lattice/setup/relinearization-key-share/lnp-proof-bytes-v1',
            [proofBytes(proofMaterialBytesHex)],
        ),
        proofBytesHex: proofMaterialBytesHex,
    };
};

const galoisProofMaterial = (
    evaluatorKeySchedule: EvaluatorKeySchedule,
    label: string,
    rotation: number,
    level: number,
    applicationRingDegree = ringDegree,
    qSharePrimeList: readonly number[] = qSharePrimes,
): GaloisKeyShareProofMaterial => {
    const keySwitchDomain = `galois-${String(rotation)}`;
    const keySwitchSeedHex = galoisKeySwitchSeed(
        evaluatorKeySchedule,
        rotation,
        level,
    );
    const keySwitchComponentVectors = evaluationKeyComponentVectors(
        `galois-${label}`,
        level,
        applicationRingDegree,
        qSharePrimeList,
    );
    const proofMaterialBytesHex = '44556677';

    return {
        proofProfileId: 'sealed-lattice-galois-key-share-proof-lnp-v1',
        setupProofBinding: {
            objectType: 'SetupCeremonyAssemblyProofBindingFixture',
            label,
        },
        keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
        keySwitchDomain,
        keySwitchSeedHex,
        ringDegree: applicationRingDegree,
        keySwitchComponentVectorRoot: evaluationKeyComponentVectorRoot(
            'galois-key-share',
            keySwitchDomain,
            keySwitchSeedHex,
            level,
            keySwitchComponentVectors,
            applicationRingDegree,
        ),
        keySwitchComponentVectors,
        galoisKeyShareTboxParameterProfileHash: fixtureHash(
            `galois-tbox-${label}`,
        ),
        statementHash: fixtureHash(`galois-statement-${label}`),
        relationCommitmentHash: fixtureHash(
            `galois-relation-commitment-${label}`,
        ),
        tboxCommitmentPrefixHash: fixtureHash(
            `galois-tbox-commitment-${label}`,
        ),
        challenge: 19,
        proofSizeBytes: proofMaterialBytesHex.length / 2,
        proofBytesHash: hash512Hex(
            'sealed-lattice/setup/galois-key-share/lnp-proof-bytes-v1',
            [proofBytes(proofMaterialBytesHex)],
        ),
        proofBytesHex: proofMaterialBytesHex,
    };
};

const evaluationKeyFixture = (
    participantCount: number,
    sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[],
    publicKeyShareContributions: readonly PublicKeyShareContributionInput[],
    applicationRingDegree = ringDegree,
    applicationThresholdDegree = thresholdDegree,
    context: CollectiveBgvSetupContext = setupContext,
    qSharePrimeList: readonly number[] = qSharePrimes,
): CeremonyEvaluationKeyFixture => {
    const vssCoefficientCommitmentBundle = createVssCoefficientCommitmentBundle(
        {
            setupContext: context,
            publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
            qSharePrimes: qSharePrimeList,
            ringDegree: applicationRingDegree,
            participantCount,
            thresholdDegree: applicationThresholdDegree,
            sourceTrusteeOpeningStates,
        },
    );
    const sameSecretConsistency = createSameSecretConsistencyStatementSet({
        setupContext: context,
        qSharePrimes: qSharePrimeList,
        participantCount,
        thresholdDegree: applicationThresholdDegree,
        vssCoefficientCommitments: vssCoefficientCommitmentBundle.commitmentSet,
    });
    const publicKeyShares = createPublicKeyShareSet({
        setupContext: context,
        qSharePrimes: qSharePrimeList,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        sameSecretConsistency,
        shareContributions: publicKeyShareContributions,
    });
    const publicKeyShareProofs = createPublicKeyShareProofSet({
        setupContext: context,
        qSharePrimes: qSharePrimeList,
        participantCount,
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        sameSecretConsistency,
        publicKeyShares,
    });
    const evaluatorKeySchedule = createEvaluatorKeySchedule({
        setupContext: context,
        qSharePrimes: qSharePrimeList,
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
                        const proofMaterial = relinearizationProofMaterial(
                            evaluatorKeySchedule,
                            `round-one-${String(
                                reference.trusteeRosterPosition,
                            )}-${String(scheduleEntry.level)}`,
                            'round-one',
                            scheduleEntry.level,
                            applicationRingDegree,
                            qSharePrimeList,
                        );

                        return {
                            trusteeRosterPosition:
                                reference.trusteeRosterPosition,
                            level: scheduleEntry.level,
                            roundOneShareRoot:
                                proofMaterial.keySwitchComponentVectorRoot,
                            proofMaterial,
                        };
                    }),
            ),
        relinearizationRoundTwoContributions:
            evaluatorKeySchedule.relinearizationLevelSchedule.flatMap(
                (scheduleEntry) =>
                    sameSecretProofReferences.map((reference) => {
                        const proofMaterial = relinearizationProofMaterial(
                            evaluatorKeySchedule,
                            `round-two-${String(
                                reference.trusteeRosterPosition,
                            )}-${String(scheduleEntry.level)}`,
                            'round-two',
                            scheduleEntry.level,
                            applicationRingDegree,
                            qSharePrimeList,
                        );

                        return {
                            trusteeRosterPosition:
                                reference.trusteeRosterPosition,
                            level: scheduleEntry.level,
                            roundTwoShareRoot:
                                proofMaterial.keySwitchComponentVectorRoot,
                            proofMaterial,
                        };
                    }),
            ),
        galoisKeyShareBatchContributions: sameSecretProofReferences.map(
            (reference) => ({
                trusteeRosterPosition: reference.trusteeRosterPosition,
                galoisKeyShareProofs: requiredGaloisKeySchedule.map(
                    (scheduleEntry) => {
                        const proofMaterial = galoisProofMaterial(
                            evaluatorKeySchedule,
                            `${String(
                                reference.trusteeRosterPosition,
                            )}-${String(scheduleEntry.rotation)}-${String(
                                scheduleEntry.level,
                            )}`,
                            scheduleEntry.rotation,
                            scheduleEntry.level,
                            applicationRingDegree,
                            qSharePrimeList,
                        );

                        return {
                            rotation: scheduleEntry.rotation,
                            level: scheduleEntry.level,
                            galoisKeyShareRoot:
                                proofMaterial.keySwitchComponentVectorRoot,
                            proofMaterial,
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
    context: CollectiveBgvSetupContext = setupContext,
): SetupPhaseParticipantObject =>
    ({
        objectType: 'SetupPhaseParticipantObject',
        objectVersion: 1,
        phaseId,
        phaseNumber,
        ceremonyId: context.ceremonyId,
        manifestHash: context.manifestHash,
        rosterHash: context.rosterHash,
        setupProfileHash: context.setupProfileHash,
        commitmentProfileHash: context.commitmentProfileHash,
        setupEpoch: context.setupEpoch,
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
    context: CollectiveBgvSetupContext = setupContext,
): readonly SetupPhaseRecord[] => {
    let previousPhaseRoot: string | null = null;

    return setupPhaseOrder.map(([phaseId, phaseNumber]) => {
        const phaseRecord = createSetupPhaseRecord({
            setupContext: context,
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

const commonRandomnessFixture = (
    context: CollectiveBgvSetupContext = setupContext,
): SetupCommonRandomness => {
    const publicMatrixSeedHash = fixtureHash('public-matrix-seed');
    const publicDerivationsWithoutRoot = {
        objectType: 'SetupPublicDerivations',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        publicMatrixSeedHash,
        bgvPublicA: {
            objectType: 'BgvPublicAPolynomial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            publicMatrixSeedHash,
            publicPolynomialRoot: fixtureHash('public-a-polynomial'),
        },
        publicMatrices: {
            objectType: 'SetupPublicMatrixMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            publicMatrixSeedHash,
            commitmentMatrix: {
                matrixRoot: fixtureHash('commitment-matrix'),
            },
            setupProofMatrix: {
                matrixRoot: fixtureHash('setup-proof-matrix'),
            },
            materializationStatus: 'deterministic-entry-streams-bound',
            publicMatricesRoot: fixtureHash('public-matrices'),
        },
        crpRoots: {
            publicKeyCrpRoot: fixtureHash('public-key-crp'),
            relinearizationCrpRoot: fixtureHash('relinearization-crp'),
            galoisKeyCrpRoot: fixtureHash('galois-key-crp'),
            commitmentMatrixCrpRoot: fixtureHash('commitment-matrix-crp'),
            proofMatrixCrpRoot: fixtureHash('proof-matrix-crp'),
        },
        status: 'deterministic-public-derivations-bound',
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
        ceremonyId: context.ceremonyId,
        manifestHash: context.manifestHash,
        rosterHash: context.rosterHash,
        setupProfileHash: context.setupProfileHash,
        setupEpoch: context.setupEpoch,
        commitRecords: [],
        revealRecords: [],
        publicMatrixSeedHash,
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
    applicationRingDegree = ringDegree,
    applicationThresholdDegree = thresholdDegree,
    context: CollectiveBgvSetupContext = setupContext,
    qShareRecord: SetupCeremonyAssemblyInput['qShare'] = qShare,
    qSharePrimeList: readonly number[] = qSharePrimes,
): SetupPackageCertificateInput => {
    const commitmentProfile = {
        objectType: 'SetupCommitmentProfile',
        objectVersion: 1,
        messageEncoding: {
            commitmentModulusLimbs: qSharePrimeList,
        },
    };
    const setupProofProfile = {
        objectType: 'SetupProofProfile',
        objectVersion: 1,
        profileId: 'SealedLattice-LNP-SetupProof-v1',
        setupProfileId: 'CollectiveBgvSetup-v1',
        proofSystem: 'fixed-lnp-linear-relation-subset',
        relationModel: {
            applicationRingDegree,
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
            qromStatus: 'qrom-reduction-theorem-accepted-for-setup-proof-claim',
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
            applicationRingDegree,
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
        setupProfileHash: context.setupProfileHash,
        participantCount,
        qDec: applicationThresholdDegree,
        qShare: qShareRecord,
        qShareHash: context.qShareHash,
        carryAwareVssShareRelationProfileHash:
            context.carryAwareVssShareRelationProfileHash,
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
                polynomialDegree: applicationRingDegree,
                plaintextModulus: 65_537,
                dataBasisId: 'fixture-data-basis',
                dataPrimes: qSharePrimeList,
                specialPrime: qSharePrimeList[qSharePrimeList.length - 1],
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
    context: CollectiveBgvSetupContext = setupContext,
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
                    context,
                ),
        ),
    };
};

type AssemblyInputFixtureOptions = Readonly<{
    readonly setupContext?: CollectiveBgvSetupContext;
    readonly qShare?: SetupCeremonyAssemblyInput['qShare'];
    readonly qSharePrimes?: readonly number[];
    readonly setupProofBinding?: SetupCeremonyAssemblyInput['setupProofBinding'];
}>;

const createAssemblyInput = (
    participantCount: number,
    kernel: PrivateVssMailboxDeliveryKernel,
    applicationRingDegree = ringDegree,
    applicationThresholdDegree = thresholdDegree,
    options: AssemblyInputFixtureOptions = {},
): SetupCeremonyAssemblyInput => {
    const fixtureSetupContext = options.setupContext ?? setupContext;
    const fixtureQShare = options.qShare ?? qShare;
    const fixtureQSharePrimes = options.qSharePrimes ?? qSharePrimes;
    const fixtureSetupProofBinding =
        options.setupProofBinding ??
        setupProofBindingFixture(fixtureSetupContext);
    const publicKeyShareMaterialContributions = Array.from(
        { length: participantCount },
        (_unused, position) =>
            publicKeyShareMaterialContribution(
                position,
                applicationRingDegree,
                fixtureQSharePrimes,
            ),
    );
    const publicKeyShareContributions = publicKeyShareMaterialContributions.map(
        (materialContribution) =>
            publicKeyShareContribution(materialContribution),
    );
    const sourceTrusteeOpeningStates = Array.from(
        { length: participantCount },
        (_unused, position) =>
            sourceTrusteeOpeningState(
                position,
                applicationRingDegree,
                applicationThresholdDegree,
                fixtureQSharePrimes,
            ),
    );
    const evaluationKeyInputs = evaluationKeyFixture(
        participantCount,
        sourceTrusteeOpeningStates,
        publicKeyShareContributions,
        applicationRingDegree,
        applicationThresholdDegree,
        fixtureSetupContext,
        fixtureQSharePrimes,
    );
    const trustees = Array.from(
        { length: participantCount },
        (_unused, position) =>
            createTrusteeInput(position, fixtureSetupContext),
    );

    return {
        kernel,
        setupContext: fixtureSetupContext,
        qShare: fixtureQShare,
        phaseTranscript: phaseTranscriptFixture(trustees, fixtureSetupContext),
        commonRandomness: commonRandomnessFixture(fixtureSetupContext),
        phaseOrderHash: fixtureHash('phase-order'),
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        publicKeyCrpRoot: fixtureHash('public-key-crp'),
        publicAPolynomialRoot: fixtureHash('public-a-polynomial'),
        setupProofBinding: fixtureSetupProofBinding,
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
        setupCertificateInput: setupCertificateInputFixture(
            participantCount,
            1,
            applicationRingDegree,
            applicationThresholdDegree,
            fixtureSetupContext,
            fixtureQShare,
            fixtureQSharePrimes,
        ),
        qSharePrimes: fixtureQSharePrimes,
        ringDegree: applicationRingDegree,
        thresholdDegree: applicationThresholdDegree,
        trustees,
        sourceTrusteeOpeningStates,
        deliveryPhaseNumber: 6,
        verificationPhaseNumber: 7,
        privateVssShareProofFactory,
    };
};

const createAcceptedQShareAssemblyInput = (
    participantCount: number,
    kernel: PrivateVssMailboxDeliveryKernel,
    applicationRingDegree = ringDegree,
    applicationThresholdDegree = firstProfileThresholdDegree,
): SetupCeremonyAssemblyInput =>
    createAssemblyInput(
        participantCount,
        kernel,
        applicationRingDegree,
        applicationThresholdDegree,
        {
            setupContext: acceptedQShareSetupContext,
            qShare: acceptedBgvSetupQShare,
            qSharePrimes: acceptedBgvSetupQSharePrimes,
        },
    );

const sameSecretProofReferencesFixture = (
    participantCount: number,
): readonly {
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
}[] =>
    Array.from({ length: participantCount }, (_unused, trusteeIndex) => ({
        trusteeIdentity: `trustee-${String(trusteeIndex)}`,
        trusteeRosterPosition: trusteeIndex,
    }));

const binaryVssMaterialByteLengthForInput = (
    input: SetupCeremonyAssemblyInput,
): number => {
    return binaryVssCoefficientCommitmentMaterialByteLength({
        participantCount: input.trustees.length,
        thresholdDegree: input.thresholdDegree,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
    });
};

describe('setup ceremony assembly', () => {
    it('creates transported setup proof material for same-secret and public-key-share proofs', () => {
        const participantCount = 3;
        const sameSecretProofMaterials = Array.from(
            { length: participantCount },
            (_unused, position) => hashBoundSameSecretProofMaterial(position),
        );
        const publicKeyShareProofMaterials = Array.from(
            { length: participantCount },
            (_unused, position) =>
                hashBoundPublicKeyShareProofMaterial(position),
        );

        expect(() =>
            createBinaryChunkedSameSecretProofMaterialTransport([
                sameSecretProofMaterial(0),
            ]),
        ).toThrow('proofBytesHash must match proofBytesHex before transport');
        const sameSecretTransport =
            createBinaryChunkedSameSecretProofMaterialTransport(
                sameSecretProofMaterials,
            );
        const publicKeyShareTransport =
            createBinaryChunkedPublicKeyShareProofMaterialTransport(
                publicKeyShareProofMaterials,
            );

        expect(
            sameSecretTransport.transportedSameSecretProofMaterial,
        ).toMatchObject({
            objectType: 'SetupTransportedSameSecretProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
            proofFamily: 'same-secret-consistency',
        });
        expect(
            publicKeyShareTransport.transportedPublicKeyShareProofMaterial,
        ).toMatchObject({
            objectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
            proofFamily: 'public-key-share',
        });
        sameSecretTransport.proofMaterials.forEach(
            (proofMaterial, proofIndex) => {
                const proofMaterialRecord = jsonRecord(
                    proofMaterial,
                    'sameSecretTransport.proofMaterials',
                );
                const transportedMaterialRecord = jsonRecord(
                    sameSecretTransport.transportedSameSecretProofMaterial
                        .proofMaterials[proofIndex],
                    'transportedSameSecretProofMaterial.proofMaterials',
                );
                expect(proofMaterialRecord.proofBytesHex).toBeUndefined();
                expect(proofMaterialRecord.proofBytesEncoding).toBe(
                    'binary-chunked-proof-bytes',
                );
                expect(proofMaterialRecord.proofTotalByteLength).toBe(
                    proofMaterial.proofSizeBytes,
                );
                expect(proofMaterialRecord.proofMaterialRoot).toBe(
                    transportedMaterialRecord.proofMaterialRoot,
                );
                expect(proofMaterialRecord.proofFullObjectHash).toBe(
                    transportedMaterialRecord.fullObjectHash,
                );
                expect(proofMaterialRecord.proofChunkRoot).toBe(
                    transportedMaterialRecord.chunkRoot,
                );
                expect(proofMaterialRecord.proofChunkHashes).toEqual(
                    transportedMaterialRecord.chunkHashes,
                );
                expect(transportedMaterialRecord.chunks).toEqual([
                    {
                        chunkIndex: 0,
                        bytesHex: embeddedProofMaterialBytesHex(
                            sameSecretProofMaterials[proofIndex],
                        ),
                    },
                ]);
            },
        );
        publicKeyShareTransport.proofMaterials.forEach(
            (proofMaterial, proofIndex) => {
                const proofMaterialRecord = jsonRecord(
                    proofMaterial,
                    'publicKeyShareTransport.proofMaterials',
                );
                const transportedMaterialRecord = jsonRecord(
                    publicKeyShareTransport
                        .transportedPublicKeyShareProofMaterial.proofMaterials[
                        proofIndex
                    ],
                    'transportedPublicKeyShareProofMaterial.proofMaterials',
                );
                expect(proofMaterialRecord.proofBytesHex).toBeUndefined();
                expect(proofMaterialRecord.proofBytesEncoding).toBe(
                    'binary-chunked-proof-bytes',
                );
                expect(proofMaterialRecord.proofTotalByteLength).toBe(
                    proofMaterial.proofSizeBytes,
                );
                expect(proofMaterialRecord.proofMaterialRoot).toBe(
                    transportedMaterialRecord.proofMaterialRoot,
                );
                expect(proofMaterialRecord.proofFullObjectHash).toBe(
                    transportedMaterialRecord.fullObjectHash,
                );
                expect(proofMaterialRecord.proofChunkRoot).toBe(
                    transportedMaterialRecord.chunkRoot,
                );
                expect(proofMaterialRecord.proofChunkHashes).toEqual(
                    transportedMaterialRecord.chunkHashes,
                );
                expect(transportedMaterialRecord.chunks).toEqual([
                    {
                        chunkIndex: 0,
                        bytesHex: embeddedProofMaterialBytesHex(
                            publicKeyShareProofMaterials[proofIndex],
                        ),
                    },
                ]);
            },
        );
    });

    it('creates transported evaluation-key proof and component material companions', () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );

        const transport =
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    sameSecretProofReferencesFixture(participantCount),
                relinearizationRoundOneContributions:
                    input.relinearizationRoundOneContributions,
                relinearizationRoundTwoContributions:
                    input.relinearizationRoundTwoContributions,
                galoisKeyShareBatchContributions:
                    input.galoisKeyShareBatchContributions,
            });

        const transportedProofSet =
            transport.transportedEvaluationKeyShareProofMaterial;
        const transportedComponentSet =
            transport.transportedEvaluationKeyShareComponentMaterial;
        expect(transportedProofSet).toMatchObject({
            objectType: 'SetupTransportedEvaluationKeyShareProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
            proofFamily: 'evaluation-key-share',
        });
        expect(transportedComponentSet).toMatchObject({
            objectType:
                'SetupTransportedEvaluationKeyShareComponentMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
        });
        const expectedProofMaterialCount =
            input.relinearizationRoundOneContributions.length +
            input.relinearizationRoundTwoContributions.length +
            input.galoisKeyShareBatchContributions.reduce(
                (proofCount, batchContribution) =>
                    proofCount + batchContribution.galoisKeyShareProofs.length,
                0,
            );
        expect(transportedProofSet.proofMaterials).toHaveLength(
            expectedProofMaterialCount,
        );
        expect(transportedComponentSet.componentMaterials).toHaveLength(
            expectedProofMaterialCount,
        );
        const transportedProofRoots = new Set(
            transportedProofSet.proofMaterials.map(
                (proofMaterial) =>
                    jsonRecord(proofMaterial, 'proofMaterial')
                        .proofMaterialRoot,
            ),
        );
        const transportedComponentRoots = new Set(
            transportedComponentSet.componentMaterials.map(
                (componentMaterial) =>
                    jsonRecord(componentMaterial, 'componentMaterial')
                        .keySwitchComponentMaterialRoot,
            ),
        );
        for (const contribution of [
            ...transport.relinearizationRoundOneContributions,
            ...transport.relinearizationRoundTwoContributions,
        ]) {
            const proofMaterial = jsonRecord(
                contribution.proofMaterial,
                'relinearization proof material',
            );
            expect(proofMaterial.proofBytesHex).toBeUndefined();
            expect(proofMaterial.keySwitchComponentVectors).toBeUndefined();
            expect(proofMaterial.proofBytesEncoding).toBe(
                'binary-chunked-proof-bytes',
            );
            expect(proofMaterial.keySwitchMaterialEncoding).toBe(
                'binary-chunked-key-switch-component-vectors',
            );
            expect(
                transportedProofRoots.has(proofMaterial.proofMaterialRoot),
            ).toBe(true);
            expect(
                transportedComponentRoots.has(
                    proofMaterial.keySwitchComponentMaterialRoot,
                ),
            ).toBe(true);
        }
        for (const batchContribution of transport.galoisKeyShareBatchContributions) {
            for (const proofContribution of batchContribution.galoisKeyShareProofs) {
                const proofMaterial = jsonRecord(
                    proofContribution.proofMaterial,
                    'Galois proof material',
                );
                expect(proofMaterial.proofBytesHex).toBeUndefined();
                expect(proofMaterial.keySwitchComponentVectors).toBeUndefined();
                expect(proofMaterial.proofBytesEncoding).toBe(
                    'binary-chunked-proof-bytes',
                );
                expect(proofMaterial.keySwitchMaterialEncoding).toBe(
                    'binary-chunked-key-switch-component-vectors',
                );
                expect(
                    transportedProofRoots.has(proofMaterial.proofMaterialRoot),
                ).toBe(true);
                expect(
                    transportedComponentRoots.has(
                        proofMaterial.keySwitchComponentMaterialRoot,
                    ),
                ).toBe(true);
            }
        }
        const firstProofMaterial = jsonRecord(
            transportedProofSet.proofMaterials[0],
            'transported evaluation-key proof material',
        );
        expect(firstProofMaterial.proofFullObjectHash).toMatch(
            /^[0-9a-f]{128}$/u,
        );
        expect(firstProofMaterial.fullObjectHash).toBeUndefined();
        const firstComponentMaterial = jsonRecord(
            transportedComponentSet.componentMaterials[0],
            'transported evaluation-key component material',
        );
        const firstComponentChunk = jsonRecord(
            (firstComponentMaterial.chunks as readonly JsonRecord[])[0],
            'transported evaluation-key component chunk',
        );
        expect(firstComponentChunk.bytesHex).toMatch(/^534c454b434d5631/u);
    });

    it('assembles transported evaluation-key proof records with material companions', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const transport =
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    sameSecretProofReferencesFixture(participantCount),
                relinearizationRoundOneContributions:
                    input.relinearizationRoundOneContributions,
                relinearizationRoundTwoContributions:
                    input.relinearizationRoundTwoContributions,
                galoisKeyShareBatchContributions:
                    input.galoisKeyShareBatchContributions,
            });

        const assembly = await createSetupCeremonyAssembly({
            ...input,
            relinearizationRoundOneContributions:
                transport.relinearizationRoundOneContributions,
            relinearizationRoundTwoContributions:
                transport.relinearizationRoundTwoContributions,
            galoisKeyShareBatchContributions:
                transport.galoisKeyShareBatchContributions,
            transportedEvaluationKeyShareProofMaterial:
                transport.transportedEvaluationKeyShareProofMaterial,
            transportedEvaluationKeyShareComponentMaterial:
                transport.transportedEvaluationKeyShareComponentMaterial,
        });

        expect(assembly.transportedEvaluationKeyShareProofMaterial).toBe(
            transport.transportedEvaluationKeyShareProofMaterial,
        );
        expect(assembly.transportedEvaluationKeyShareComponentMaterial).toBe(
            transport.transportedEvaluationKeyShareComponentMaterial,
        );
        const setupTransportedObjects =
            setupTransportCertificateTransportedObjects(assembly.setupPackage);
        transport.transportedEvaluationKeyShareProofMaterial.proofMaterials.forEach(
            (transportedProofMaterial) => {
                const transportedProofMaterialRecord = jsonRecord(
                    transportedProofMaterial,
                    'transported evaluation-key proof material',
                );
                expect(setupTransportedObjects).toEqual(
                    expect.arrayContaining([
                        expect.objectContaining({
                            objectName: 'evaluationKeyShareProofMaterial',
                            objectRole: 'evaluation-key-share-proof-material',
                            objectRoot:
                                transportedProofMaterialRecord.proofMaterialRoot,
                            byteLength:
                                transportedProofMaterialRecord.proofTotalByteLength,
                            fullObjectHash:
                                transportedProofMaterialRecord.proofFullObjectHash,
                            chunkRoot:
                                transportedProofMaterialRecord.proofChunkRoot,
                            chunkHashes:
                                transportedProofMaterialRecord.proofChunkHashes,
                        }),
                    ]),
                );
            },
        );
        transport.transportedEvaluationKeyShareComponentMaterial.componentMaterials.forEach(
            (transportedComponentMaterial) => {
                const transportedComponentMaterialRecord = jsonRecord(
                    transportedComponentMaterial,
                    'transported evaluation-key component material',
                );
                expect(setupTransportedObjects).toEqual(
                    expect.arrayContaining([
                        expect.objectContaining({
                            objectName: 'evaluationKeyShareComponentMaterial',
                            objectRole:
                                'evaluation-key-share-component-material',
                            objectRoot:
                                transportedComponentMaterialRecord.keySwitchComponentMaterialRoot,
                            byteLength:
                                transportedComponentMaterialRecord.totalByteLength,
                            fullObjectHash:
                                transportedComponentMaterialRecord.fullObjectHash,
                            chunkRoot:
                                transportedComponentMaterialRecord.chunkRoot,
                            chunkHashes:
                                transportedComponentMaterialRecord.chunkHashes,
                        }),
                    ]),
                );
            },
        );
        expect(
            assembly.relinearizationKeyShareRounds.roundOneRecords.every(
                (record) =>
                    !('proofBytesHex' in record) &&
                    !('keySwitchComponentVectors' in record) &&
                    record.proofBytesEncoding ===
                        'binary-chunked-proof-bytes' &&
                    record.keySwitchMaterialEncoding ===
                        'binary-chunked-key-switch-component-vectors',
            ),
        ).toBe(true);
        expect(
            assembly.galoisKeyShareBatches.every((batch) =>
                batch.galoisKeyShareProofs.every(
                    (proofRecord) =>
                        !('proofBytesHex' in proofRecord) &&
                        !('keySwitchComponentVectors' in proofRecord) &&
                        proofRecord.proofBytesEncoding ===
                            'binary-chunked-proof-bytes' &&
                        proofRecord.keySwitchMaterialEncoding ===
                            'binary-chunked-key-switch-component-vectors',
                ),
            ),
        ).toBe(true);
    });

    it('assembles root-referenced setup proof records with transported proof material companions', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const sameSecretTransport =
            createBinaryChunkedSameSecretProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundSameSecretProofMaterial(position),
                ),
            );
        const publicKeyShareTransport =
            createBinaryChunkedPublicKeyShareProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundPublicKeyShareProofMaterial(position),
                ),
            );

        const assembly = await createSetupCeremonyAssembly({
            ...input,
            sameSecretProofMaterials: sameSecretTransport.proofMaterials,
            transportedSameSecretProofMaterial:
                sameSecretTransport.transportedSameSecretProofMaterial,
            publicKeyShareLnpProofMaterials:
                publicKeyShareTransport.proofMaterials,
            transportedPublicKeyShareProofMaterial:
                publicKeyShareTransport.transportedPublicKeyShareProofMaterial,
        });

        expect(assembly.transportedSameSecretProofMaterial).toBe(
            sameSecretTransport.transportedSameSecretProofMaterial,
        );
        expect(assembly.transportedPublicKeyShareProofMaterial).toBe(
            publicKeyShareTransport.transportedPublicKeyShareProofMaterial,
        );
        const setupTransportedObjects =
            setupTransportCertificateTransportedObjects(assembly.setupPackage);
        sameSecretTransport.transportedSameSecretProofMaterial.proofMaterials.forEach(
            (transportedProofMaterial) => {
                const transportedProofMaterialRecord = jsonRecord(
                    transportedProofMaterial,
                    'transported same-secret proof material',
                );
                expect(setupTransportedObjects).toEqual(
                    expect.arrayContaining([
                        expect.objectContaining({
                            objectName: 'sameSecretProofMaterial',
                            objectRole: 'same-secret-proof-material',
                            objectRoot:
                                transportedProofMaterialRecord.proofMaterialRoot,
                            byteLength:
                                transportedProofMaterialRecord.totalByteLength,
                            fullObjectHash:
                                transportedProofMaterialRecord.fullObjectHash,
                            chunkRoot: transportedProofMaterialRecord.chunkRoot,
                            chunkHashes:
                                transportedProofMaterialRecord.chunkHashes,
                        }),
                    ]),
                );
            },
        );
        publicKeyShareTransport.transportedPublicKeyShareProofMaterial.proofMaterials.forEach(
            (transportedProofMaterial) => {
                const transportedProofMaterialRecord = jsonRecord(
                    transportedProofMaterial,
                    'transported public-key proof material',
                );
                expect(setupTransportedObjects).toEqual(
                    expect.arrayContaining([
                        expect.objectContaining({
                            objectName: 'publicKeyShareProofMaterial',
                            objectRole: 'public-key-share-proof-material',
                            objectRoot:
                                transportedProofMaterialRecord.proofMaterialRoot,
                            byteLength:
                                transportedProofMaterialRecord.totalByteLength,
                            fullObjectHash:
                                transportedProofMaterialRecord.fullObjectHash,
                            chunkRoot: transportedProofMaterialRecord.chunkRoot,
                            chunkHashes:
                                transportedProofMaterialRecord.chunkHashes,
                        }),
                    ]),
                );
            },
        );
        sameSecretTransport.proofMaterials.forEach(
            (proofMaterial, proofIndex) => {
                const proofRecord = jsonRecord(
                    assembly.sameSecretProofs.proofRecords[proofIndex],
                    'sameSecretProofRecord',
                );
                expect(proofRecord.proofMaterialRoot).toBe(
                    jsonRecord(proofMaterial, 'sameSecretProofMaterial')
                        .proofMaterialRoot,
                );
                expect(proofRecord.proofBytesEncoding).toBe(
                    'binary-chunked-proof-bytes',
                );
                expect(proofRecord).not.toHaveProperty('proofBytesHex');
            },
        );
        publicKeyShareTransport.proofMaterials.forEach(
            (proofMaterial, proofIndex) => {
                const proofRecord = jsonRecord(
                    assembly.publicKeyShareLnpProofs.proofRecords[proofIndex],
                    'publicKeyShareLnpProofRecord',
                );
                expect(proofRecord.proofMaterialRoot).toBe(
                    jsonRecord(proofMaterial, 'publicKeyShareProofMaterial')
                        .proofMaterialRoot,
                );
                expect(proofRecord.proofBytesEncoding).toBe(
                    'binary-chunked-proof-bytes',
                );
                expect(proofRecord).not.toHaveProperty('proofBytesHex');
            },
        );
    });

    it('builds public-only setup verification input from transported assembly companions', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const sameSecretTransport =
            createBinaryChunkedSameSecretProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundSameSecretProofMaterial(position),
                ),
            );
        const publicKeyShareTransport =
            createBinaryChunkedPublicKeyShareProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundPublicKeyShareProofMaterial(position),
                ),
            );
        const evaluationKeyTransport =
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    sameSecretProofReferencesFixture(participantCount),
                relinearizationRoundOneContributions:
                    input.relinearizationRoundOneContributions,
                relinearizationRoundTwoContributions:
                    input.relinearizationRoundTwoContributions,
                galoisKeyShareBatchContributions:
                    input.galoisKeyShareBatchContributions,
            });
        const binaryVssMaterialByteLength =
            binaryVssMaterialByteLengthForInput(input);
        const transportedAssemblyInput = {
            ...input,
            sameSecretProofMaterials: sameSecretTransport.proofMaterials,
            transportedSameSecretProofMaterial:
                sameSecretTransport.transportedSameSecretProofMaterial,
            publicKeyShareLnpProofMaterials:
                publicKeyShareTransport.proofMaterials,
            transportedPublicKeyShareProofMaterial:
                publicKeyShareTransport.transportedPublicKeyShareProofMaterial,
            relinearizationRoundOneContributions:
                evaluationKeyTransport.relinearizationRoundOneContributions,
            relinearizationRoundTwoContributions:
                evaluationKeyTransport.relinearizationRoundTwoContributions,
            galoisKeyShareBatchContributions:
                evaluationKeyTransport.galoisKeyShareBatchContributions,
            transportedEvaluationKeyShareProofMaterial:
                evaluationKeyTransport.transportedEvaluationKeyShareProofMaterial,
            transportedEvaluationKeyShareComponentMaterial:
                evaluationKeyTransport.transportedEvaluationKeyShareComponentMaterial,
            vssCoefficientCommitmentMaterialEncoding:
                'binary-chunked-full-public-setup-commitment-values',
            publicKeyShareMaterialEncoding:
                publicKeyShareMaterialTransportEncoding,
            setupCertificateInput: setupCertificateInputFixture(
                participantCount,
                binaryVssMaterialByteLength,
            ),
        } satisfies SetupCeremonyAssemblyInput;
        const assemblyWithoutPublicEvaluationKeyMaterial =
            await createSetupCeremonyAssembly(transportedAssemblyInput);
        const publicEvaluationKeyMaterialTransport =
            createBinaryChunkedPublicEvaluationKeyMaterialTransport({
                setupContext: input.setupContext,
                qSharePrimes: input.qSharePrimes,
                participantCount,
                evaluatorKeySchedule:
                    assemblyWithoutPublicEvaluationKeyMaterial.evaluatorKeySchedule,
                sameSecretProofSetRoot:
                    assemblyWithoutPublicEvaluationKeyMaterial.sameSecretProofs
                        .sameSecretProofSetRoot,
                sameSecretProofFamilyBindingRoot:
                    assemblyWithoutPublicEvaluationKeyMaterial
                        .sameSecretConsistency.sameSecretProofFamilyBindingRoot,
                publicKeyShareLnpProofSetRoot:
                    assemblyWithoutPublicEvaluationKeyMaterial
                        .publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot,
                sameSecretProofReferences:
                    assemblyWithoutPublicEvaluationKeyMaterial.sameSecretProofs.proofRecords.map(
                        (proofRecord) => ({
                            trusteeIdentity: proofRecord.trusteeIdentity,
                            trusteeRosterPosition:
                                proofRecord.trusteeRosterPosition,
                            sameSecretStatementRoot:
                                proofRecord.sameSecretStatementRoot,
                            trusteeSecretCommitmentRoot:
                                proofRecord.trusteeSecretCommitmentRoot,
                            sameSecretProofRoot:
                                proofRecord.sameSecretProofRoot,
                        }),
                    ),
                relinearizationKeyShareRounds:
                    assemblyWithoutPublicEvaluationKeyMaterial.relinearizationKeyShareRounds,
                galoisKeyShareBatches:
                    assemblyWithoutPublicEvaluationKeyMaterial.galoisKeyShareBatches,
                transportedEvaluationKeyShareComponentMaterial:
                    evaluationKeyTransport.transportedEvaluationKeyShareComponentMaterial,
            });

        const assembly = await createSetupCeremonyAssembly({
            ...transportedAssemblyInput,
            publicEvaluationKeyMaterialReference:
                publicEvaluationKeyMaterialTransport.publicEvaluationKeyMaterialReference,
            transportedPublicEvaluationKeyMaterial:
                publicEvaluationKeyMaterialTransport.transportedPublicEvaluationKeyMaterial,
        });
        const transportedVssMaterial =
            assembly.transportedVssCoefficientCommitmentMaterial;
        if (transportedVssMaterial === undefined) {
            throw new Error('assembly must include transported VSS material.');
        }
        const { chunks: omittedVssChunks, ...transportedVssMaterialReference } =
            transportedVssMaterial;
        void omittedVssChunks;
        const verificationInput = createSetupPackageVerificationInput({
            ...assembly,
            transportedVssCoefficientCommitmentMaterial:
                transportedVssMaterialReference,
        });

        expect(Object.keys(verificationInput).sort()).toEqual([
            'setupPackage',
            'transportedEvaluationKeyShareComponentMaterial',
            'transportedEvaluationKeyShareProofMaterial',
            'transportedPublicEvaluationKeyMaterial',
            'transportedPublicKeyShareMaterial',
            'transportedPublicKeyShareProofMaterial',
            'transportedSameSecretProofMaterial',
            'transportedVssCoefficientCommitmentMaterial',
        ]);
        expect(verificationInput.setupPackage).toBe(assembly.setupPackage);
        expect(
            verificationInput.transportedVssCoefficientCommitmentMaterial,
        ).toEqual(transportedVssMaterialReference);
        expect(
            verificationInput.transportedVssCoefficientCommitmentMaterial,
        ).not.toHaveProperty('chunks');
        expect(verificationInput.transportedSameSecretProofMaterial).toBe(
            sameSecretTransport.transportedSameSecretProofMaterial,
        );
        expect(verificationInput.transportedPublicKeyShareMaterial).toBe(
            assembly.transportedPublicKeyShareMaterial,
        );
        expect(verificationInput.transportedPublicKeyShareProofMaterial).toBe(
            publicKeyShareTransport.transportedPublicKeyShareProofMaterial,
        );
        expect(
            verificationInput.transportedEvaluationKeyShareProofMaterial,
        ).toBe(
            evaluationKeyTransport.transportedEvaluationKeyShareProofMaterial,
        );
        expect(
            verificationInput.transportedEvaluationKeyShareComponentMaterial,
        ).toBe(
            evaluationKeyTransport.transportedEvaluationKeyShareComponentMaterial,
        );
        expect(verificationInput.transportedPublicEvaluationKeyMaterial).toBe(
            publicEvaluationKeyMaterialTransport.transportedPublicEvaluationKeyMaterial,
        );
        const publicEvaluationKeyMaterialRoot =
            publicEvaluationKeyMaterialTransport
                .publicEvaluationKeyMaterialReference
                .publicEvaluationKeyMaterialRoot;
        expect(assembly.evaluationKeys.publicEvaluationKeyMaterialRoot).toBe(
            publicEvaluationKeyMaterialRoot,
        );
        expect(
            setupTransportCertificateTransportedObjects(assembly.setupPackage),
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    objectName: 'publicEvaluationKeyMaterial',
                    objectRole: 'public-evaluation-key-runtime-material',
                    objectRoot: publicEvaluationKeyMaterialRoot,
                }),
            ]),
        );
        const serializedVerificationInput = JSON.stringify(verificationInput);
        expect(serializedVerificationInput).not.toMatch(
            /localTrusteeSetupStates|setupContributions|sourceTrusteeOpeningStates|coefficientOpenings|mailboxSecretKeyBytesHex|storageKeyBytesHex|proofGeneration|secretCoefficients/u,
        );
    });

    it('builds public-only setup verification input from provider-backed binary assembly', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const sourceOpeningLoadCounts = new Map<number, number>();
        const sourceTrusteeOpeningStateProvider = {
            sourceTrusteeReferences: input.trustees.map((trustee) => ({
                sourceTrusteeIdentity: trustee.trusteeIdentity,
                sourceTrusteeRosterPosition: trustee.trusteeRosterPosition,
            })),
            loadSourceTrusteeOpeningState: (sourceTrusteeReference: {
                readonly sourceTrusteeIdentity: string;
                readonly sourceTrusteeRosterPosition: number;
            }) => {
                if (
                    sourceTrusteeReference.sourceTrusteeIdentity !==
                    `trustee-${String(sourceTrusteeReference.sourceTrusteeRosterPosition)}`
                ) {
                    throw new Error(
                        'test provider reference must match the deterministic trustee identity.',
                    );
                }

                sourceOpeningLoadCounts.set(
                    sourceTrusteeReference.sourceTrusteeRosterPosition,
                    (sourceOpeningLoadCounts.get(
                        sourceTrusteeReference.sourceTrusteeRosterPosition,
                    ) ?? 0) + 1,
                );

                return sourceTrusteeOpeningState(
                    sourceTrusteeReference.sourceTrusteeRosterPosition,
                    input.ringDegree,
                    input.thresholdDegree,
                );
            },
        };
        const sameSecretTransport =
            createBinaryChunkedSameSecretProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundSameSecretProofMaterial(position),
                ),
            );
        const publicKeyShareTransport =
            createBinaryChunkedPublicKeyShareProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundPublicKeyShareProofMaterial(position),
                ),
            );
        const evaluationKeyTransport =
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    sameSecretProofReferencesFixture(participantCount),
                relinearizationRoundOneContributions:
                    input.relinearizationRoundOneContributions,
                relinearizationRoundTwoContributions:
                    input.relinearizationRoundTwoContributions,
                galoisKeyShareBatchContributions:
                    input.galoisKeyShareBatchContributions,
            });
        const binaryVssMaterialByteLength =
            binaryVssMaterialByteLengthForInput(input);
        const providerBackedTransportedInput = {
            ...input,
            sourceTrusteeOpeningStates: undefined,
            sourceTrusteeOpeningStateProvider,
            sameSecretProofMaterials: sameSecretTransport.proofMaterials,
            transportedSameSecretProofMaterial:
                sameSecretTransport.transportedSameSecretProofMaterial,
            publicKeyShareLnpProofMaterials:
                publicKeyShareTransport.proofMaterials,
            transportedPublicKeyShareProofMaterial:
                publicKeyShareTransport.transportedPublicKeyShareProofMaterial,
            relinearizationRoundOneContributions:
                evaluationKeyTransport.relinearizationRoundOneContributions,
            relinearizationRoundTwoContributions:
                evaluationKeyTransport.relinearizationRoundTwoContributions,
            galoisKeyShareBatchContributions:
                evaluationKeyTransport.galoisKeyShareBatchContributions,
            transportedEvaluationKeyShareProofMaterial:
                evaluationKeyTransport.transportedEvaluationKeyShareProofMaterial,
            transportedEvaluationKeyShareComponentMaterial:
                evaluationKeyTransport.transportedEvaluationKeyShareComponentMaterial,
            vssCoefficientCommitmentMaterialEncoding:
                'binary-chunked-full-public-setup-commitment-values',
            publicKeyShareMaterialEncoding:
                publicKeyShareMaterialTransportEncoding,
            setupCertificateInput: setupCertificateInputFixture(
                participantCount,
                binaryVssMaterialByteLength,
            ),
        } satisfies SetupCeremonyAssemblyInput;
        const assemblyWithoutPublicEvaluationKeyMaterial =
            await createSetupCeremonyAssembly(providerBackedTransportedInput);
        const publicEvaluationKeyMaterialTransport =
            createBinaryChunkedPublicEvaluationKeyMaterialTransport({
                setupContext: input.setupContext,
                qSharePrimes: input.qSharePrimes,
                participantCount,
                evaluatorKeySchedule:
                    assemblyWithoutPublicEvaluationKeyMaterial.evaluatorKeySchedule,
                sameSecretProofSetRoot:
                    assemblyWithoutPublicEvaluationKeyMaterial.sameSecretProofs
                        .sameSecretProofSetRoot,
                sameSecretProofFamilyBindingRoot:
                    assemblyWithoutPublicEvaluationKeyMaterial
                        .sameSecretConsistency.sameSecretProofFamilyBindingRoot,
                publicKeyShareLnpProofSetRoot:
                    assemblyWithoutPublicEvaluationKeyMaterial
                        .publicKeyShareLnpProofs.publicKeyShareLnpProofSetRoot,
                sameSecretProofReferences:
                    assemblyWithoutPublicEvaluationKeyMaterial.sameSecretProofs.proofRecords.map(
                        (proofRecord) => ({
                            trusteeIdentity: proofRecord.trusteeIdentity,
                            trusteeRosterPosition:
                                proofRecord.trusteeRosterPosition,
                            sameSecretStatementRoot:
                                proofRecord.sameSecretStatementRoot,
                            trusteeSecretCommitmentRoot:
                                proofRecord.trusteeSecretCommitmentRoot,
                            sameSecretProofRoot:
                                proofRecord.sameSecretProofRoot,
                        }),
                    ),
                relinearizationKeyShareRounds:
                    assemblyWithoutPublicEvaluationKeyMaterial.relinearizationKeyShareRounds,
                galoisKeyShareBatches:
                    assemblyWithoutPublicEvaluationKeyMaterial.galoisKeyShareBatches,
                transportedEvaluationKeyShareComponentMaterial:
                    evaluationKeyTransport.transportedEvaluationKeyShareComponentMaterial,
            });

        const assembly = await createSetupCeremonyAssembly({
            ...providerBackedTransportedInput,
            publicEvaluationKeyMaterialReference:
                publicEvaluationKeyMaterialTransport.publicEvaluationKeyMaterialReference,
            transportedPublicEvaluationKeyMaterial:
                publicEvaluationKeyMaterialTransport.transportedPublicEvaluationKeyMaterial,
        });
        const transportedVssMaterial =
            assembly.transportedVssCoefficientCommitmentMaterial;
        if (transportedVssMaterial === undefined) {
            throw new Error('assembly must include transported VSS material.');
        }
        const verificationInput = createSetupPackageVerificationInput({
            ...assembly,
            transportedVssCoefficientCommitmentMaterial: transportedVssMaterial,
        });

        expect(
            Array.from(
                { length: participantCount },
                (_unused, position) =>
                    sourceOpeningLoadCounts.get(position) ?? 0,
            ).every((loadCount) => loadCount > 0),
        ).toBe(true);
        expect(assembly.vssCoefficientCommitmentMaterial).not.toHaveProperty(
            'coefficientCommitments',
        );
        expect(assembly.transportedVssCoefficientCommitmentMaterial).toEqual(
            transportedVssMaterial,
        );
        expect(assembly.transportedPublicKeyShareMaterial).toBeDefined();
        expect(assembly.transportedSameSecretProofMaterial).toBe(
            sameSecretTransport.transportedSameSecretProofMaterial,
        );
        expect(assembly.transportedPublicKeyShareProofMaterial).toBe(
            publicKeyShareTransport.transportedPublicKeyShareProofMaterial,
        );
        expect(assembly.transportedEvaluationKeyShareComponentMaterial).toBe(
            evaluationKeyTransport.transportedEvaluationKeyShareComponentMaterial,
        );
        expect(verificationInput).toMatchObject({
            setupPackage: assembly.setupPackage,
            transportedVssCoefficientCommitmentMaterial: transportedVssMaterial,
            transportedPublicKeyShareMaterial:
                assembly.transportedPublicKeyShareMaterial,
            transportedPublicEvaluationKeyMaterial:
                publicEvaluationKeyMaterialTransport.transportedPublicEvaluationKeyMaterial,
        });
        expect(JSON.stringify(verificationInput)).not.toMatch(
            /localTrusteeSetupStates|setupContributions|sourceTrusteeOpeningStates|coefficientOpenings|mailboxSecretKeyBytesHex|storageKeyBytesHex|proofGeneration|secretCoefficients/u,
        );
    });

    it('refuses profile-ring assembly without terminal material transports', async () => {
        const participantCount = 10;
        const kernelFixture = createKernelFixture();
        const input = createAcceptedQShareAssemblyInput(
            participantCount,
            kernelFixture.kernel,
            ringDegree,
            firstProfileThresholdDegree,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                ringDegree: acceptedBgvProfileRingDegree,
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires binary-chunked VSS coefficient commitment material.',
        );
    });

    it('refuses profile-ring assembly outside the first setup profile roster and threshold', async () => {
        const kernelFixture = createKernelFixture();
        const wrongRosterInput = createAssemblyInput(
            3,
            kernelFixture.kernel,
            ringDegree,
            firstProfileThresholdDegree,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...wrongRosterInput,
                ringDegree: acceptedBgvProfileRingDegree,
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires the first-profile 10-trustee roster.',
        );

        const wrongThresholdInput = createAssemblyInput(
            10,
            kernelFixture.kernel,
            ringDegree,
            thresholdDegree,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...wrongThresholdInput,
                ringDegree: acceptedBgvProfileRingDegree,
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires first-profile q_dec 4 threshold shares.',
        );
    });

    it('refuses profile-ring assembly with embedded proof material', async () => {
        const participantCount = 10;
        const kernelFixture = createKernelFixture();
        const input = createAcceptedQShareAssemblyInput(
            participantCount,
            kernelFixture.kernel,
            ringDegree,
            firstProfileThresholdDegree,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                ringDegree: acceptedBgvProfileRingDegree,
                vssCoefficientCommitmentMaterialEncoding:
                    'binary-chunked-full-public-setup-commitment-values',
                publicKeyShareMaterialEncoding:
                    publicKeyShareMaterialTransportEncoding,
                publicEvaluationKeyMaterialReference: {
                    publicEvaluationKeyMaterialEncoding:
                        'binary-chunked-public-evaluation-key-root-manifest',
                    publicEvaluationKeyMaterialRoot: fixtureHash(
                        'public-evaluation-key-material',
                    ),
                    publicEvaluationKeyMaterialChunkSizeBytes: 1_048_576,
                    publicEvaluationKeyMaterialChunkCount: 1,
                    publicEvaluationKeyMaterialTotalByteLength: 64,
                    publicEvaluationKeyMaterialFullObjectHash: fixtureHash(
                        'public-evaluation-key-material-full',
                    ),
                    publicEvaluationKeyMaterialChunkRoot: fixtureHash(
                        'public-evaluation-key-material-chunk-root',
                    ),
                    publicEvaluationKeyMaterialChunkHashes: [
                        fixtureHash('public-evaluation-key-material-chunk'),
                    ],
                },
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires transported same-secret proof material.',
        );
    });

    it('refuses profile-ring assembly with eager source opening state loading', async () => {
        const participantCount = 10;
        const kernelFixture = createKernelFixture();
        const input = createAcceptedQShareAssemblyInput(
            participantCount,
            kernelFixture.kernel,
            ringDegree,
            firstProfileThresholdDegree,
        );
        const sameSecretTransport =
            createBinaryChunkedSameSecretProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundSameSecretProofMaterial(position),
                ),
            );
        const publicKeyShareTransport =
            createBinaryChunkedPublicKeyShareProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundPublicKeyShareProofMaterial(position),
                ),
            );
        const evaluationKeyTransport =
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    sameSecretProofReferencesFixture(participantCount),
                relinearizationRoundOneContributions:
                    input.relinearizationRoundOneContributions,
                relinearizationRoundTwoContributions:
                    input.relinearizationRoundTwoContributions,
                galoisKeyShareBatchContributions:
                    input.galoisKeyShareBatchContributions,
            });

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                ringDegree: acceptedBgvProfileRingDegree,
                vssCoefficientCommitmentMaterialEncoding:
                    'binary-chunked-full-public-setup-commitment-values',
                publicKeyShareMaterialEncoding:
                    publicKeyShareMaterialTransportEncoding,
                sameSecretProofMaterials: sameSecretTransport.proofMaterials,
                transportedSameSecretProofMaterial:
                    sameSecretTransport.transportedSameSecretProofMaterial,
                publicKeyShareLnpProofMaterials:
                    publicKeyShareTransport.proofMaterials,
                transportedPublicKeyShareProofMaterial:
                    publicKeyShareTransport.transportedPublicKeyShareProofMaterial,
                relinearizationRoundOneContributions:
                    evaluationKeyTransport.relinearizationRoundOneContributions,
                relinearizationRoundTwoContributions:
                    evaluationKeyTransport.relinearizationRoundTwoContributions,
                galoisKeyShareBatchContributions:
                    evaluationKeyTransport.galoisKeyShareBatchContributions,
                transportedEvaluationKeyShareProofMaterial:
                    evaluationKeyTransport.transportedEvaluationKeyShareProofMaterial,
                transportedEvaluationKeyShareComponentMaterial:
                    evaluationKeyTransport.transportedEvaluationKeyShareComponentMaterial,
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires provider-backed source trustee opening state loading.',
        );
    });

    it('refuses profile-ring assembly with public derivation root mismatches', async () => {
        const participantCount = 10;
        const kernelFixture = createKernelFixture();
        const input = createAcceptedQShareAssemblyInput(
            participantCount,
            kernelFixture.kernel,
            ringDegree,
            firstProfileThresholdDegree,
        );
        const sameSecretTransport =
            createBinaryChunkedSameSecretProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundSameSecretProofMaterial(position),
                ),
            );
        const publicKeyShareTransport =
            createBinaryChunkedPublicKeyShareProofMaterialTransport(
                Array.from({ length: participantCount }, (_unused, position) =>
                    hashBoundPublicKeyShareProofMaterial(position),
                ),
            );
        const evaluationKeyTransport =
            createBinaryChunkedEvaluationKeyShareMaterialTransport({
                sameSecretProofReferences:
                    sameSecretProofReferencesFixture(participantCount),
                relinearizationRoundOneContributions:
                    input.relinearizationRoundOneContributions,
                relinearizationRoundTwoContributions:
                    input.relinearizationRoundTwoContributions,
                galoisKeyShareBatchContributions:
                    input.galoisKeyShareBatchContributions,
            });
        const sourceTrusteeOpeningStateProvider = {
            sourceTrusteeReferences: input.trustees.map((trustee) => ({
                sourceTrusteeIdentity: trustee.trusteeIdentity,
                sourceTrusteeRosterPosition: trustee.trusteeRosterPosition,
            })),
            loadSourceTrusteeOpeningState: (sourceTrusteeReference: {
                readonly sourceTrusteeIdentity: string;
                readonly sourceTrusteeRosterPosition: number;
            }) =>
                sourceTrusteeOpeningState(
                    sourceTrusteeReference.sourceTrusteeRosterPosition,
                    input.ringDegree,
                    input.thresholdDegree,
                    input.qSharePrimes,
                ),
        };
        const commonRandomnessPublicDerivations = jsonRecord(
            input.commonRandomness.publicDerivations,
            'commonRandomness.publicDerivations',
        );
        const mismatchedCommonRandomness = {
            ...input.commonRandomness,
            publicDerivations: {
                ...commonRandomnessPublicDerivations,
                crpRoots: {
                    ...jsonRecord(
                        commonRandomnessPublicDerivations.crpRoots,
                        'commonRandomness.publicDerivations.crpRoots',
                    ),
                    publicKeyCrpRoot: fixtureHash('mutated-public-key-crp'),
                },
            },
        } satisfies SetupCommonRandomness;

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                commonRandomness: mismatchedCommonRandomness,
                ringDegree: acceptedBgvProfileRingDegree,
                sourceTrusteeOpeningStates: undefined,
                sourceTrusteeOpeningStateProvider,
                vssCoefficientCommitmentMaterialEncoding:
                    'binary-chunked-full-public-setup-commitment-values',
                publicKeyShareMaterialEncoding:
                    publicKeyShareMaterialTransportEncoding,
                setupCertificateInput: setupCertificateInputFixture(
                    participantCount,
                    binaryVssMaterialByteLengthForInput(input),
                    input.ringDegree,
                    input.thresholdDegree,
                    input.setupContext,
                    input.qShare,
                    input.qSharePrimes,
                ),
                sameSecretProofMaterials: sameSecretTransport.proofMaterials,
                transportedSameSecretProofMaterial:
                    sameSecretTransport.transportedSameSecretProofMaterial,
                publicKeyShareLnpProofMaterials:
                    publicKeyShareTransport.proofMaterials,
                transportedPublicKeyShareProofMaterial:
                    publicKeyShareTransport.transportedPublicKeyShareProofMaterial,
                relinearizationRoundOneContributions:
                    evaluationKeyTransport.relinearizationRoundOneContributions,
                relinearizationRoundTwoContributions:
                    evaluationKeyTransport.relinearizationRoundTwoContributions,
                galoisKeyShareBatchContributions:
                    evaluationKeyTransport.galoisKeyShareBatchContributions,
                transportedEvaluationKeyShareProofMaterial:
                    evaluationKeyTransport.transportedEvaluationKeyShareProofMaterial,
                transportedEvaluationKeyShareComponentMaterial:
                    evaluationKeyTransport.transportedEvaluationKeyShareComponentMaterial,
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires publicKeyCrpRoot to match commonRandomness public derivations.',
        );
    });

    it('refuses profile-ring assembly with a non-accepted Q_share list', async () => {
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            10,
            kernelFixture.kernel,
            ringDegree,
            firstProfileThresholdDegree,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                ringDegree: acceptedBgvProfileRingDegree,
                vssCoefficientCommitmentMaterialEncoding:
                    'binary-chunked-full-public-setup-commitment-values',
                publicKeyShareMaterialEncoding:
                    publicKeyShareMaterialTransportEncoding,
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires the accepted Q_share prime list.',
        );
    });

    it('refuses profile-ring assembly with accepted primes but non-accepted Q_share metadata', async () => {
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            10,
            kernelFixture.kernel,
            ringDegree,
            firstProfileThresholdDegree,
        );

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                ringDegree: acceptedBgvProfileRingDegree,
                qSharePrimes: acceptedBgvSetupQSharePrimes,
                vssCoefficientCommitmentMaterialEncoding:
                    'binary-chunked-full-public-setup-commitment-values',
                publicKeyShareMaterialEncoding:
                    publicKeyShareMaterialTransportEncoding,
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires the accepted Q_share object.',
        );

        await expect(
            createSetupCeremonyAssembly({
                ...createAcceptedQShareAssemblyInput(
                    10,
                    kernelFixture.kernel,
                    ringDegree,
                    firstProfileThresholdDegree,
                ),
                qShare: {
                    ...acceptedBgvSetupQShare,
                    targetDecryptionReadiness:
                        'target-decryption-ready-without-target-certificate',
                },
                ringDegree: acceptedBgvProfileRingDegree,
                vssCoefficientCommitmentMaterialEncoding:
                    'binary-chunked-full-public-setup-commitment-values',
                publicKeyShareMaterialEncoding:
                    publicKeyShareMaterialTransportEncoding,
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires the accepted Q_share object.',
        );

        await expect(
            createSetupCeremonyAssembly({
                ...createAcceptedQShareAssemblyInput(
                    10,
                    kernelFixture.kernel,
                    ringDegree,
                    firstProfileThresholdDegree,
                ),
                setupContext,
                ringDegree: acceptedBgvProfileRingDegree,
                vssCoefficientCommitmentMaterialEncoding:
                    'binary-chunked-full-public-setup-commitment-values',
                publicKeyShareMaterialEncoding:
                    publicKeyShareMaterialTransportEncoding,
            }),
        ).rejects.toThrow(
            'profile-ring setup assembly requires setupContext.qShareHash to match the accepted Q_share object.',
        );
    });

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
        const transportedObjects = assembly.setupPackage
            .setupTransportCertificate.transportedObjects as readonly Record<
            string,
            unknown
        >[];
        const vssTransportedObject = transportedObjects.find(
            (transportedObject) =>
                transportedObject.objectName ===
                'vssCoefficientCommitmentMaterial',
        );
        expect(assembly.setupPackage.setupTransportCertificate).toMatchObject({
            totalByteLength: fullMaterialCoefficientBytes,
            chunkCount:
                assembly.transportedVssCoefficientCommitmentMaterial
                    ?.chunkCount,
            transportedObjects: [
                expect.objectContaining({
                    objectName: 'vssCoefficientCommitmentMaterial',
                    objectRole: 'public-vss-coefficient-commitment-material',
                    objectRoot:
                        assembly.vssCoefficientCommitmentMaterial
                            .vssCoefficientCommitmentMaterialRoot,
                    fullObjectHash:
                        assembly.transportedVssCoefficientCommitmentMaterial
                            ?.fullObjectHash,
                    chunkRoot:
                        assembly.transportedVssCoefficientCommitmentMaterial
                            ?.chunkRoot,
                    chunkHashes:
                        assembly.transportedVssCoefficientCommitmentMaterial
                            ?.chunkHashes,
                    byteLength: fullMaterialCoefficientBytes,
                }),
            ],
        });
        expect(vssTransportedObject).toBeDefined();
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

    it('uses kernel-derived threshold commitments from transported VSS material', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const commitmentBundle = createVssCoefficientCommitmentBundle({
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            qSharePrimes: input.qSharePrimes,
            ringDegree: input.ringDegree,
            participantCount: input.trustees.length,
            thresholdDegree: input.thresholdDegree,
            sourceTrusteeOpeningStates: input.sourceTrusteeOpeningStates,
        });
        const expectedTransport =
            createBinaryChunkedVssCoefficientCommitmentMaterialTransport(
                commitmentBundle.materialSet,
            );
        const expectedThresholdShareCommitments =
            deriveThresholdShareCommitments({
                setupContext: input.setupContext,
                vssCoefficientCommitments: commitmentBundle.commitmentSet,
                vssCoefficientCommitmentMaterial: expectedTransport.materialSet,
                transportedVssCoefficientCommitmentMaterial:
                    expectedTransport.transportedVssCoefficientCommitmentMaterial,
            });
        let transportDerivationCount = 0;
        const deriveThresholdShareCommitmentsFromTransport = (
            request: Readonly<{
                readonly setupContext: unknown;
                readonly publicMatrixSeedHash: ProtocolHash;
                readonly vssCoefficientCommitmentRoot: ProtocolHash;
                readonly sourceTrusteeCoefficientCommitmentRecords: readonly unknown[];
                readonly transportedVssCoefficientCommitmentMaterial: unknown;
            }>,
        ): {
            readonly thresholdShareCommitmentRoot: ProtocolHash;
            readonly thresholdShareCommitments: JsonRecord;
            readonly vssCoefficientCommitmentMaterial: JsonRecord;
        } => {
            transportDerivationCount += 1;
            expect(request.transportedVssCoefficientCommitmentMaterial).toEqual(
                expectedTransport.transportedVssCoefficientCommitmentMaterial,
            );

            return {
                thresholdShareCommitmentRoot:
                    expectedThresholdShareCommitments.thresholdShareCommitmentRoot,
                thresholdShareCommitments: expectedThresholdShareCommitments,
                vssCoefficientCommitmentMaterial: expectedTransport.materialSet,
            };
        };

        const assembly = await createSetupCeremonyAssembly({
            ...input,
            kernel: {
                ...input.kernel,
                deriveThresholdShareCommitmentsFromTransport,
            },
            vssCoefficientCommitmentMaterialEncoding:
                'binary-chunked-full-public-setup-commitment-values',
            setupCertificateInput: setupCertificateInputFixture(
                participantCount,
                expectedTransport.transportedVssCoefficientCommitmentMaterial
                    .totalByteLength,
            ),
        });

        expect(transportDerivationCount).toBe(1);
        expect(assembly.thresholdShareCommitments).toEqual(
            expectedThresholdShareCommitments,
        );
        expect(assembly.setupPackage.thresholdShareCommitments).toEqual(
            expectedThresholdShareCommitments,
        );
    });

    it('uses stream-verified VSS material for binary setup assembly', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const commitmentBundle = createVssCoefficientCommitmentBundle({
            setupContext: input.setupContext,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            qSharePrimes: input.qSharePrimes,
            ringDegree: input.ringDegree,
            participantCount: input.trustees.length,
            thresholdDegree: input.thresholdDegree,
            sourceTrusteeOpeningStates: input.sourceTrusteeOpeningStates,
        });
        const expectedTransport =
            createBinaryChunkedVssCoefficientCommitmentMaterialTransport(
                commitmentBundle.materialSet,
            );
        const expectedThresholdShareCommitments =
            deriveThresholdShareCommitments({
                setupContext: input.setupContext,
                vssCoefficientCommitments: commitmentBundle.commitmentSet,
                vssCoefficientCommitmentMaterial: expectedTransport.materialSet,
                transportedVssCoefficientCommitmentMaterial:
                    expectedTransport.transportedVssCoefficientCommitmentMaterial,
            });
        const capturedChunks: {
            readonly chunkIndex: number;
            readonly bytesHex: string;
        }[] = [];
        let beginCount = 0;
        let finishCount = 0;
        const verifiedVssCoefficientCommitmentMaterial = {
            objectType: 'VerifiedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            verificationId: 'assembly-vss-stream-1',
            materialBinaryFormat:
                'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
            publicMatrixSeedHash:
                expectedTransport.materialSet.publicMatrixSeedHash,
            vssCoefficientCommitmentRoot:
                commitmentBundle.commitmentSet.vssCoefficientCommitmentRoot,
            vssCoefficientCommitmentMaterialRoot:
                expectedTransport.materialSet
                    .vssCoefficientCommitmentMaterialRoot,
            thresholdShareCommitmentRoot:
                expectedThresholdShareCommitments.thresholdShareCommitmentRoot,
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
            transportChunkSizeBytes: 1_048_576,
            transportChunkCount:
                expectedTransport.transportedVssCoefficientCommitmentMaterial
                    .chunkCount,
            transportTotalByteLength:
                expectedTransport.transportedVssCoefficientCommitmentMaterial
                    .totalByteLength,
            transportFullObjectHash:
                expectedTransport.transportedVssCoefficientCommitmentMaterial
                    .fullObjectHash,
            transportChunkRoot:
                expectedTransport.transportedVssCoefficientCommitmentMaterial
                    .chunkRoot,
        } as const;

        const assembly = await createSetupCeremonyAssembly({
            ...input,
            kernel: {
                ...input.kernel,
                beginThresholdShareCommitmentsFromTransportStream: (
                    request,
                ) => {
                    beginCount += 1;
                    expect(request.derivationId).toMatch(/^vss-transport-/u);
                    expect(request.setupContext).toBe(input.setupContext);
                    expect(request.publicMatrixSeedHash).toBe(
                        input.publicMatrixSeedHash,
                    );
                    expect(
                        request.transportedVssCoefficientCommitmentMaterial,
                    ).toMatchObject({
                        objectType:
                            'SetupTransportedVssCoefficientCommitmentMaterial',
                        chunkCount:
                            expectedTransport
                                .transportedVssCoefficientCommitmentMaterial
                                .chunkCount,
                        totalByteLength:
                            expectedTransport
                                .transportedVssCoefficientCommitmentMaterial
                                .totalByteLength,
                    });
                    expect(
                        request.transportedVssCoefficientCommitmentMaterial,
                    ).not.toHaveProperty('chunks');

                    return { ok: true };
                },
                absorbThresholdShareCommitmentsFromTransportStreamChunk: (
                    request,
                ) => {
                    capturedChunks.push({
                        chunkIndex: request.chunkIndex,
                        bytesHex: request.bytesHex,
                    });

                    return { ok: true };
                },
                finishThresholdShareCommitmentsFromTransportStream: (
                    request,
                ) => {
                    finishCount += 1;
                    expect(request.vssCoefficientCommitmentRoot).toBe(
                        commitmentBundle.commitmentSet
                            .vssCoefficientCommitmentRoot,
                    );
                    expect(
                        request.sourceTrusteeCoefficientCommitmentRecords,
                    ).toEqual(
                        commitmentBundle.commitmentSet.sourceTrusteeRecords,
                    );
                    expect(capturedChunks).toEqual(
                        expectedTransport
                            .transportedVssCoefficientCommitmentMaterial.chunks,
                    );

                    return {
                        thresholdShareCommitmentRoot:
                            expectedThresholdShareCommitments.thresholdShareCommitmentRoot,
                        thresholdShareCommitments:
                            expectedThresholdShareCommitments,
                        vssCoefficientCommitmentMaterial:
                            expectedTransport.materialSet,
                        verifiedVssCoefficientCommitmentMaterial,
                        transport: {
                            fullObjectHash:
                                expectedTransport
                                    .transportedVssCoefficientCommitmentMaterial
                                    .fullObjectHash,
                        },
                    };
                },
            },
            vssCoefficientCommitmentMaterialEncoding:
                'binary-chunked-full-public-setup-commitment-values',
            setupCertificateInput: setupCertificateInputFixture(
                participantCount,
                expectedTransport.transportedVssCoefficientCommitmentMaterial
                    .totalByteLength,
            ),
        });
        const verificationInput = createSetupPackageVerificationInput(assembly);

        expect(beginCount).toBe(1);
        expect(finishCount).toBe(1);
        expect(assembly.thresholdShareCommitments).toEqual(
            expectedThresholdShareCommitments,
        );
        expect(assembly.verifiedVssCoefficientCommitmentMaterial).toBe(
            verifiedVssCoefficientCommitmentMaterial,
        );
        const streamedTransportedVssMaterialReference =
            assembly.transportedVssCoefficientCommitmentMaterial;
        expect(streamedTransportedVssMaterialReference).not.toHaveProperty(
            'chunks',
        );
        expect(verificationInput.verifiedVssCoefficientCommitmentMaterial).toBe(
            verifiedVssCoefficientCommitmentMaterial,
        );
        expect(
            verificationInput.transportedVssCoefficientCommitmentMaterial,
        ).toEqual(streamedTransportedVssMaterialReference);

        const verificationInputWithRawVssMaterial =
            createSetupPackageVerificationInput({
                ...assembly,
                transportedVssCoefficientCommitmentMaterial:
                    expectedTransport.transportedVssCoefficientCommitmentMaterial,
            });

        expect(
            verificationInputWithRawVssMaterial.verifiedVssCoefficientCommitmentMaterial,
        ).toBe(verifiedVssCoefficientCommitmentMaterial);
        expect(
            verificationInputWithRawVssMaterial.transportedVssCoefficientCommitmentMaterial,
        ).toEqual(streamedTransportedVssMaterialReference);
        expect(
            verificationInputWithRawVssMaterial.transportedVssCoefficientCommitmentMaterial,
        ).not.toHaveProperty('chunks');
    });

    it('assembles a setup package bound to binary-chunked public-key share material', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const assembly = await createSetupCeremonyAssembly({
            ...input,
            publicKeyShareMaterialEncoding:
                publicKeyShareMaterialTransportEncoding,
        });

        expect(assembly.publicKeyShareMaterial).toMatchObject({
            objectType: 'PublicKeyShareMaterialSet',
            materialEncoding: publicKeyShareMaterialTransportEncoding,
            publicKeyShareSetRoot:
                assembly.publicKeyShares.publicKeyShareSetRoot,
            transport: {
                fullObjectHash:
                    assembly.transportedPublicKeyShareMaterial?.fullObjectHash,
                chunkRoot:
                    assembly.transportedPublicKeyShareMaterial?.chunkRoot,
                totalByteLength:
                    assembly.transportedPublicKeyShareMaterial?.totalByteLength,
            },
        });
        expect(assembly.publicKeyShareMaterial).not.toHaveProperty(
            'shareMaterialRecords',
        );
        expect(assembly.transportedPublicKeyShareMaterial).toMatchObject({
            objectType: 'SetupTransportedPublicKeyShareMaterial',
            binaryFormat: 'sealed-lattice-public-key-share-material-binary-v1',
        });
        expect(
            assembly.transportedPublicKeyShareMaterial?.totalByteLength,
        ).toBeGreaterThan(0);
        expect(assembly.setupPackage.publicKeyShareMaterial).toEqual(
            assembly.publicKeyShareMaterial,
        );
        const transportedObjects = assembly.setupPackage
            .setupTransportCertificate.transportedObjects as readonly Record<
            string,
            unknown
        >[];
        expect(transportedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    objectName: 'publicKeyShareMaterial',
                    objectRole: 'public-key-share-material',
                    objectRoot:
                        assembly.publicKeyShareMaterial
                            .publicKeyShareMaterialSetRoot,
                    fullObjectHash:
                        assembly.transportedPublicKeyShareMaterial
                            ?.fullObjectHash,
                    chunkRoot:
                        assembly.transportedPublicKeyShareMaterial?.chunkRoot,
                    chunkHashes:
                        assembly.transportedPublicKeyShareMaterial?.chunkHashes,
                    byteLength:
                        assembly.transportedPublicKeyShareMaterial
                            ?.totalByteLength,
                }),
            ]),
        );
        expect(
            assembly.publicKeyShareLnpProofs.publicKeyShareMaterialSetRoot,
        ).toBe(assembly.publicKeyShareMaterial.publicKeyShareMaterialSetRoot);
        expect(assembly.collectivePublicKey.publicKeyShareMaterialSetRoot).toBe(
            assembly.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        );
        expect(
            assembly.collectivePublicKey.sourceShareMaterialRoots,
        ).toHaveLength(participantCount);
        expect(
            assembly.collectivePublicKey.aggregateCoefficientVectorsByLimb,
        ).toHaveLength(qSharePrimes.length);
    });

    it('rejects opening states rebound to another trustee identity', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const sourceTrusteeOpeningStates = input.sourceTrusteeOpeningStates;
        if (sourceTrusteeOpeningStates === undefined) {
            throw new Error(
                'setup assembly fixture must provide source trustee opening states.',
            );
        }

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                sourceTrusteeOpeningStates: sourceTrusteeOpeningStates.map(
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

    it('rejects provider-loaded opening states rebound to another trustee identity', async () => {
        const participantCount = 3;
        const kernelFixture = createKernelFixture();
        const input = createAssemblyInput(
            participantCount,
            kernelFixture.kernel,
        );
        const sourceTrusteeOpeningStateProvider = {
            sourceTrusteeReferences: input.trustees.map((trustee) => ({
                sourceTrusteeIdentity: trustee.trusteeIdentity,
                sourceTrusteeRosterPosition: trustee.trusteeRosterPosition,
            })),
            loadSourceTrusteeOpeningState: (sourceTrusteeReference: {
                readonly sourceTrusteeRosterPosition: number;
            }) =>
                sourceTrusteeReference.sourceTrusteeRosterPosition === 1
                    ? sourceTrusteeOpeningState(0)
                    : sourceTrusteeOpeningState(
                          sourceTrusteeReference.sourceTrusteeRosterPosition,
                      ),
        };

        await expect(
            createSetupCeremonyAssembly({
                ...input,
                sourceTrusteeOpeningStates: undefined,
                sourceTrusteeOpeningStateProvider,
            }),
        ).rejects.toThrow(
            /loaded source trustee opening state must match the requested source trustee reference/u,
        );
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
