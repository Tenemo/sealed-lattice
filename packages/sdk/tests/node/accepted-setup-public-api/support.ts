import {
    createSetupPackageVerificationInput,
    verifyPrivateVssShare,
    verifySetupPackage,
} from '../../../dist/index.js';
import { loadTranscriptCoreKernel } from '../../../dist/kernel.js';
import {
    createCommonRandomnessCommit,
    createCommonRandomnessReveal,
    createEvaluatorKeySchedule,
    createGaloisKeyShareBatches,
    createPublicEvaluationKeySet,
    createPublicKeyShareMaterialSet,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createPublicKeyShareSuccinctProofSet,
    createRelinearizationKeyShareRounds,
    createSameSecretProofSet,
    createSetupCertificates,
    createSetupCommonRandomness,
    createSetupContribution,
    createSetupIntent,
    createSetupPackage,
    createSetupPhaseRecord,
    createVssComplaint,
    createVssShareAcceptance,
    exportEncryptedLocalTrusteeSetupState,
    restoreLocalTrusteeSetupState,
} from '../../support/internal-setup-flow.js';

import { hash512Hex } from '#packages/crypto/src/index';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import {
    acceptedBgvSetupQSharePrimes,
    createSameSecretConsistencyStatementSet,
    createVssCoefficientCommitmentBundle,
    publicKeyShareCoefficientVectorHashDomain,
    setupTransportChunkSizeBytes,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/index';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';

export { hash512Hex };
export {
    createSameSecretConsistencyStatementSet,
    createVssCoefficientCommitmentBundle,
};

export type PublicSetupApi = {
    readonly createCommonRandomnessCommit: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
    readonly createCommonRandomnessReveal: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
    readonly createEvaluatorKeySchedule: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createGaloisKeyShareBatches: (
        input: unknown,
    ) => readonly Record<string, unknown>[];
    readonly createPublicEvaluationKeySet: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createPublicKeyShareSuccinctProofSet: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createPublicKeyShareMaterialSet: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createPublicKeyShareProofSet: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createPublicKeyShareSet: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createRelinearizationKeyShareRounds: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createSameSecretProofSet: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createSetupCommonRandomness: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
    readonly createSetupContribution: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createSetupCertificates: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createSetupIntent: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
    readonly createSetupPackage: (input: unknown) => Record<string, unknown>;
    readonly createSetupPackageVerificationInput: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createSetupPhaseRecord: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createVssShareAcceptance: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
    readonly createVssComplaint: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
    readonly exportEncryptedLocalTrusteeSetupState: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
    readonly restoreLocalTrusteeSetupState: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
    readonly verifySetupPackage: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
    readonly verifyPrivateVssShare: (
        input: unknown,
    ) => Promise<Record<string, unknown>>;
};

// The setup-assembly builders are demoted out of the public verifier-only SDK and now live
// in the relocated test-support module; the verifier path stays on the published dist surface.
// The test still builds a package through the relocated internal flow and verifies it through
// the public verifier path.
export const publicSetupApi = {
    createCommonRandomnessCommit,
    createCommonRandomnessReveal,
    createEvaluatorKeySchedule,
    createGaloisKeyShareBatches,
    createPublicEvaluationKeySet,
    createPublicKeyShareMaterialSet,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createPublicKeyShareSuccinctProofSet,
    createRelinearizationKeyShareRounds,
    createSameSecretProofSet,
    createSetupCertificates,
    createSetupCommonRandomness,
    createSetupContribution,
    createSetupIntent,
    createSetupPackage,
    createSetupPackageVerificationInput,
    createSetupPhaseRecord,
    createVssComplaint,
    createVssShareAcceptance,
    exportEncryptedLocalTrusteeSetupState,
    restoreLocalTrusteeSetupState,
    verifyPrivateVssShare,
    verifySetupPackage,
} as unknown as PublicSetupApi;
export const loadPublicTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    loadTranscriptCoreKernel;
export const trusteeIdentity = 'trustee-0';
export const trusteeRosterPosition = 0;

type SetupContextFixture = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: string;
    readonly rosterHash: string;
    readonly setupParametersHash: string;
    readonly setupEpoch: string;
}>;

export const hashFromKernel = (
    kernel: TranscriptCoreKernel,
    label: string,
): string =>
    kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'ActionContextHash',
            fixture: 'accepted-setup-public-api',
            label,
        },
    });

export const setupContextFromKernel = (
    kernel: TranscriptCoreKernel,
): SetupContextFixture => {
    const parameters = kernel.describeCollectiveBgvSetupParameters();

    return {
        ceremonyId: 'ceremony-public-setup-api',
        manifestHash: hashFromKernel(kernel, 'manifest'),
        rosterHash: hashFromKernel(kernel, 'roster'),
        setupParametersHash: parameters.setupParametersHash,
        setupEpoch: 'setup-epoch-1',
    } as const;
};

export const contextFields = (
    setupContext: SetupContextFixture,
): SetupContextFixture => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupParametersHash: setupContext.setupParametersHash,
    setupEpoch: setupContext.setupEpoch,
});

const canonicalObjectHashFromKernel = (
    kernel: TranscriptCoreKernel,
    value: Record<string, unknown>,
): string =>
    kernel.deriveCanonicalObjectHash({
        value,
    });

const qSharePrimes = acceptedBgvSetupQSharePrimes;
export { qSharePrimes };
export const participantCount = 2;
export const vssFixtureRingDegree = 8;
export const vssFixtureThresholdDegree = 2;
export { setupTransportChunkSizeBytes };
export const requiredGaloisKeySchedule = [
    {
        rotation: 3,
        level: 1,
        purpose: 'public-package-fixture',
        proofFamily: 'galois-key-share',
    },
] as const;

const vssCoefficientMessage = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    rnsPrime: number,
): readonly number[] =>
    Array.from(
        { length: vssFixtureRingDegree },
        (_unused, coefficientIndex) => {
            const value =
                (sourceTrusteeRosterPosition + 1) * 23 +
                (rnsLimbIndex + 1) * 11 +
                (shamirCoefficientIndex + 1) * 7 +
                coefficientIndex;

            return value % rnsPrime;
        },
    );

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

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

const coefficientVectorHash = (coefficients: readonly number[]): string =>
    hash512Hex(publicKeyShareCoefficientVectorHashDomain, [
        coefficientVectorBytes(coefficients),
    ]);

const publicKeyShareCoefficientVector = (
    shareRosterPosition: number,
    rnsLimbIndex: number,
    rnsPrime: number,
): readonly number[] =>
    Array.from(
        { length: vssFixtureRingDegree },
        (_unused, coefficientIndex) =>
            ((shareRosterPosition + 1) * 31 +
                (rnsLimbIndex + 1) * 17 +
                coefficientIndex * 5) %
            rnsPrime,
    );

export const publicKeyShareMaterialContribution = (
    shareRosterPosition: number,
): Record<string, unknown> => ({
    trusteeIdentity: `trustee-${String(shareRosterPosition)}`,
    trusteeRosterPosition: shareRosterPosition,
    shareCoefficientVectorsByLimb: qSharePrimes.map(
        (rnsPrime, rnsLimbIndex) => {
            const coefficients = publicKeyShareCoefficientVector(
                shareRosterPosition,
                rnsLimbIndex,
                rnsPrime,
            );

            return {
                rnsLimbIndex,
                rnsPrime,
                component: 'b_i',
                coefficientByteLength: vssFixtureRingDegree * 8,
                coefficientVectorHash512: coefficientVectorHash(coefficients),
                coefficientsLeHex: bytesToHex(
                    coefficientVectorBytes(coefficients),
                ),
            };
        },
    ),
});

const vssOpeningRandomnessByColumn = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): readonly (readonly number[])[] =>
    Array.from({ length: 5 }, (_unusedColumn, randomnessColumnIndex) =>
        Array.from(
            { length: vssFixtureRingDegree },
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

const vssCoefficientOpening = (
    sourceTrusteeRosterPosition: number,
    rnsPrime: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningInput => ({
    rnsLimbIndex,
    rnsPrime,
    shamirCoefficientIndex,
    coefficientMessage: vssCoefficientMessage(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
        rnsPrime,
    ),
    randomnessByColumn: vssOpeningRandomnessByColumn(
        sourceTrusteeRosterPosition,
        rnsLimbIndex,
        shamirCoefficientIndex,
    ),
});

export const vssSourceTrusteeOpeningState = (
    sourceTrusteeRosterPosition: number,
): VssSourceTrusteeCoefficientOpeningState => ({
    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
    sourceTrusteeRosterPosition,
    coefficientOpenings: qSharePrimes.flatMap((rnsPrime, rnsLimbIndex) =>
        Array.from(
            { length: vssFixtureThresholdDegree },
            (_unused, shamirCoefficientIndex) =>
                vssCoefficientOpening(
                    sourceTrusteeRosterPosition,
                    rnsPrime,
                    rnsLimbIndex,
                    shamirCoefficientIndex,
                ),
        ),
    ),
});

export const sameSecretProofMaterial = (
    kernel: TranscriptCoreKernel,
    statementRecord: Record<string, unknown>,
): Record<string, unknown> => {
    const proofRosterPosition = Number(statementRecord.trusteeRosterPosition);
    const proofBytesHex = `aa55${proofRosterPosition.toString(16).padStart(4, '0')}`;

    return {
        proofFamily: 'same-secret-linkage-anchor',
        trusteeIdentity: statementRecord.trusteeIdentity,
        trusteeRosterPosition: proofRosterPosition,
        statementHash: hashFromKernel(
            kernel,
            `same-secret-proof-statement-${String(proofRosterPosition)}`,
        ),
        proofSizeBytes: proofBytesHex.length / 2,
        proofBytesHash: hashFromKernel(
            kernel,
            `same-secret-proof-bytes-${String(proofRosterPosition)}`,
        ),
        proofBytesHex,
    };
};

export const sameSecretProofReferencesFromSet = (
    sameSecretProofs: Record<string, unknown>,
): readonly Record<string, unknown>[] =>
    (sameSecretProofs.proofRecords as readonly Record<string, unknown>[]).map(
        (proofRecord) => ({
            trusteeIdentity: proofRecord.trusteeIdentity,
            trusteeRosterPosition: proofRecord.trusteeRosterPosition,
            sameSecretStatementRoot: proofRecord.sameSecretStatementRoot,
            trusteeSecretCommitmentRoot:
                proofRecord.trusteeSecretCommitmentRoot,
            sameSecretProofRoot: proofRecord.sameSecretProofRoot,
        }),
    );

export const publicKeyShareSuccinctProofMaterial = (
    kernel: TranscriptCoreKernel,
    proofRecord: Record<string, unknown>,
): Record<string, unknown> => {
    const proofRosterPosition = Number(proofRecord.trusteeRosterPosition);
    const proofBytesHex = `bb66${proofRosterPosition.toString(16).padStart(4, '0')}`;

    return {
        proofFamily: 'public-key-share',
        trusteeIdentity: proofRecord.trusteeIdentity,
        trusteeRosterPosition: proofRosterPosition,
        statementHash: hashFromKernel(
            kernel,
            `public-key-succinct-statement-${String(proofRosterPosition)}`,
        ),
        proofSizeBytes: proofBytesHex.length / 2,
        proofBytesHash: hashFromKernel(
            kernel,
            `public-key-succinct-proof-bytes-${String(proofRosterPosition)}`,
        ),
        proofBytesHex,
    };
};

const relinearizationKeySwitchSeed = (
    kernel: TranscriptCoreKernel,
    evaluatorKeySchedule: Record<string, unknown>,
    round: 'round-one' | 'round-two',
    level: number,
): string =>
    canonicalObjectHashFromKernel(kernel, {
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        objectVersion: 1,
        proofFamily: 'relinearization-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-level-and-round',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        relinearizationCrpRoot: evaluatorKeySchedule.relinearizationCrpRoot,
        round,
        level,
    });

const galoisKeySwitchSeed = (
    kernel: TranscriptCoreKernel,
    evaluatorKeySchedule: Record<string, unknown>,
    rotation: number,
    level: number,
): string =>
    canonicalObjectHashFromKernel(kernel, {
        objectType: 'GaloisKeySwitchPublicSampleSeed',
        objectVersion: 1,
        proofFamily: 'galois-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-rotation-and-level',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        galoisKeyCrpRoot: evaluatorKeySchedule.galoisKeyCrpRoot,
        requiredGaloisSetHash: evaluatorKeySchedule.requiredGaloisSetHash,
        rotation,
        level,
    });

export const relinearizationShareMaterial = (
    kernel: TranscriptCoreKernel,
    evaluatorKeySchedule: Record<string, unknown>,
    shareRoot: string,
    label: string,
    round: 'round-one' | 'round-two',
    level: number,
): Record<string, unknown> => ({
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: 'relinearization',
    keySwitchSeedHex: relinearizationKeySwitchSeed(
        kernel,
        evaluatorKeySchedule,
        round,
        level,
    ),
    ringDegree: 8,
    keySwitchComponentVectorRoot: shareRoot,
    keySwitchComponentVectors: [
        {
            component: 'b',
            digitIndex: level,
            vectorHash: hashFromKernel(kernel, `component-vector-${label}`),
        },
    ],
});

export const galoisShareMaterial = (
    kernel: TranscriptCoreKernel,
    evaluatorKeySchedule: Record<string, unknown>,
    shareRoot: string,
    label: string,
    rotation: number,
    level: number,
): Record<string, unknown> => ({
    keySwitchMaterialEncoding: 'embedded-full-key-switch-component-vectors',
    keySwitchDomain: `galois-${String(rotation)}`,
    keySwitchSeedHex: galoisKeySwitchSeed(
        kernel,
        evaluatorKeySchedule,
        rotation,
        level,
    ),
    ringDegree: 8,
    keySwitchComponentVectorRoot: shareRoot,
    keySwitchComponentVectors: [
        {
            component: 'b',
            digitIndex: 0,
            vectorHash: hashFromKernel(kernel, `galois-component-${label}`),
        },
    ],
});

type SetupIntentSignerFixture = Readonly<{
    readonly keyFixture: ReturnType<typeof createMlDsaKeyPairFixture>;
    readonly signRoot: (
        signedRoot: Parameters<
            typeof createProtocolSignatureFixture
        >[0]['signedRoot'],
    ) => ReturnType<typeof createProtocolSignatureFixture>;
}>;

export const setupIntentSigner = (
    seedLabel: string,
): SetupIntentSignerFixture => {
    const keyFixture = createMlDsaKeyPairFixture(seedLabel);

    return {
        keyFixture,
        signRoot: (
            signedRoot: Parameters<
                typeof createProtocolSignatureFixture
            >[0]['signedRoot'],
        ) =>
            createProtocolSignatureFixture({
                profile: createMlDsaSignatureProfileFixture(),
                publicKeyBytesHex: keyFixture.publicKeyBytesHex,
                publicKeyHash: keyFixture.publicKeyHash,
                secretKeyBytesHex: keyFixture.secretKeyBytesHex,
                signedRoot,
            }),
    };
};

export const phaseObject = (
    kernel: TranscriptCoreKernel,
    setupContext: SetupContextFixture,
    phaseNumber: number,
    phaseId = `phase-${String(phaseNumber)}`,
): Record<string, unknown> => ({
    objectType: 'SetupPhaseParticipantObject',
    objectVersion: 1,
    phaseId,
    phaseNumber,
    trusteeIdentity,
    rosterPosition: trusteeRosterPosition,
    recoveryEpoch: 0,
    deviceEpoch: 2,
    signingPublicKeyHash: hashFromKernel(
        kernel,
        `signing-key-${String(phaseNumber)}`,
    ),
    phaseObjectRoot: hashFromKernel(
        kernel,
        `phase-root-${String(phaseNumber)}`,
    ),
    phaseObjectByteLength: 100 + phaseNumber,
    phaseSignatureContextHash: hashFromKernel(
        kernel,
        `phase-context-${String(phaseNumber)}`,
    ),
    signatureEnvelopeHash: hashFromKernel(
        kernel,
        `phase-signature-${String(phaseNumber)}`,
    ),
    signatureEnvelope: {
        signatureHash: hashFromKernel(
            kernel,
            `signature-${String(phaseNumber)}`,
        ),
    },
    ceremonyId: setupContext.ceremonyId,
});

export const phaseTranscriptFixture = (
    kernel: TranscriptCoreKernel,
    setupContext: SetupContextFixture,
): readonly Record<string, unknown>[] => {
    const parameters = kernel.describeCollectiveBgvSetupParameters();
    let previousPhaseRoot: string | null = null;

    return (
        parameters.phaseOrder as readonly {
            readonly phaseId: string;
            readonly phaseNumber: number;
        }[]
    ).map((phase) => {
        const phaseRecord = publicSetupApi.createSetupPhaseRecord({
            setupContext,
            phaseId: phase.phaseId,
            phaseNumber: phase.phaseNumber,
            previousPhaseRoot,
            participantPhaseObjects: [
                phaseObject(
                    kernel,
                    setupContext,
                    phase.phaseNumber,
                    phase.phaseId,
                ),
            ],
        });
        previousPhaseRoot = String(phaseRecord.phaseRoot);

        return phaseRecord;
    });
};

export const localStateInput = (
    kernel: TranscriptCoreKernel,
    setupContext: SetupContextFixture,
): Record<string, unknown> => {
    const commonFields = contextFields(setupContext);
    const sourceTrusteeCommitmentRoot = hashFromKernel(
        kernel,
        'source-trustee-commitment',
    );
    const privateEnvelope = {
        objectType: 'PrivateVssShareEnvelope',
        objectVersion: 1,
        ...commonFields,
        sourceTrusteeIdentity: trusteeIdentity,
        sourceTrusteeRosterPosition: trusteeRosterPosition,
        recipientIdentity: trusteeIdentity,
        recipientRosterPosition: trusteeRosterPosition,
        sourceTrusteeCommitmentRoot,
        rnsShareOpenings: [
            {
                objectType: 'PrivateVssShareOpening',
                objectVersion: 1,
                rnsLimbIndex: 0,
                rnsPrime: 65_537,
                shareValues: [7, 11, 13, 17],
            },
        ],
    };
    const privateEnvelopeHash = kernel.deriveCanonicalObjectHash({
        value: privateEnvelope,
    });
    const privateVssEnvelopeCommitmentRoot = hashFromKernel(
        kernel,
        'private-vss-envelope-commitment-set',
    );

    return {
        setupContext,
        trusteeIdentity,
        trusteeRosterPosition,
        deviceEpoch: 2,
        thresholdShareCommitments: {
            objectType: 'ThresholdShareCommitmentSet',
            objectVersion: 1,
            ...commonFields,
            recipientRecords: [
                {
                    objectType: 'ThresholdShareCommitmentRecipient',
                    objectVersion: 1,
                    recipientIdentity: trusteeIdentity,
                    recipientRosterPosition: trusteeRosterPosition,
                    recipientCommitmentRoot: hashFromKernel(
                        kernel,
                        'threshold-recipient',
                    ),
                },
            ],
        },
        privateVssEnvelopeCommitments: {
            objectType: 'PrivateVssEnvelopeCommitmentSet',
            objectVersion: 1,
            ...commonFields,
            participantCount: 1,
            privateVssEnvelopeCommitmentRoot,
            envelopeReferences: [
                {
                    objectType: 'PrivateVssEnvelopeCommitment',
                    objectVersion: 1,
                    ...commonFields,
                    sourceTrusteeIdentity: trusteeIdentity,
                    sourceTrusteeRosterPosition: trusteeRosterPosition,
                    recipientIdentity: trusteeIdentity,
                    recipientRosterPosition: trusteeRosterPosition,
                    sourceTrusteeCommitmentRoot,
                    privateEnvelopeCommitmentRoot: hashFromKernel(
                        kernel,
                        'private-envelope-commitment',
                    ),
                    encryptedEnvelopeHash: hashFromKernel(
                        kernel,
                        'encrypted-envelope',
                    ),
                    privateEnvelopeHash,
                    localVerificationRoot: hashFromKernel(
                        kernel,
                        'local-verification',
                    ),
                },
            ],
        },
        verifiedPrivateVssShareEnvelopes: [privateEnvelope],
        vssShareAcceptances: {
            objectType: 'VssShareAcceptanceSet',
            objectVersion: 1,
            ...commonFields,
            acceptanceRecords: [
                {
                    objectType: 'VssShareAcceptance',
                    objectVersion: 1,
                    ...commonFields,
                    sourceTrusteeIdentity: trusteeIdentity,
                    sourceTrusteeRosterPosition: trusteeRosterPosition,
                    recipientIdentity: trusteeIdentity,
                    recipientRosterPosition: trusteeRosterPosition,
                    privateVssEnvelopeCommitmentRoot,
                    privateEnvelopeHash,
                    localVerificationRoot: hashFromKernel(
                        kernel,
                        'local-verification',
                    ),
                    acceptanceRoot: hashFromKernel(kernel, 'acceptance-root'),
                },
            ],
        },
        storageKeyBytesHex: '41'.repeat(32),
        localStateAeadNonceBytesHex: '51'.repeat(12),
        sealedAggregateThresholdShareAeadNonceBytesHex: '61'.repeat(12),
    };
};

export const privateVssEnvelopeReference = (
    kernel: TranscriptCoreKernel,
    setupContext: SetupContextFixture,
): Record<string, unknown> => ({
    objectType: 'PrivateVssEnvelopeCommitment',
    objectVersion: 1,
    ...contextFields(setupContext),
    sourceTrusteeIdentity: 'trustee-1',
    sourceTrusteeRosterPosition: 1,
    recipientIdentity: trusteeIdentity,
    recipientRosterPosition: trusteeRosterPosition,
    sourceTrusteeCommitmentRoot: hashFromKernel(
        kernel,
        'vss-source-trustee-commitment',
    ),
    privateEnvelopeCommitmentRoot: hashFromKernel(
        kernel,
        'vss-private-envelope-commitment',
    ),
    encryptedEnvelopeHash: hashFromKernel(kernel, 'vss-encrypted-envelope'),
    privateEnvelopeHash: hashFromKernel(kernel, 'vss-private-envelope'),
    localVerificationRoot: hashFromKernel(kernel, 'vss-local-verification'),
});
