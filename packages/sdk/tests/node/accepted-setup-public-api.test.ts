import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';
import { loadTranscriptCoreKernel } from '../../dist/kernel.js';

import { hash512Hex } from '#packages/crypto/src/index';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import {
    createSameSecretConsistencyStatementSet,
    createVssCoefficientCommitmentBundle,
    publicKeyShareCoefficientVectorHashDomain,
    publicKeyShareSuccinctProofModelStatus,
    publicKeyShareSuccinctProofVerificationStatus,
    sameSecretAnchorProofModelStatus,
    sameSecretAnchorProofVerificationStatus,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/index';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';

type PublicSetupApi = {
    readonly createCommonRandomnessCommit: (
        input: unknown,
    ) => Record<string, unknown>;
    readonly createCommonRandomnessReveal: (
        input: unknown,
    ) => Record<string, unknown>;
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

const publicSetupApi = publicApiRuntime as unknown as PublicSetupApi;
const loadPublicTranscriptCoreKernel: () => Promise<TranscriptCoreKernel> =
    loadTranscriptCoreKernel;
const trusteeIdentity = 'trustee-0';
const trusteeRosterPosition = 0;

type SetupContextFixture = Readonly<{
    readonly ceremonyId: string;
    readonly manifestHash: string;
    readonly rosterHash: string;
    readonly setupProfileHash: string;
    readonly qShareHash: string;
    readonly carryAwareVssShareRelationProfileHash: string;
    readonly commitmentProfileHash: string;
    readonly setupEpoch: string;
}>;

const hashFromKernel = (kernel: TranscriptCoreKernel, label: string): string =>
    kernel.deriveProtocolHash({
        namespace: 'ActionContextHash',
        value: {
            fixture: 'accepted-setup-public-api',
            label,
        },
    });

const setupContextFromKernel = (
    kernel: TranscriptCoreKernel,
): SetupContextFixture => {
    const profile = kernel.describeCollectiveBgvSetupProfile();

    return {
        ceremonyId: 'ceremony-public-setup-api',
        manifestHash: hashFromKernel(kernel, 'manifest'),
        rosterHash: hashFromKernel(kernel, 'roster'),
        setupProfileHash: profile.setupProfileHash,
        qShareHash: profile.qShareHash,
        carryAwareVssShareRelationProfileHash:
            profile.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: profile.commitmentProfileHash,
        setupEpoch: 'setup-epoch-1',
    } as const;
};

const contextFields = (
    setupContext: SetupContextFixture,
): SetupContextFixture => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const protocolHashFromKernel = (
    kernel: TranscriptCoreKernel,
    namespace: string,
    value: Record<string, unknown>,
): string =>
    kernel.deriveProtocolHash({
        namespace,
        value,
    });

const qSharePrimes = [
    65_537, 65_539, 65_543, 65_551, 65_557, 65_563, 65_579, 65_581, 65_587,
    65_599, 65_609, 65_617, 65_629, 65_633, 65_647, 65_651, 65_657,
] as const;
const participantCount = 2;
const vssFixtureRingDegree = 8;
const vssFixtureThresholdDegree = 2;
const setupTransportChunkSizeBytes = 1_048_576;
const setupProofProfileId = 'SealedLattice-LNP-SetupProof-v1';
const requiredGaloisKeySchedule = [
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

const publicKeyShareMaterialContribution = (
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

const vssSourceTrusteeOpeningState = (
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

const sameSecretProofMaterial = (
    kernel: TranscriptCoreKernel,
    statementRecord: Record<string, unknown>,
): Record<string, unknown> => {
    const proofRosterPosition = Number(statementRecord.trusteeRosterPosition);
    const proofBytesHex = `aa55${proofRosterPosition.toString(16).padStart(4, '0')}`;

    return {
        setupProofProfileId,
        proofFamily: 'same-secret-linkage-anchor',
        proofVerificationStatus: sameSecretAnchorProofVerificationStatus,
        proofModelStatus: sameSecretAnchorProofModelStatus,
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

const sameSecretProofReferencesFromSet = (
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

const publicKeyShareSuccinctProofMaterial = (
    kernel: TranscriptCoreKernel,
    proofRecord: Record<string, unknown>,
): Record<string, unknown> => {
    const proofRosterPosition = Number(proofRecord.trusteeRosterPosition);
    const proofBytesHex = `bb66${proofRosterPosition.toString(16).padStart(4, '0')}`;

    return {
        setupProofProfileId,
        proofFamily: 'public-key-share',
        proofVerificationStatus: publicKeyShareSuccinctProofVerificationStatus,
        proofModelStatus: publicKeyShareSuccinctProofModelStatus,
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
    protocolHashFromKernel(kernel, 'RelinearizationKeyShareSeed', {
        objectType: 'RelinearizationKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
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
    protocolHashFromKernel(kernel, 'GaloisKeyShareSeed', {
        objectType: 'GaloisKeySwitchPublicSampleSeed',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: 'galois-key-share',
        keySwitchSampleScope: 'shared-by-scheduled-rotation-and-level',
        evaluatorKeyScheduleRoot: evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        galoisKeyCrpRoot: evaluatorKeySchedule.galoisKeyCrpRoot,
        requiredGaloisSetHash: evaluatorKeySchedule.requiredGaloisSetHash,
        rotation,
        level,
    });

const relinearizationShareMaterial = (
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

const galoisShareMaterial = (
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

const setupIntentSigner = (seedLabel: string): SetupIntentSignerFixture => {
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

const phaseObject = (
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

const phaseTranscriptFixture = (
    kernel: TranscriptCoreKernel,
    setupContext: SetupContextFixture,
): readonly Record<string, unknown>[] => {
    const profile = kernel.describeCollectiveBgvSetupProfile();
    let previousPhaseRoot: string | null = null;

    return (
        profile.phaseOrder as readonly {
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

const localStateInput = (
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
    const privateEnvelopeHash = kernel.deriveProtocolHash({
        namespace: 'PrivateVssShareEnvelopeHash',
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

const privateVssEnvelopeReference = (
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

describe('accepted setup public package API in Node', () => {
    it('creates signed setup intent objects and deterministic setup phase records', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const { keyFixture, signRoot } = setupIntentSigner(
            'accepted-setup-public-api-intent',
        );
        const mailboxPublicKeyHash = hashFromKernel(kernel, 'mailbox-key');
        const mailboxPublicKeyBytesHash = hashFromKernel(
            kernel,
            'mailbox-key-bytes',
        );

        const setupIntent = await publicSetupApi.createSetupIntent({
            setupContext,
            trusteeIdentity,
            rosterPosition: trusteeRosterPosition,
            recoveryEpoch: 0,
            deviceEpoch: 2,
            signingPublicKeyHash: keyFixture.publicKeyHash,
            privateVssMailboxPublicKeyHash: mailboxPublicKeyHash,
            privateVssMailboxPublicKeyBytesHash: mailboxPublicKeyBytesHash,
            signRoot,
        });
        const setupIntentPhase = publicSetupApi.createSetupPhaseRecord({
            setupContext,
            phaseId: 'setupIntent',
            phaseNumber: 2,
            previousPhaseRoot: null,
            participantPhaseObjects: [setupIntent],
        });

        expect(setupIntent).toMatchObject({
            objectType: 'SetupPhaseParticipantObject',
            phaseId: 'setupIntent',
            phaseNumber: 2,
            trusteeIdentity,
            rosterPosition: trusteeRosterPosition,
            privateVssMailboxPublicKeyHash: mailboxPublicKeyHash,
            privateVssMailboxPublicKeyBytesHash: mailboxPublicKeyBytesHash,
            signingPublicKeyHash: keyFixture.publicKeyHash,
        });
        expect(String(setupIntent.phaseObjectRoot)).toHaveLength(128);
        expect(String(setupIntent.signatureEnvelopeHash)).toBe(
            String(
                (setupIntent.signatureEnvelope as Record<string, unknown>)
                    .signatureHash,
            ),
        );
        expect(setupIntentPhase).toMatchObject({
            phaseId: 'setupIntent',
            phaseNumber: 2,
            previousPhaseRoot: null,
            participantPhaseObjects: [setupIntent],
        });
        expect(String(setupIntentPhase.phaseRoot)).toHaveLength(128);
    });

    it('assembles full-roster common randomness and refuses stale commit bindings', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const revealRecords: Record<string, unknown>[] = [];
        const commitRecords: Record<string, unknown>[] = [];
        for (let rosterPosition = 0; rosterPosition < 10; rosterPosition += 1) {
            const recordTrusteeIdentity = `trustee-${String(rosterPosition)}`;
            const signatureEnvelopeHash = hashFromKernel(
                kernel,
                `common-randomness-signature-${String(rosterPosition)}`,
            );
            const revealRecord = publicSetupApi.createCommonRandomnessReveal({
                setupContext,
                trusteeIdentity: recordTrusteeIdentity,
                rosterPosition,
                recoveryEpoch: 0,
                deviceEpoch: 2,
                signatureEnvelopeHash,
                revealHex: hashFromKernel(
                    kernel,
                    `common-randomness-reveal-${String(rosterPosition)}`,
                ).slice(0, 64),
            });
            revealRecords.push(revealRecord);
            commitRecords.push(
                publicSetupApi.createCommonRandomnessCommit({
                    setupContext,
                    trusteeIdentity: recordTrusteeIdentity,
                    rosterPosition,
                    recoveryEpoch: 0,
                    deviceEpoch: 2,
                    signatureEnvelopeHash,
                    revealHash: revealRecord.revealHash,
                }),
            );
        }

        const commonRandomness =
            await publicSetupApi.createSetupCommonRandomness({
                setupContext,
                commitRecords: [...commitRecords].reverse(),
                revealRecords: [...revealRecords].reverse(),
            });

        expect(commonRandomness).toMatchObject({
            objectType: 'SetupCommonRandomness',
            setupProfileHash: setupContext.setupProfileHash,
            publicDerivations: {
                objectType: 'SetupPublicDerivations',
                publicMatrixSeedHash: String(
                    commonRandomness.publicMatrixSeedHash,
                ),
            },
        });
        expect(commonRandomness.commitRecords).toEqual(
            expect.arrayContaining([commitRecords[0]]),
        );
        expect(commonRandomness.revealRecords).toEqual(
            expect.arrayContaining([revealRecords[0]]),
        );
        expect(
            (commonRandomness.commitRecords as Record<string, unknown>[]).map(
                (commitRecord) => commitRecord.rosterPosition,
            ),
        ).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        expect(String(commonRandomness.commonRandomnessRoot)).toHaveLength(128);
        expect(JSON.stringify(commonRandomness)).not.toMatch(
            /setupSeed|shareValues|coefficientMessage|randomnessByColumn/u,
        );

        const staleCommit = publicSetupApi.createCommonRandomnessCommit({
            setupContext,
            trusteeIdentity,
            rosterPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 2,
            signatureEnvelopeHash: hashFromKernel(kernel, 'stale-signature'),
            revealHash: revealRecords[1]?.revealHash,
        });

        await expect(
            publicSetupApi.createSetupCommonRandomness({
                setupContext,
                commitRecords: [staleCommit, ...commitRecords.slice(1)],
                revealRecords,
            }),
        ).rejects.toThrow(/must match the reveal record/u);
        await expect(
            publicSetupApi.createSetupCommonRandomness({
                setupContext,
                commitRecords: commitRecords.slice(1),
                revealRecords: revealRecords.slice(1),
            }),
        ).rejects.toThrow(/one record per participant/u);
    });

    it('verifies private VSS shares and signs acceptance or complaint from local verification', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const envelopeReference = privateVssEnvelopeReference(
            kernel,
            setupContext,
        );
        const { keyFixture, signRoot } = setupIntentSigner(
            'accepted-setup-public-api-vss-recipient',
        );

        const malformedVerification =
            await publicSetupApi.verifyPrivateVssShare({
                setupContext,
                publicMatrixSeedHash: hashFromKernel(
                    kernel,
                    'vss-public-matrix-seed',
                ),
                sourceTrusteeCoefficientCommitmentRecord: {
                    objectType: 'VssSourceTrusteeCoefficientCommitments',
                },
                sourceTrusteeCoefficientCommitmentMaterialRecords: [],
                privateEnvelope: {
                    objectType: 'PrivateVssShareEnvelope',
                    objectVersion: 1,
                },
            });
        expect(malformedVerification).toMatchObject({
            ok: false,
            operation: 'verifyPrivateVssShareEnvelope',
            verifierStatus: 'refused',
        });
        expect(JSON.stringify(malformedVerification)).not.toMatch(
            /shareValues|coefficientMessage|randomnessByColumn/u,
        );

        const acceptedLocalVerification = {
            ok: true,
            operation: 'verifyPrivateVssShareEnvelope',
            setupProfileId: 'CollectiveBgvSetup-v1',
            verifierStatus: 'accepted',
            privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
            localVerificationRoot: envelopeReference.localVerificationRoot,
            limbVerifications: [],
            refusedObjects: [],
        };
        const refusedLocalVerification = {
            ok: false,
            operation: 'verifyPrivateVssShareEnvelope',
            setupProfileId: 'CollectiveBgvSetup-v1',
            verifierStatus: 'refused',
            privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
            localVerificationRoot: null,
            limbVerifications: [],
            refusedObjects: [
                {
                    reasonCode: 'private-vss-opening-verification-failed',
                    message:
                        'recipient local private VSS opening verification failed',
                    objectPath: 'privateEnvelope.rnsShareOpenings.0',
                },
            ],
        };

        const acceptance = await publicSetupApi.createVssShareAcceptance({
            setupContext,
            privateVssEnvelopeCommitmentRoot:
                envelopeReference.privateEnvelopeCommitmentRoot,
            envelopeReference,
            localVerification: acceptedLocalVerification,
            recoveryEpoch: 0,
            deviceEpoch: 2,
            signingPublicKeyHash: keyFixture.publicKeyHash,
            signRoot,
        });
        expect(acceptance).toMatchObject({
            objectType: 'VssShareAcceptance',
            sourceTrusteeIdentity: 'trustee-1',
            recipientIdentity: trusteeIdentity,
            privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
            localVerificationRoot: envelopeReference.localVerificationRoot,
            verificationStatus: 'accepted',
        });
        expect(String(acceptance.acceptanceRoot)).toHaveLength(128);
        expect(JSON.stringify(acceptance)).not.toMatch(
            /shareValues|coefficientMessage|randomnessByColumn/u,
        );

        await expect(
            publicSetupApi.createVssShareAcceptance({
                setupContext,
                privateVssEnvelopeCommitmentRoot:
                    envelopeReference.privateEnvelopeCommitmentRoot,
                envelopeReference,
                localVerification: refusedLocalVerification,
                recoveryEpoch: 0,
                deviceEpoch: 2,
                signingPublicKeyHash: keyFixture.publicKeyHash,
                signRoot,
            }),
        ).rejects.toThrow(/must be accepted/u);
        await expect(
            publicSetupApi.createVssShareAcceptance({
                setupContext,
                privateVssEnvelopeCommitmentRoot:
                    envelopeReference.privateEnvelopeCommitmentRoot,
                envelopeReference,
                localVerification: {
                    ...acceptedLocalVerification,
                    localVerificationRoot: hashFromKernel(
                        kernel,
                        'stale-local-verification',
                    ),
                },
                recoveryEpoch: 0,
                deviceEpoch: 2,
                signingPublicKeyHash: keyFixture.publicKeyHash,
                signRoot,
            }),
        ).rejects.toThrow(/localVerificationRoot/u);

        const complaint = await publicSetupApi.createVssComplaint({
            setupContext,
            privateVssEnvelopeCommitmentRoot:
                envelopeReference.privateEnvelopeCommitmentRoot,
            envelopeReference,
            localVerification: refusedLocalVerification,
            recoveryEpoch: 0,
            deviceEpoch: 2,
            signingPublicKeyHash: keyFixture.publicKeyHash,
            signRoot,
        });
        expect(complaint).toMatchObject({
            objectType: 'VssShareComplaint',
            sourceTrusteeIdentity: 'trustee-1',
            recipientIdentity: trusteeIdentity,
            privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
            complaintReasonCode: 'private-vss-opening-verification-failed',
            complaintStatus: 'valid-complaint-aborts-setup',
        });
        expect(String(complaint.complaintRoot)).toHaveLength(128);
        expect(JSON.stringify(complaint)).not.toMatch(
            /shareValues|coefficientMessage|randomnessByColumn/u,
        );
        await expect(
            publicSetupApi.createVssComplaint({
                setupContext,
                privateVssEnvelopeCommitmentRoot:
                    envelopeReference.privateEnvelopeCommitmentRoot,
                envelopeReference,
                localVerification: acceptedLocalVerification,
                recoveryEpoch: 0,
                deviceEpoch: 2,
                signingPublicKeyHash: keyFixture.publicKeyHash,
                signRoot,
            }),
        ).rejects.toThrow(/must be refused/u);
    });

    it('creates a roots-only setup contribution and refuses raw fields in the public record', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const commonFields = contextFields(setupContext);
        const sourceTrusteeRecord = {
            objectType: 'VssSourceTrusteeCoefficientCommitments',
            objectVersion: 1,
            ...commonFields,
            sourceTrusteeIdentity: trusteeIdentity,
            sourceTrusteeRosterPosition: trusteeRosterPosition,
            publicMatrixSeedHash: hashFromKernel(kernel, 'public-matrix-seed'),
            coefficientCommitments: [],
            sourceTrusteeCommitmentRoot: hashFromKernel(
                kernel,
                'source-trustee-root',
            ),
        };

        const setupContribution = publicSetupApi.createSetupContribution({
            setupContext,
            trusteeIdentity,
            trusteeRosterPosition,
            setupPhaseParticipantObjects: [
                phaseObject(kernel, setupContext, 2),
                phaseObject(kernel, setupContext, 1),
            ],
            commonRandomnessCommitRoot: hashFromKernel(
                kernel,
                'common-randomness-commit',
            ),
            commonRandomnessRevealRoot: hashFromKernel(
                kernel,
                'common-randomness-reveal',
            ),
            vssSourceTrusteeRecord: sourceTrusteeRecord,
        });

        expect(setupContribution).toMatchObject({
            objectType: 'SetupContributionAssembly',
            setupProfileId: 'CollectiveBgvSetup-v1',
            trusteeIdentity,
            trusteeRosterPosition,
            vssSourceTrusteeCommitmentRoot:
                sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
            phaseObjectRoots: [
                hashFromKernel(kernel, 'phase-root-1'),
                hashFromKernel(kernel, 'phase-root-2'),
            ],
        });
        expect(String(setupContribution.setupContributionRoot)).toHaveLength(
            128,
        );
        expect(JSON.stringify(setupContribution)).not.toMatch(
            /shareValues|coefficientMessage|randomnessByColumn/u,
        );
    });

    it('assembles public key and evaluation-key records from proof material only', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupProfile = kernel.describeCollectiveBgvSetupProfile();
        const bgvProfile = kernel.describeBgvRnsProfile();
        const setupContext = setupContextFromKernel(kernel);
        const publicMatrixSeedHash = hashFromKernel(
            kernel,
            'key-record-public-matrix-seed',
        );
        const publicDerivations =
            kernel.deriveCollectiveBgvSetupPublicDerivations({
                publicMatrixSeedHash,
            });
        const publicKeyCrpRoot = publicDerivations.crpRoots.publicKeyCrpRoot;
        const publicAPolynomialRoot =
            publicDerivations.bgvPublicA.publicPolynomialRoot;
        const relinearizationCrpRoot =
            publicDerivations.crpRoots.relinearizationCrpRoot;
        const galoisKeyCrpRoot = publicDerivations.crpRoots.galoisKeyCrpRoot;
        const vssCoefficientCommitmentBundle =
            createVssCoefficientCommitmentBundle({
                setupContext: setupContext,
                publicMatrixSeedHash,
                qSharePrimes,
                ringDegree: vssFixtureRingDegree,
                participantCount,
                thresholdDegree: vssFixtureThresholdDegree,
                sourceTrusteeOpeningStates: Array.from(
                    { length: participantCount },
                    (_unused, sourceTrusteeRosterPosition) =>
                        vssSourceTrusteeOpeningState(
                            sourceTrusteeRosterPosition,
                        ),
                ),
            });
        const vssCoefficientCommitments =
            vssCoefficientCommitmentBundle.commitmentSet;
        const vssCoefficientCommitmentMaterial =
            vssCoefficientCommitmentBundle.materialSet;
        const sameSecretConsistency = createSameSecretConsistencyStatementSet({
            setupContext: setupContext,
            qSharePrimes,
            participantCount,
            thresholdDegree: vssFixtureThresholdDegree,
            vssCoefficientCommitments,
        });
        const publicKeyShareMaterialContributions = Array.from(
            { length: participantCount },
            (_unused, shareRosterPosition) =>
                publicKeyShareMaterialContribution(shareRosterPosition),
        );
        const shareContributions = publicKeyShareMaterialContributions.map(
            (materialContribution) => ({
                trusteeIdentity: materialContribution.trusteeIdentity,
                trusteeRosterPosition:
                    materialContribution.trusteeRosterPosition,
                shareCoefficientVectorHash512ByLimb: (
                    materialContribution.shareCoefficientVectorsByLimb as readonly Record<
                        string,
                        unknown
                    >[]
                ).map((coefficientVector) => ({
                    rnsLimbIndex: coefficientVector.rnsLimbIndex,
                    rnsPrime: coefficientVector.rnsPrime,
                    component: coefficientVector.component,
                    coefficientVectorHash512:
                        coefficientVector.coefficientVectorHash512,
                })),
            }),
        );

        const publicKeyShares = publicSetupApi.createPublicKeyShareSet({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash,
            publicKeyCrpRoot,
            publicAPolynomialRoot,
            sameSecretConsistency,
            shareContributions,
        });
        const publicKeyShareProofs =
            publicSetupApi.createPublicKeyShareProofSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash,
                publicKeyCrpRoot,
                publicAPolynomialRoot,
                sameSecretConsistency,
                publicKeyShares,
            });
        const sameSecretLinkageAnchorProofAccountingHash = hashFromKernel(
            kernel,
            'same-secret-linkage-anchor-proof-accounting',
        );
        const sameSecretProofs = publicSetupApi.createSameSecretProofSet({
            setupContext,
            qSharePrimes,
            participantCount,
            sameSecretConsistency,
            vssCoefficientCommitmentMaterial,
            proofAccountingHash: sameSecretLinkageAnchorProofAccountingHash,
            proofMaterials: (
                sameSecretConsistency.statementRecords as readonly Record<
                    string,
                    unknown
                >[]
            ).map((statementRecord) =>
                sameSecretProofMaterial(kernel, statementRecord),
            ),
        });
        const publicKeyShareMaterial =
            publicSetupApi.createPublicKeyShareMaterialSet({
                setupContext,
                qSharePrimes,
                participantCount,
                ringDegree: vssFixtureRingDegree,
                publicMatrixSeedHash,
                publicKeyCrpRoot,
                publicAPolynomialRoot,
                publicKeyShares,
                materialContributions: publicKeyShareMaterialContributions,
            });
        const publicKeyShareProofAccountingHash = hashFromKernel(
            kernel,
            'public-key-share-proof-accounting',
        );
        const publicKeyShareSuccinctProofs =
            publicSetupApi.createPublicKeyShareSuccinctProofSet({
                setupContext,
                qSharePrimes,
                participantCount,
                publicMatrixSeedHash,
                publicKeyCrpRoot,
                publicAPolynomialRoot,
                sameSecretConsistency,
                sameSecretProofs,
                publicKeyShares,
                publicKeyShareProofs,
                publicKeyShareMaterial,
                proofAccountingHash: publicKeyShareProofAccountingHash,
                proofMaterials: (
                    publicKeyShareProofs.proofRecords as readonly Record<
                        string,
                        unknown
                    >[]
                ).map((proofRecord) =>
                    publicKeyShareSuccinctProofMaterial(kernel, proofRecord),
                ),
            });
        const evaluatorKeySchedule = publicSetupApi.createEvaluatorKeySchedule({
            setupContext,
            qSharePrimes,
            participantCount,
            publicMatrixSeedHash,
            relinearizationCrpRoot,
            galoisKeyCrpRoot,
            sameSecretConsistency,
            publicKeyShares,
            publicKeyShareProofs,
            requiredGaloisKeySchedule,
        });
        const relinearizationLevelSchedule =
            evaluatorKeySchedule.relinearizationLevelSchedule as readonly {
                readonly level: number;
            }[];
        const sameSecretProofReferences =
            sameSecretProofReferencesFromSet(sameSecretProofs);
        const commonEvaluationKeyInput = {
            setupContext,
            qSharePrimes,
            participantCount,
            evaluatorKeySchedule,
            sameSecretProofSetRoot: sameSecretProofs.sameSecretProofSetRoot,
            sameSecretProofFamilyBindingRoot:
                sameSecretConsistency.sameSecretProofFamilyBindingRoot,
            publicKeyShareSuccinctProofSetRoot:
                publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot,
            sameSecretProofReferences,
        };
        const relinearizationLevels = relinearizationLevelSchedule.map(
            (scheduleEntry) => scheduleEntry.level,
        );
        const roundOneContributions = sameSecretProofReferences.flatMap(
            (reference) =>
                relinearizationLevels.map((level) => {
                    const contributionLabel = `${String(reference.trusteeRosterPosition)}-${String(level)}`;
                    const roundOneShareRoot = hashFromKernel(
                        kernel,
                        `round-one-share-${contributionLabel}`,
                    );

                    return {
                        trusteeRosterPosition: reference.trusteeRosterPosition,
                        level,
                        roundOneShareRoot,
                        shareMaterial: relinearizationShareMaterial(
                            kernel,
                            evaluatorKeySchedule,
                            roundOneShareRoot,
                            `round-one-${contributionLabel}`,
                            'round-one',
                            level,
                        ),
                    };
                }),
        );
        const roundTwoContributions = sameSecretProofReferences.flatMap(
            (reference) =>
                relinearizationLevels.map((level) => {
                    const contributionLabel = `${String(reference.trusteeRosterPosition)}-${String(level)}`;
                    const roundTwoShareRoot = hashFromKernel(
                        kernel,
                        `round-two-share-${contributionLabel}`,
                    );

                    return {
                        trusteeRosterPosition: reference.trusteeRosterPosition,
                        level,
                        roundTwoShareRoot,
                        shareMaterial: relinearizationShareMaterial(
                            kernel,
                            evaluatorKeySchedule,
                            roundTwoShareRoot,
                            `round-two-${contributionLabel}`,
                            'round-two',
                            level,
                        ),
                    };
                }),
        );
        const relinearizationKeyShareRounds =
            publicSetupApi.createRelinearizationKeyShareRounds({
                ...commonEvaluationKeyInput,
                roundOneContributions,
                roundTwoContributions,
            });
        const galoisKeyShareBatches =
            publicSetupApi.createGaloisKeyShareBatches({
                ...commonEvaluationKeyInput,
                batchContributions: sameSecretProofReferences.map(
                    (reference) => ({
                        trusteeRosterPosition: reference.trusteeRosterPosition,
                        galoisKeyShares: requiredGaloisKeySchedule.map(
                            (scheduleEntry) => {
                                const galoisKeyShareRoot = hashFromKernel(
                                    kernel,
                                    `galois-share-${String(reference.trusteeRosterPosition)}-${String(scheduleEntry.rotation)}`,
                                );

                                return {
                                    rotation: scheduleEntry.rotation,
                                    level: scheduleEntry.level,
                                    galoisKeyShareRoot,
                                    shareMaterial: galoisShareMaterial(
                                        kernel,
                                        evaluatorKeySchedule,
                                        galoisKeyShareRoot,
                                        `${String(reference.trusteeRosterPosition)}-${String(scheduleEntry.rotation)}`,
                                        scheduleEntry.rotation,
                                        scheduleEntry.level,
                                    ),
                                };
                            },
                        ),
                    }),
                ),
            });
        const publicEvaluationKeys =
            publicSetupApi.createPublicEvaluationKeySet({
                ...commonEvaluationKeyInput,
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
            });
        const trusteeEvaluationKeyProofsWithoutRoot = {
            objectType: 'TrusteeEvaluationKeyProofSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            relinearizationKeyShareRoundsRoot:
                relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot,
            proofRecords: [],
        };
        const trusteeEvaluationKeyProofs = {
            ...trusteeEvaluationKeyProofsWithoutRoot,
            trusteeEvaluationKeyProofSetRoot: kernel.deriveProtocolHash({
                namespace: 'TrusteeEvaluationKeyProofSetRoot',
                value: trusteeEvaluationKeyProofsWithoutRoot,
            }),
        };
        const privateVssEnvelopeCommitmentRoot = hashFromKernel(
            kernel,
            'package-private-vss-envelope-root',
        );
        const setupTransportChunkCount = Math.ceil(
            Number(
                setupProfile.publicVssCommitmentMaterialSizeProfile
                    .fullMaterialCoefficientBytes,
            ) / setupTransportChunkSizeBytes,
        );
        const setupTransport = {
            fullObjectHash: hashFromKernel(
                kernel,
                'setup-transport-full-object',
            ),
            chunkHashes: Array.from(
                { length: setupTransportChunkCount },
                (_unused, chunkIndex) =>
                    hashFromKernel(
                        kernel,
                        `setup-transport-chunk-${String(chunkIndex)}`,
                    ),
            ),
        };
        const setupCertificates = publicSetupApi.createSetupCertificates({
            setupProfile,
            bgvProfile,
            vssCoefficientCommitmentMaterial,
            transport: setupTransport,
            sameSecretLinkageAnchorProofAccounting: {
                objectType: 'SuccinctSameSecretLinkageAnchorAccounting',
                objectVersion: 1,
                fixture: 'sdk-same-secret-linkage-anchor-accounting',
            },
            publicKeyShareProofAccounting: {
                objectType: 'SuccinctPublicKeyShareAccounting',
                objectVersion: 1,
                fixture: 'sdk-public-key-share-accounting',
            },
            trusteeEvaluationKeyProofAccounting: {
                objectType: 'SuccinctEvaluationKeyProofAccounting',
                objectVersion: 1,
                fixture: 'sdk-trustee-evaluation-key-accounting',
            },
        });
        const setupCommitmentSecurityCertificate =
            setupCertificates.setupCommitmentSecurityCertificate as Record<
                string,
                unknown
            >;
        const setupTransportCertificate =
            setupCertificates.setupTransportCertificate as Record<
                string,
                unknown
            >;
        const heSecurityCertificate =
            setupCertificates.heSecurityCertificate as Record<string, unknown>;
        const commonRandomnessWithoutRoot = {
            objectType: 'SetupCommonRandomness',
            objectVersion: 1,
            ceremonyId: setupContext.ceremonyId,
            manifestHash: setupContext.manifestHash,
            rosterHash: setupContext.rosterHash,
            setupProfileHash: setupContext.setupProfileHash,
            setupEpoch: setupContext.setupEpoch,
            publicMatrixSeedHash,
            publicDerivations,
            commitRecords: [],
            revealRecords: [],
        } as const;
        const setupPackageInput = {
            setupContext,
            qShare: setupProfile.qShare,
            phaseTranscript: phaseTranscriptFixture(kernel, setupContext),
            commonRandomness: {
                ...commonRandomnessWithoutRoot,
                commonRandomnessRoot: kernel.deriveProtocolHash({
                    namespace: 'SetupCommonRandomnessRoot',
                    value: commonRandomnessWithoutRoot,
                }),
            },
            vssCoefficientCommitments,
            vssCoefficientCommitmentMaterial,
            privateVssEnvelopeCommitments: {
                objectType: 'PrivateVssEnvelopeCommitmentSet',
                objectVersion: 1,
                ...contextFields(setupContext),
                privateVssEnvelopeCommitmentRoot,
                envelopeReferences: [
                    {
                        objectType: 'PrivateVssEnvelopeCommitment',
                        objectVersion: 1,
                        ...contextFields(setupContext),
                        sourceTrusteeIdentity: 'trustee-0',
                        sourceTrusteeRosterPosition: 0,
                        recipientIdentity: 'trustee-1',
                        recipientRosterPosition: 1,
                        privateEnvelopeCommitmentRoot: hashFromKernel(
                            kernel,
                            'package-private-envelope-commitment',
                        ),
                        encryptedEnvelopeHash: hashFromKernel(
                            kernel,
                            'package-encrypted-envelope',
                        ),
                        privateEnvelopeHash: hashFromKernel(
                            kernel,
                            'package-private-envelope',
                        ),
                        localVerificationRoot: hashFromKernel(
                            kernel,
                            'package-local-verification',
                        ),
                        encryptedEnvelope: {
                            objectType: 'EncryptedPrivateVssShareEnvelope',
                            ciphertextBytesHex: '00',
                        },
                        transportedPrivateVssShareProofMaterial: {
                            objectType:
                                'SetupTransportedPrivateVssShareProofMaterialSet',
                        },
                    },
                ],
            },
            vssShareAcceptances: {
                objectType: 'VssShareAcceptanceSet',
                objectVersion: 1,
                ...contextFields(setupContext),
                privateVssEnvelopeCommitmentRoot,
                acceptanceRecords: [],
                vssShareAcceptanceRoot: hashFromKernel(
                    kernel,
                    'package-acceptance-root',
                ),
            },
            sameSecretConsistency,
            sameSecretProofs,
            publicKeyShares,
            publicKeyShareProofs,
            publicKeyShareMaterial,
            publicKeyShareSuccinctProofs,
            evaluatorKeySchedule,
            relinearizationKeyShareRounds,
            galoisKeyShareBatches,
            trusteeEvaluationKeyProofs,
            evaluationKeys: publicEvaluationKeys,
            setupCertificateInput: {
                setupProfile,
                bgvProfile,
                transport: setupTransport,
            },
        };
        const setupPackage =
            publicSetupApi.createSetupPackage(setupPackageInput);
        const { setupPackageHash, ...setupPackageHashInput } = setupPackage;

        expect(publicKeyShares).toMatchObject({
            objectType: 'PublicKeyShareSet',
            publicMatrixSeedHash,
        });
        expect(relinearizationKeyShareRounds.objectType).toBe(
            'RelinearizationKeyShareRounds',
        );
        expect(
            Array.isArray(relinearizationKeyShareRounds.roundOneRecords),
        ).toBe(true);
        expect(
            Array.isArray(relinearizationKeyShareRounds.roundTwoRecords),
        ).toBe(true);
        expect(galoisKeyShareBatches).toHaveLength(participantCount);
        expect(publicEvaluationKeys).toMatchObject({
            objectType: 'PublicEvaluationKeySet',
            rawKeyBytesEmbedded: false,
            verifierGeneratedKeyMaterial: false,
            relinearizationKeyShareRoundsRoot:
                relinearizationKeyShareRounds.relinearizationKeyShareRoundsRoot,
        });
        expect(setupPackage).toMatchObject({
            objectType: 'SetupPackage',
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupContext,
            collectivePublicKey: {
                objectType: 'CollectivePublicKey',
                publicKeyShareMaterialSetRoot:
                    publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
                publicKeyShareSuccinctProofSetRoot:
                    publicKeyShareSuccinctProofs.publicKeyShareSuccinctProofSetRoot,
            },
            privateVssEnvelopeCommitmentRoot,
            evaluationKeys: publicEvaluationKeys,
            setupCommitmentSecurityCertificate,
            setupTransportCertificate,
            heSecurityCertificate,
        });
        expect(setupPackage.collectivePublicKeyRoot).toBe(
            (setupPackage.collectivePublicKey as Record<string, unknown>)
                .collectivePublicKeyRoot,
        );
        expect(setupPackage.setupTransportCertificate).toMatchObject({
            chunkSizeBytes: setupTransportChunkSizeBytes,
            chunkCount: setupTransportChunkCount,
            chunkHashes: setupTransport.chunkHashes,
        });
        expect(setupPackage.setupCommitmentSecurityCertificateHash).toBe(
            setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash,
        );
        expect(
            (setupPackage.thresholdShareCommitments as Record<string, unknown>)
                .thresholdShareCommitmentRoot,
        ).toMatch(/^[0-9a-f]{128}$/u);
        expect(setupPackageHash).toBe(
            kernel.deriveProtocolHash({
                namespace: 'SetupPackageHash',
                value: setupPackageHashInput,
            }),
        );
        expect(JSON.stringify(setupPackage)).not.toContain(
            '"encryptedEnvelope":',
        );
        expect(JSON.stringify(setupPackage)).not.toContain(
            '"transportedPrivateVssShareProofMaterial":',
        );
        expect(
            JSON.stringify({
                relinearizationKeyShareRounds,
                galoisKeyShareBatches,
                publicEvaluationKeys,
                setupPackage,
            }),
        ).not.toMatch(
            /secretCoefficients|openingRandomness|roundOneAggregateSourceCoefficients|proofGeneration/u,
        );
        expect(() =>
            publicSetupApi.createSetupPackage({
                ...setupPackageInput,
                thresholdShareCommitments: {
                    ...(setupPackage.thresholdShareCommitments as Record<
                        string,
                        unknown
                    >),
                    thresholdShareCommitmentRoot: hashFromKernel(
                        kernel,
                        'stale-threshold-share-commitment',
                    ),
                },
            }),
        ).toThrow(/verifier-derived commitments/u);
        expect(() =>
            publicSetupApi.createSetupPackage({
                ...setupPackageInput,
                evaluationKeys: {
                    ...publicEvaluationKeys,
                    proofGeneration: {
                        secretCoefficients: [1],
                    },
                },
            }),
        ).toThrow(/forbidden raw setup fields/u);
        for (const requiredPublicKeyClosureField of [
            'sameSecretProofs',
            'publicKeyShareMaterial',
            'publicKeyShareSuccinctProofs',
        ]) {
            const incompleteSetupPackageInput = {
                ...setupPackageInput,
            };
            delete incompleteSetupPackageInput[
                requiredPublicKeyClosureField as keyof typeof incompleteSetupPackageInput
            ];

            expect(() =>
                publicSetupApi.createSetupPackage(incompleteSetupPackageInput),
            ).toThrow(
                new RegExp(
                    `${requiredPublicKeyClosureField} must be an object`,
                    'u',
                ),
            );
        }
    });

    it('exports encrypted local trustee state and restores only a sealed payload', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const exportedState =
            await publicSetupApi.exportEncryptedLocalTrusteeSetupState(
                localStateInput(kernel, setupContext),
            );

        expect(exportedState).not.toHaveProperty('localStatePlaintext');
        expect(exportedState).not.toHaveProperty('localStatePlaintextHash');
        expect(exportedState.sealedLocalStatePayloadHash).toMatch(
            /^[0-9a-f]{128}$/u,
        );
        expect(JSON.stringify(exportedState.localStateCommitment)).not.toMatch(
            /shareValues|privateEnvelope|coefficientMessage/u,
        );
        expect(exportedState.encryptedLocalState).toMatchObject({
            objectType: 'EncryptedLocalTrusteeSetupState',
            localStateRoot: (
                exportedState.localStateCommitment as Record<string, unknown>
            ).localStateRoot,
        });

        const restoredState =
            await publicSetupApi.restoreLocalTrusteeSetupState({
                encryptedLocalState: exportedState.encryptedLocalState,
                localStateCommitment: exportedState.localStateCommitment,
                setupContext,
                storageKeyBytesHex: '41'.repeat(32),
                expectedTrusteeIdentity: trusteeIdentity,
                expectedTrusteeRosterPosition: trusteeRosterPosition,
                expectedDeviceEpoch: 2,
                minimumDeviceEpoch: 2,
                expectedAggregateThresholdShareRoot: (
                    exportedState.localStateCommitment as Record<
                        string,
                        unknown
                    >
                ).aggregateThresholdShareRoot,
                expectedThresholdShareCommitmentRecipientRoot: (
                    exportedState.localStateCommitment as Record<
                        string,
                        unknown
                    >
                ).thresholdShareCommitmentRecipientRoot,
                expectedIssuedVssAcceptanceRoot: (
                    exportedState.localStateCommitment as Record<
                        string,
                        unknown
                    >
                ).issuedVssAcceptanceRoot,
            });

        expect(restoredState).toMatchObject({
            ok: true,
            operation: 'restoreLocalTrusteeSetupState',
            setupProfileId: 'CollectiveBgvSetup-v1',
            localStateVerification: {
                ok: true,
                operation: 'verifyLocalTrusteeSetupState',
                localStateRoot: (
                    exportedState.localStateCommitment as Record<
                        string,
                        unknown
                    >
                ).localStateRoot,
            },
        });
        expect(restoredState).not.toHaveProperty('localStatePlaintext');
        expect(restoredState).not.toHaveProperty('localStatePlaintextHash');
        expect(restoredState.sealedLocalStatePayloadHash).toBe(
            exportedState.sealedLocalStatePayloadHash,
        );
        expect(
            JSON.stringify(restoredState.sealedLocalStatePayload),
        ).not.toMatch(/shareValues|rawShare|coefficientMessage/u);
    });

    it('rejects incomplete export input and stale restored device state', async () => {
        const kernel = await loadPublicTranscriptCoreKernel();
        const setupContext = setupContextFromKernel(kernel);
        const exportInput = localStateInput(kernel, setupContext);

        await expect(
            publicSetupApi.exportEncryptedLocalTrusteeSetupState({
                ...exportInput,
                verifiedPrivateVssShareEnvelopes: [],
            }),
        ).rejects.toThrow(/must include the private envelope/u);

        const exportedState =
            await publicSetupApi.exportEncryptedLocalTrusteeSetupState(
                exportInput,
            );

        await expect(
            publicSetupApi.restoreLocalTrusteeSetupState({
                encryptedLocalState: exportedState.encryptedLocalState,
                localStateCommitment: exportedState.localStateCommitment,
                setupContext,
                storageKeyBytesHex: '41'.repeat(32),
                expectedTrusteeIdentity: trusteeIdentity,
                expectedTrusteeRosterPosition: trusteeRosterPosition,
                minimumDeviceEpoch: 3,
            }),
        ).rejects.toThrow(/older than the minimum accepted device epoch/u);
    });

    it('exposes setup package verification without accepting legacy setup objects', async () => {
        const transportHash = hash512Hex(
            'sealed-lattice/test/setup-verification-vss-transport',
            [new Uint8Array([1, 2, 3, 4])],
        );
        const chunkHash = hash512Hex(
            'sealed-lattice/test/setup-verification-vss-chunk',
            [new Uint8Array([1, 2, 3, 4])],
        );
        const vssMaterialReference = {
            objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            binaryFormat:
                'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
            chunkSizeBytes: 1_048_576,
            chunkCount: 1,
            totalByteLength: 4,
            fullObjectHash: transportHash,
            chunkHashes: [chunkHash],
            chunkRoot: chunkHash,
        };
        const transportedVssCoefficientCommitmentMaterial = {
            ...vssMaterialReference,
            chunks: [
                {
                    chunkIndex: 0,
                    bytesHex: '01020304',
                },
            ],
        };
        const verifiedVssCoefficientCommitmentMaterial = {
            objectType: 'VerifiedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            verificationId: 'sdk-public-verification-input-test',
            materialBinaryFormat:
                'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
            publicMatrixSeedHash: transportHash,
            vssCoefficientCommitmentRoot: transportHash,
            vssCoefficientCommitmentMaterialRoot: transportHash,
            thresholdShareCommitmentRoot: transportHash,
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
            transportChunkSizeBytes: 1_048_576,
            transportChunkCount: 1,
            transportTotalByteLength: 4,
            transportFullObjectHash: transportHash,
            transportChunkRoot: chunkHash,
        };
        const setupPackage = {
            objectType: 'SetupPackage',
            objectVersion: 1,
            setupPackageHash: transportHash,
        };

        const verificationInput =
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                transportedVssCoefficientCommitmentMaterial,
                verifiedVssCoefficientCommitmentMaterial,
            });

        expect(verificationInput.setupPackage).toBe(setupPackage);
        expect(verificationInput.verifiedVssCoefficientCommitmentMaterial).toBe(
            verifiedVssCoefficientCommitmentMaterial,
        );
        expect(
            verificationInput.transportedVssCoefficientCommitmentMaterial,
        ).toEqual(vssMaterialReference);
        expect(
            verificationInput.transportedVssCoefficientCommitmentMaterial,
        ).not.toHaveProperty('chunks');

        const verification = await publicSetupApi.verifySetupPackage({
            setupPackage: {
                objectType: 'BgvPassiveSetupPackage',
                objectVersion: 1,
            },
        });

        expect(verification).toMatchObject({
            ok: false,
            operation: 'verifyCollectiveBgvSetupPackage',
            verifierStatus: 'outsideProfile',
        });
        expect(verification.acceptedSetupHandoff).toBeUndefined();
    });
});
