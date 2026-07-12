import { loadTranscriptCoreKernel } from '@sealed-lattice/wasm';

import {
    createSetupPackageVerificationInput,
    verifyPrivateVssShare,
    verifySetupPackage,
} from '../../../dist/index.js';

import {
    hash512Hex,
    type EncryptedLocalTrusteeSetupState,
    type LocalTrusteeSetupStateSealedPayload,
} from '#packages/crypto/src/index';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import {
    acceptedBgvSetupQSharePrimes,
    createCommonRandomnessCommit,
    createCommonRandomnessReveal,
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares,
    createEvaluatorKeySchedule,
    createGaloisKeyShareBatches,
    createPublicEvaluationKeySet,
    createPublicKeyShareMaterialSet,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createPublicKeyShareSuccinctProofSet,
    createRelinearizationKeyShareRounds,
    createSetupCertificates,
    createSetupCommonRandomness,
    createSetupContributionAssembly,
    createVssCoefficientCommitmentBundle,
    createSetupPackage,
    createSetupPhaseParticipantObject,
    createSetupPhaseRecord,
    createVssShareAcceptanceRecord,
    createVssShareComplaintRecordFromLocalVerification,
    decryptLocalTrusteeSetupState,
    publicKeyShareCoefficientVectorHashDomain,
    setupTransportChunkSizeBytes,
    type CollectiveBgvSetupContext,
    type GeneratedLocalTrusteeSetupStateInput,
    type LocalTrusteeSetupStateCommitment,
    type PublicKeyShareSuccinctProofMaterial,
    type SetupCommonRandomnessInput,
    type SetupPhaseParticipantObjectInput,
    type VssCoefficientOpeningInput,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/index';
import type { TranscriptCoreKernel } from '#packages/wasm/src/index';

export { hash512Hex };
export { createVssCoefficientCommitmentBundle };

type JsonRecord = Record<string, unknown>;

const setupPhaseNumber = (
    phaseOrder: readonly {
        readonly phaseId: string;
        readonly phaseNumber: number;
    }[],
    phaseId: string,
): number => {
    const phase = phaseOrder.find(
        (candidatePhase) => candidatePhase.phaseId === phaseId,
    );
    if (phase === undefined) {
        throw new Error(`Accepted setup phase ${phaseId} is not available.`);
    }

    return phase.phaseNumber;
};

type SetupIntentInput = Omit<
    SetupPhaseParticipantObjectInput,
    'phaseId' | 'phaseNumber'
>;

const createSetupIntent = async (
    input: SetupIntentInput,
): Promise<Awaited<ReturnType<typeof createSetupPhaseParticipantObject>>> => {
    const kernel = await loadTranscriptCoreKernel();

    return createSetupPhaseParticipantObject({
        ...input,
        phaseId: 'setupIntent',
        phaseNumber: setupPhaseNumber(
            kernel.describeCollectiveBgvSetupParameters().phaseOrder,
            'setupIntent',
        ),
    });
};

type CommonRandomnessInput = Omit<
    SetupCommonRandomnessInput,
    'derivePublicDerivations' | 'participantCount'
>;

const createSetupCommonRandomnessForTest = async (
    input: CommonRandomnessInput,
): Promise<ReturnType<typeof createSetupCommonRandomness>> => {
    const kernel = await loadTranscriptCoreKernel();

    return createSetupCommonRandomness({
        ...input,
        participantCount:
            kernel.describeCollectiveBgvSetupParameters().participantCount,
        derivePublicDerivations: (publicMatrixSeedHash) =>
            kernel.deriveCollectiveBgvSetupPublicDerivations({
                publicMatrixSeedHash,
            }),
    });
};

type PrivateVssVerificationResult = Readonly<{
    readonly isValid: boolean;
    readonly privateEnvelopeHash: string | null;
    readonly localVerificationRoot: string | null;
    readonly refusedObjects: readonly Readonly<{
        readonly reasonCode: string;
        readonly message: string;
        readonly objectPath?: string;
    }>[];
}>;

type VssShareAcceptanceInput = Parameters<
    typeof createVssShareAcceptanceRecord
>[0] & {
    readonly localVerification: PrivateVssVerificationResult;
};

const createVssShareAcceptance = async (
    input: VssShareAcceptanceInput,
): Promise<Awaited<ReturnType<typeof createVssShareAcceptanceRecord>>> => {
    if (!input.localVerification.isValid) {
        throw new Error(
            'localVerification must be accepted before creating a VSS share acceptance.',
        );
    }
    if (
        input.localVerification.privateEnvelopeHash !==
        input.envelopeReference.privateEnvelopeHash
    ) {
        throw new Error(
            'localVerification.privateEnvelopeHash must match envelopeReference.privateEnvelopeHash.',
        );
    }
    if (
        input.localVerification.localVerificationRoot !==
        input.envelopeReference.localVerificationRoot
    ) {
        throw new Error(
            'localVerification.localVerificationRoot must match envelopeReference.localVerificationRoot.',
        );
    }

    return createVssShareAcceptanceRecord(input);
};

type VssComplaintInput = Omit<
    Parameters<typeof createVssShareComplaintRecordFromLocalVerification>[0],
    'localVerification'
> & {
    readonly localVerification: PrivateVssVerificationResult;
};

const createVssComplaint = async (
    input: VssComplaintInput,
): Promise<
    Awaited<
        ReturnType<typeof createVssShareComplaintRecordFromLocalVerification>
    >
> => {
    if (input.localVerification.isValid) {
        throw new Error(
            'localVerification must be refused before creating a VSS complaint.',
        );
    }
    if (input.localVerification.refusedObjects.length === 0) {
        throw new Error(
            'localVerification.refusedObjects must include the local verification failure.',
        );
    }

    return createVssShareComplaintRecordFromLocalVerification({
        ...input,
        localVerification: {
            isValid: false,
            privateEnvelopeHash: input.localVerification.privateEnvelopeHash,
            localVerificationRoot:
                input.localVerification.localVerificationRoot,
            refusedObjects: input.localVerification.refusedObjects,
        },
    });
};

type ExportedLocalTrusteeSetupState = Readonly<{
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly sealedLocalStatePayloadHash: string;
    readonly storageAadHash: string;
}>;

const exportEncryptedLocalTrusteeSetupState = async (
    input: GeneratedLocalTrusteeSetupStateInput,
): Promise<ExportedLocalTrusteeSetupState> => {
    const result =
        await createEncryptedLocalTrusteeSetupStateFromVerifiedShares(input);

    return {
        localStateCommitment: result.localStateCommitment,
        encryptedLocalState: result.encryptedLocalState,
        sealedLocalStatePayloadHash: result.localStatePlaintextHash,
        storageAadHash: result.storageAadHash,
    };
};

type RestoreLocalTrusteeSetupStateInput = Readonly<{
    readonly encryptedLocalState: EncryptedLocalTrusteeSetupState;
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly storageKeyBytesHex: string;
    readonly expectedTrusteeIdentity?: string;
    readonly expectedTrusteeRosterPosition?: number;
    readonly expectedDeviceEpoch?: number;
    readonly minimumDeviceEpoch?: number;
    readonly expectedThresholdShareCommitmentRecipientRoot?: string;
    readonly expectedAggregateThresholdShareRoot?: string;
    readonly expectedIssuedVssAcceptanceRoot?: string;
}>;

type RestoredLocalTrusteeSetupState = Readonly<{
    readonly localStateCommitment: LocalTrusteeSetupStateCommitment;
    readonly sealedLocalStatePayload: LocalTrusteeSetupStateSealedPayload;
    readonly sealedLocalStatePayloadHash: string;
    readonly storageAadHash: string;
    readonly localStateVerification: ReturnType<
        TranscriptCoreKernel['verifyLocalTrusteeSetupState']
    >;
}>;

const assertExpectedValue = <Value>(
    actual: Value,
    expected: Value | undefined,
    fieldName: string,
): void => {
    if (expected !== undefined && actual !== expected) {
        throw new Error(`${fieldName} does not match the expected value.`);
    }
};

const assertRestoredLocalStateBindings = (
    input: RestoreLocalTrusteeSetupStateInput,
    sealedLocalStatePayload: LocalTrusteeSetupStateSealedPayload,
): void => {
    for (const [fieldName, actualSetupEpoch] of [
        [
            'localStateCommitment.setupEpoch',
            input.localStateCommitment.setupEpoch,
        ],
        [
            'sealedLocalStatePayload.setupEpoch',
            sealedLocalStatePayload.setupEpoch,
        ],
    ] as const) {
        assertExpectedValue(
            actualSetupEpoch,
            input.setupContext.setupEpoch,
            fieldName,
        );
    }
    assertExpectedValue(
        input.localStateCommitment.trusteeIdentity,
        input.expectedTrusteeIdentity,
        'localStateCommitment.trusteeIdentity',
    );
    assertExpectedValue(
        sealedLocalStatePayload.trusteeIdentity,
        input.expectedTrusteeIdentity,
        'sealedLocalStatePayload.trusteeIdentity',
    );
    assertExpectedValue(
        input.localStateCommitment.trusteeRosterPosition,
        input.expectedTrusteeRosterPosition,
        'localStateCommitment.trusteeRosterPosition',
    );
    assertExpectedValue(
        sealedLocalStatePayload.trusteeRosterPosition,
        input.expectedTrusteeRosterPosition,
        'sealedLocalStatePayload.trusteeRosterPosition',
    );
    assertExpectedValue(
        sealedLocalStatePayload.deviceEpoch,
        input.expectedDeviceEpoch,
        'sealedLocalStatePayload.deviceEpoch',
    );
    if (
        input.minimumDeviceEpoch !== undefined &&
        sealedLocalStatePayload.deviceEpoch < input.minimumDeviceEpoch
    ) {
        throw new Error(
            'sealedLocalStatePayload.deviceEpoch is older than the minimum accepted device epoch.',
        );
    }
    assertExpectedValue(
        input.localStateCommitment.thresholdShareCommitmentRecipientRoot,
        input.expectedThresholdShareCommitmentRecipientRoot,
        'localStateCommitment.thresholdShareCommitmentRecipientRoot',
    );
    assertExpectedValue(
        sealedLocalStatePayload.thresholdShareCommitmentRecipientRoot,
        input.expectedThresholdShareCommitmentRecipientRoot,
        'sealedLocalStatePayload.thresholdShareCommitmentRecipientRoot',
    );
    assertExpectedValue(
        input.localStateCommitment.aggregateThresholdShareRoot,
        input.expectedAggregateThresholdShareRoot,
        'localStateCommitment.aggregateThresholdShareRoot',
    );
    assertExpectedValue(
        sealedLocalStatePayload.sealedAggregateThresholdShare.materialRoot,
        input.expectedAggregateThresholdShareRoot,
        'sealedLocalStatePayload.sealedAggregateThresholdShare.materialRoot',
    );
    assertExpectedValue(
        input.localStateCommitment.issuedVssAcceptanceRoot,
        input.expectedIssuedVssAcceptanceRoot,
        'localStateCommitment.issuedVssAcceptanceRoot',
    );
    if (sealedLocalStatePayload.issuedVssAcceptanceRoots.length !== 1) {
        throw new Error(
            'sealedLocalStatePayload.issuedVssAcceptanceRoots must contain exactly one issued acceptance root.',
        );
    }
    assertExpectedValue(
        sealedLocalStatePayload.issuedVssAcceptanceRoots[0],
        input.expectedIssuedVssAcceptanceRoot ??
            input.localStateCommitment.issuedVssAcceptanceRoot,
        'sealedLocalStatePayload.issuedVssAcceptanceRoots.0',
    );
    assertExpectedValue(
        sealedLocalStatePayload.sealedAggregateThresholdShare.materialRoot,
        input.localStateCommitment.aggregateThresholdShareRoot,
        'sealedLocalStatePayload.sealedAggregateThresholdShare.materialRoot',
    );
};

const restoreLocalTrusteeSetupState = async (
    input: RestoreLocalTrusteeSetupStateInput,
): Promise<RestoredLocalTrusteeSetupState> => {
    const expectedLocalStateRoot = input.localStateCommitment.localStateRoot;
    assertExpectedValue(
        input.encryptedLocalState.localStateRoot,
        expectedLocalStateRoot,
        'encryptedLocalState.localStateRoot',
    );
    const kernel = await loadTranscriptCoreKernel();
    const localStateVerification = kernel.verifyLocalTrusteeSetupState({
        setupContext: input.setupContext,
        localStateCommitment: input.localStateCommitment,
    });
    const decryptedState = await decryptLocalTrusteeSetupState({
        encryptedLocalState: input.encryptedLocalState,
        expectedLocalStateRoot,
        setupContext: input.setupContext,
        storageKeyBytesHex: input.storageKeyBytesHex,
    });
    const sealedLocalStatePayload = decryptedState.localStatePlaintext;
    assertRestoredLocalStateBindings(input, sealedLocalStatePayload);

    return {
        localStateCommitment: input.localStateCommitment,
        sealedLocalStatePayload,
        sealedLocalStatePayloadHash: decryptedState.localStatePlaintextHash,
        storageAadHash: decryptedState.storageAadHash,
        localStateVerification,
    };
};

const setupApiImplementation = {
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
    createSetupCertificates,
    createSetupCommonRandomness: createSetupCommonRandomnessForTest,
    createSetupContribution: createSetupContributionAssembly,
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
};

type TestSetupApi<Implementation> = {
    readonly [Name in keyof Implementation]: Implementation[Name] extends (
        ...arguments_: infer _Arguments
    ) => infer Result
        ? (input: JsonRecord) => Result
        : never;
};

// Inputs are deliberately loose because the tests construct malformed partial
// records. Return types still come directly from the actual builders.
export const publicSetupApi = setupApiImplementation as unknown as TestSetupApi<
    typeof setupApiImplementation
>;
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

export const trusteeReferencesFromPublicKeyShares = (
    publicKeyShares: Record<string, unknown>,
): readonly Record<string, unknown>[] =>
    (publicKeyShares.shareRecords as readonly Record<string, unknown>[]).map(
        (shareRecord) => ({
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
        }),
    );

export const publicKeyShareSuccinctProofMaterial = (
    kernel: TranscriptCoreKernel,
    proofRecord: Record<string, unknown>,
): PublicKeyShareSuccinctProofMaterial => {
    const proofTrusteeIdentity = proofRecord.trusteeIdentity;
    if (
        typeof proofTrusteeIdentity !== 'string' ||
        proofTrusteeIdentity.length === 0
    ) {
        throw new TypeError(
            'Public-key proof record trusteeIdentity must be non-empty.',
        );
    }
    const proofRosterPosition = proofRecord.trusteeRosterPosition;
    if (
        typeof proofRosterPosition !== 'number' ||
        !Number.isSafeInteger(proofRosterPosition) ||
        proofRosterPosition < 0
    ) {
        throw new TypeError(
            'Public-key proof record trusteeRosterPosition must be a non-negative safe integer.',
        );
    }
    const proofBytesHash = hashFromKernel(
        kernel,
        `public-key-succinct-proof-bytes-${String(proofRosterPosition)}`,
    );

    return {
        proofFamily: 'public-key-share',
        trusteeIdentity: proofTrusteeIdentity,
        trusteeRosterPosition: proofRosterPosition,
        statementHash: hashFromKernel(
            kernel,
            `public-key-succinct-statement-${String(proofRosterPosition)}`,
        ),
        proofBytesHash,
        proofBytesEncoding: 'binary-chunked-proof-bytes',
        proofMaterialRoot: kernel.deriveCanonicalObjectHash({
            value: {
                objectType: 'SetupProofMaterialReference',
                proofFamily: 'public-key-share',
                proofBytesHash,
            },
        }),
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
        ...commonFields,
        sourceTrusteeIdentity: trusteeIdentity,
        sourceTrusteeRosterPosition: trusteeRosterPosition,
        recipientIdentity: trusteeIdentity,
        recipientRosterPosition: trusteeRosterPosition,
        sourceTrusteeCommitmentRoot,
        rnsShareOpenings: [
            {
                objectType: 'PrivateVssShareOpening',
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
            ...commonFields,
            recipientRecords: [
                {
                    objectType: 'ThresholdShareCommitmentRecipient',
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
            ...commonFields,
            participantCount: 1,
            privateVssEnvelopeCommitmentRoot,
            envelopeReferences: [
                {
                    objectType: 'PrivateVssEnvelopeCommitment',
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
        localTrusteeAggregateOpeningCredentialHandoff: {
            objectType:
                'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff',
            trusteeIdentity,
            trusteeRosterPosition,
            aggregateOpeningCredentials: [
                {
                    objectType:
                        'LocalTrusteeVssPublicAggregateOpeningCredential',
                    recipientIdentity: trusteeIdentity,
                    recipientRosterPosition: trusteeRosterPosition,
                    recipientTrusteePoint: trusteeRosterPosition + 1,
                    rnsLimbIndex: 0,
                    rnsPrime: 65_537,
                    aggregateCommitmentRoot: hashFromKernel(
                        kernel,
                        'aggregate-commitment-root',
                    ),
                    aggregateOpeningRoot: hashFromKernel(
                        kernel,
                        'aggregate-opening-root',
                    ),
                    aggregateCommitmentMessageValuesLeHex: bytesToHex(
                        coefficientVectorBytes([7, 11, 13, 17]),
                    ),
                    aggregateMaterialSeedHex: hashFromKernel(
                        kernel,
                        'aggregate-material-seed',
                    ),
                },
            ],
        },
        vssShareAcceptances: {
            objectType: 'VssShareAcceptanceSet',
            ...commonFields,
            acceptanceRecords: [
                {
                    objectType: 'VssShareAcceptance',
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
