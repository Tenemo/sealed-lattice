import { describe, expect, it } from 'vitest';

import {
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares,
    restoreAndPrepareLocalTargetDecryptionShareWitness,
} from '#packages/protocol/src/index';
import {
    assembleVssPublicAggregateThresholdCommitmentSet,
    createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle,
    createVssPublicCoefficientCommitmentSet,
    createVssPublicRecipientShareCommitmentSet,
} from '#packages/protocol/src/setup/vss-commitments';
import {
    loadTranscriptCoreKernel,
    stageBgvTargetDecryptionAggregateOpeningMaterials,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';
import { createVssCommitmentComputers } from '#tests/support/vss-commitment-computer';

type JsonRecord = Record<string, unknown>;

type SetupLifecycleArtifacts = Readonly<{
    aggregateMaterialSeedHex: string;
    canonicalTargetBasisHash: string;
    localStateInput: Parameters<
        typeof createEncryptedLocalTrusteeSetupStateFromVerifiedShares
    >[0];
    ringDegree: number;
    setupPackage: JsonRecord;
}>;

type TargetAcceptedRecord = Readonly<{
    objectType: 'TargetAcceptedRecord';
    boardPosition: number;
    boardSequence: number;
    ceremonyId: string;
    electionManifestHash: string;
    evaluatorReplayRecordHash: string;
    organizerIdentity: string;
    targetBasisHash: string;
    targetCiphertextHash: string;
    targetContextHash: string;
    targetDecryptionParametersHash: string;
    targetFinalityCheckpointHash: string;
    targetFinalityRecordHash: string;
    targetLayoutHash: string;
    targetPreimageHash: string;
    targetProposalHash: string;
    targetAcceptedRecordHash: string;
}>;

type TargetShareProfile = Readonly<{
    objectType: 'TargetDecryptionShareProfile';
    targetDecryptionProfileHash: string;
    targetDecryptionProfileBindingHash: string;
    decryptionThreshold: number;
    minimumSharesForInterpolation: number;
    decryptionShareQuorum: number;
    targetShareProfileHash: string;
}>;

type TargetArtifacts = Readonly<{
    targetAcceptedRecord: TargetAcceptedRecord;
    targetCiphertextBinding: Readonly<{
        aggregateCiphertextRoot: string;
        topCount: number;
        targetLayoutHash: string;
    }>;
    targetCiphertexts: Readonly<{
        targetIdCanonicalBytesHex: string;
        targetOrderCanonicalBytesHex: string;
    }>;
    targetDecryptionCiphertextHash: string;
    targetShareProfile: TargetShareProfile;
}>;

type LifecycleArtifacts = Readonly<{
    kernel: TranscriptCoreKernel;
    setup: SetupLifecycleArtifacts;
    target: TargetArtifacts;
}>;

type LifecycleArtifactsPromise = Promise<LifecycleArtifacts>;

const participantCount = 3;
const localTrusteeRosterPosition = 0;
const localTrusteeIdentity = 'trustee-0';
const setupEpoch = 'setup-epoch-1';

const hash = (kernel: TranscriptCoreKernel, label: string): string =>
    kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'LocalTargetShareLifecycleFixtureHash',
            label,
        },
    });

const sourceCoefficientMessage = (
    sourceTrusteeRosterPosition: number,
    shamirCoefficientIndex: number,
    ringDegree: number,
): number[] =>
    Array.from(
        { length: ringDegree },
        (_unusedCoefficient, coefficientPosition) =>
            (sourceTrusteeRosterPosition * 11 +
                shamirCoefficientIndex * 7 +
                (coefficientPosition % 13) +
                1) %
            97,
    );

const addResidueVectors = (
    left: readonly number[],
    right: readonly number[],
    modulus: number,
): number[] =>
    left.map((leftValue, coefficientPosition) => {
        const rightValue = right[coefficientPosition];
        if (rightValue === undefined) {
            throw new Error('Fixture residue vectors must have equal length.');
        }

        return (leftValue + rightValue) % modulus;
    });

const decodeHex = (hexValue: string): Uint8Array => {
    if (hexValue.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(hexValue)) {
        throw new Error(
            'Canonical test bytes must use lowercase even-length hex.',
        );
    }

    return Uint8Array.from(
        { length: hexValue.length / 2 },
        (_unusedByte, byteIndex) =>
            Number.parseInt(
                hexValue.slice(byteIndex * 2, byteIndex * 2 + 2),
                16,
            ),
    );
};

const encodeHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const encodeCanonicalVaruint = (value: number): Uint8Array => {
    const encodedBytes: number[] = [];
    let remainingValue = value;
    do {
        let nextByte = remainingValue % 128;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            nextByte |= 0x80;
        }
        encodedBytes.push(nextByte);
    } while (remainingValue !== 0);

    return Uint8Array.from(encodedBytes);
};

const canonicalStringBytes = (value: string): Uint8Array => {
    const valueBytes = new TextEncoder().encode(value);

    return Uint8Array.from([
        ...encodeCanonicalVaruint(valueBytes.length),
        ...valueBytes,
    ]);
};

const readCanonicalVaruint = (
    bytes: Uint8Array,
    cursor: { offset: number },
): number => {
    let value = 0;
    let multiplier = 1;
    while (cursor.offset < bytes.length) {
        const byte = bytes[cursor.offset];
        if (byte === undefined) {
            break;
        }
        cursor.offset += 1;
        value += (byte & 0x7f) * multiplier;
        if ((byte & 0x80) === 0) {
            return value;
        }
        multiplier *= 128;
        if (!Number.isSafeInteger(value) || !Number.isSafeInteger(multiplier)) {
            throw new Error(
                'Canonical test varuint exceeds the safe integer range.',
            );
        }
    }

    throw new Error('Canonical test varuint is truncated.');
};

const readCanonicalString = (
    bytes: Uint8Array,
    cursor: { offset: number },
): string => {
    const byteLength = readCanonicalVaruint(bytes, cursor);
    const endOffset = cursor.offset + byteLength;
    if (endOffset > bytes.length) {
        throw new Error('Canonical test string is truncated.');
    }
    const value = new TextDecoder('utf-8', { fatal: true }).decode(
        bytes.subarray(cursor.offset, endOffset),
    );
    cursor.offset = endOffset;

    return value;
};

const canonicalPlaintextComponentBytes = (
    canonicalBytesHex: string,
): Uint8Array => {
    const bytes = decodeHex(canonicalBytesHex);
    const cursor = { offset: 0 };
    const magic = readCanonicalString(bytes, cursor);
    const version = readCanonicalVaruint(bytes, cursor);
    const objectKind = readCanonicalString(bytes, cursor);
    const componentCount = readCanonicalVaruint(bytes, cursor);
    if (
        magic !== 'sealed-lattice-bgv-rns-canonical-object' ||
        version !== 1 ||
        objectKind !== 'plaintext' ||
        componentCount !== 1
    ) {
        throw new Error('Expected one canonical BGV plaintext component.');
    }

    return bytes.slice(cursor.offset);
};

const validatedTargetCiphertext = (
    kernel: TranscriptCoreKernel,
    leftSlots: readonly number[],
    rightSlots: readonly number[],
): Readonly<{ canonicalBytesHex: string; ciphertextRoot: string }> => {
    const left = kernel.encodeBgvBatchPlaintext({
        slots: leftSlots,
        level: 0,
        includeCanonicalBytesHex: true,
    });
    const right = kernel.encodeBgvBatchPlaintext({
        slots: rightSlots,
        level: 0,
        includeCanonicalBytesHex: true,
    });
    if (
        !('canonicalBytesHex' in left) ||
        typeof left.canonicalBytesHex !== 'string' ||
        !('canonicalBytesHex' in right) ||
        typeof right.canonicalBytesHex !== 'string'
    ) {
        throw new Error('Target test plaintexts must include canonical bytes.');
    }
    const canonicalBytes = Uint8Array.from([
        ...canonicalStringBytes('sealed-lattice-bgv-rns-canonical-object'),
        ...encodeCanonicalVaruint(1),
        ...canonicalStringBytes('ciphertext'),
        ...encodeCanonicalVaruint(2),
        ...canonicalPlaintextComponentBytes(left.canonicalBytesHex),
        ...canonicalPlaintextComponentBytes(right.canonicalBytesHex),
    ]);
    const canonicalBytesHex = encodeHex(canonicalBytes);
    const validation = kernel.validateBgvCiphertextObject({
        canonicalBytesHex,
    });
    if (
        !('ciphertextRoot' in validation) ||
        typeof validation.ciphertextRoot !== 'string' ||
        validation.isValid !== true
    ) {
        throw new Error(
            'Target test ciphertext must pass canonical validation.',
        );
    }

    return { canonicalBytesHex, ciphertextRoot: validation.ciphertextRoot };
};

const setupLifecycleArtifacts = async (
    kernel: TranscriptCoreKernel,
): Promise<SetupLifecycleArtifacts> => {
    const setupParameters = kernel.describeCollectiveBgvSetupParameters({
        participantCount,
    });
    const bgvParameters = kernel.describeBgvRnsParameters();
    const ringDegree = bgvParameters.parameters.polynomialDegree;
    const firstRnsPrime = setupParameters.qShare.primes[0];
    if (firstRnsPrime === undefined) {
        throw new Error('Setup parameters must contain a first Q_share prime.');
    }
    const setupContext = {
        ceremonyId: 'local-target-share-lifecycle-ceremony',
        manifestHash: hash(kernel, 'manifest'),
        rosterHash: hash(kernel, 'roster'),
        setupParametersHash: setupParameters.setupParametersHash,
        setupEpoch,
        participantCount,
        qSetupComplete: setupParameters.qSetupComplete,
        qBallotRelease: setupParameters.qBallotRelease,
        qFinal: setupParameters.qFinal,
        qDec: setupParameters.qDec,
    } as const;
    const publicMatrixSeedHash = hash(kernel, 'public-matrix-seed');
    const thresholdDegree = setupParameters.qDec;
    const sourceTrusteeOpeningStates = Array.from(
        { length: participantCount },
        (_unusedSource, sourceTrusteeRosterPosition) => ({
            sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
            sourceTrusteeRosterPosition,
            coefficientOpenings: Array.from(
                { length: thresholdDegree },
                (_unusedCoefficient, shamirCoefficientIndex) => ({
                    rnsLimbIndex: 0,
                    rnsPrime: firstRnsPrime,
                    shamirCoefficientIndex,
                    coefficientMessage: sourceCoefficientMessage(
                        sourceTrusteeRosterPosition,
                        shamirCoefficientIndex,
                        ringDegree,
                    ),
                }),
            ),
        }),
    );
    const committedMaterialSeed = (
        coordinate: Record<string, unknown>,
    ): string =>
        kernel.deriveCanonicalObjectHash({
            value: {
                objectType: 'LocalTargetShareLifecycleMaterialSeed',
                ...coordinate,
            },
        });
    const { vssCommittedMaterialCommitmentComputer } =
        createVssCommitmentComputers(kernel);
    const coefficientBundle = createVssPublicCoefficientCommitmentSet({
        setupContext,
        publicMatrixSeedHash,
        participantCount,
        qSharePrimes: [firstRnsPrime],
        ringDegree,
        thresholdDegree,
        sourceTrusteeOpeningStates,
        committedMaterialSeed,
        computeVssCommittedMaterialCommitment:
            vssCommittedMaterialCommitmentComputer,
    });
    const recipientBundle = createVssPublicRecipientShareCommitmentSet({
        setupContext,
        publicMatrixSeedHash,
        participantCount,
        qSharePrimes: [firstRnsPrime],
        ringDegree,
        thresholdDegree,
        sourceTrusteeOpeningStates,
        committedMaterialSeed,
        computeVssCommittedMaterialCommitment:
            vssCommittedMaterialCommitmentComputer,
    });
    const aggregateBundles: Awaited<
        ReturnType<
            typeof createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle
        >
    >[] = [];
    for (
        let recipientRosterPosition = 0;
        recipientRosterPosition < participantCount;
        recipientRosterPosition += 1
    ) {
        aggregateBundles.push(
            await createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle(
                {
                    setupContext,
                    publicMatrixSeedHash,
                    participantCount,
                    qSharePrimes: [firstRnsPrime],
                    ringDegree,
                    coefficientCommitmentSet:
                        coefficientBundle.coefficientCommitmentSet,
                    recipientShareCommitmentSet:
                        recipientBundle.recipientShareCommitmentSet,
                    localTrusteeRosterPosition: recipientRosterPosition,
                    localRecipientShareCredentials:
                        recipientBundle.recipientShareCredentials.filter(
                            (credential) =>
                                credential.recipientRosterPosition ===
                                recipientRosterPosition,
                        ),
                    committedMaterialSeed,
                    computeVssCommittedMaterialCommitment:
                        vssCommittedMaterialCommitmentComputer,
                    aggregateThresholdProofRandomness: ({ rnsLimbIndex }) => ({
                        seedHex: hash(
                            kernel,
                            `aggregate-proof-seed-${String(recipientRosterPosition)}-${String(rnsLimbIndex)}`,
                        ),
                        nonceHex: hash(
                            kernel,
                            `aggregate-proof-nonce-${String(recipientRosterPosition)}-${String(rnsLimbIndex)}`,
                        ),
                    }),
                    generateVssShareLinkageProof: (proofInput) => {
                        const proofBytesHash = hash(
                            kernel,
                            `aggregate-proof-${proofInput.context.shareLinkageStatementRoot}`,
                        );

                        return Promise.resolve({
                            proofBytesEncoding: 'binary-chunked-proof-bytes',
                            proofBytesHash,
                            proofMaterialRoot: kernel.deriveCanonicalObjectHash(
                                {
                                    value: {
                                        objectType:
                                            'SetupProofMaterialReference',
                                        proofFamily: 'vss-share-linkage',
                                        proofBytesHash,
                                    },
                                },
                            ),
                            canonicalMaterial: {
                                descriptorBytes:
                                    canonicalStreamDescriptorFixture(
                                        4,
                                        0x53,
                                        0x4c,
                                    ),
                            },
                        });
                    },
                },
            ),
        );
    }
    const aggregateThresholdCommitmentSet =
        assembleVssPublicAggregateThresholdCommitmentSet({
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes: [firstRnsPrime],
            ringDegree,
            recipientShareCommitmentSet:
                recipientBundle.recipientShareCommitmentSet,
            publicAggregateThresholdCommitmentContributions:
                aggregateBundles.map(
                    (bundle) =>
                        bundle.publicAggregateThresholdCommitmentContribution,
                ),
        });
    const localAggregateBundle = aggregateBundles[localTrusteeRosterPosition];
    if (localAggregateBundle === undefined) {
        throw new Error('Fixture must contain the local aggregate bundle.');
    }
    const privateVssEnvelopeCommitmentRoot = hash(
        kernel,
        'private-envelope-commitment-set',
    );
    const localShareValuesBySource = sourceTrusteeOpeningStates.map(
        (sourceOpeningState) => {
            const constantMessage =
                sourceOpeningState.coefficientOpenings[0]?.coefficientMessage;
            const linearMessage =
                sourceOpeningState.coefficientOpenings[1]?.coefficientMessage;
            if (constantMessage === undefined || linearMessage === undefined) {
                throw new Error(
                    'Fixture requires a degree-one Shamir polynomial.',
                );
            }

            return addResidueVectors(
                constantMessage,
                linearMessage,
                firstRnsPrime,
            );
        },
    );
    const privateEnvelopes = localShareValuesBySource.map(
        (shareValues, sourceTrusteeRosterPosition) => {
            const sourceTrusteeIdentity = `trustee-${String(sourceTrusteeRosterPosition)}`;

            return {
                objectType: 'PrivateVssShareEnvelope',
                ...setupContext,
                sourceTrusteeIdentity,
                sourceTrusteeRosterPosition,
                recipientIdentity: localTrusteeIdentity,
                recipientRosterPosition: localTrusteeRosterPosition,
                sourceTrusteeCommitmentRoot: hash(
                    kernel,
                    `source-commitment-${String(sourceTrusteeRosterPosition)}`,
                ),
                rnsShareOpenings: [
                    {
                        objectType: 'PrivateVssShareOpening',
                        rnsLimbIndex: 0,
                        rnsPrime: firstRnsPrime,
                        shareValues,
                    },
                ],
            };
        },
    );
    const envelopeReferences = privateEnvelopes.map(
        (privateEnvelope, sourceTrusteeRosterPosition) => ({
            ...setupContext,
            sourceTrusteeIdentity: privateEnvelope.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition,
            recipientIdentity: localTrusteeIdentity,
            recipientRosterPosition: localTrusteeRosterPosition,
            sourceTrusteeCommitmentRoot:
                privateEnvelope.sourceTrusteeCommitmentRoot,
            privateEnvelopeHash: kernel.deriveCanonicalObjectHash({
                value: privateEnvelope,
            }),
            localVerificationRoot: hash(
                kernel,
                `local-verification-${String(sourceTrusteeRosterPosition)}`,
            ),
        }),
    );
    const thresholdShareCommitmentRecipientRoot = hash(
        kernel,
        'threshold-share-recipient',
    );
    const setupPackage: JsonRecord = {
        objectType: 'SetupPackage',
        setupContext,
        phaseTranscript: [
            {
                phaseId: 'setupIntent',
                participantPhaseObjects: Array.from(
                    { length: participantCount },
                    (_unusedParticipant, rosterPosition) => ({
                        trusteeIdentity: `trustee-${String(rosterPosition)}`,
                        rosterPosition,
                        signingPublicKeyHash: hash(
                            kernel,
                            `signing-key-${String(rosterPosition)}`,
                        ),
                    }),
                ),
            },
        ],
        commonRandomness: { publicMatrixSeedHash },
        vssShareLinkageStatement: {
            statementRoot: hash(kernel, 'share-linkage-statement'),
        },
        vssPublicAggregateThresholdCommitmentSet:
            aggregateThresholdCommitmentSet,
    };
    const aggregateOpeningCredential =
        localAggregateBundle.localTrusteeAggregateOpeningCredentialHandoff
            .aggregateOpeningCredentials[0];
    if (aggregateOpeningCredential === undefined) {
        throw new Error(
            'Fixture must contain a local aggregate opening credential.',
        );
    }

    return {
        aggregateMaterialSeedHex:
            aggregateOpeningCredential.aggregateMaterialSeedHex,
        canonicalTargetBasisHash: setupParameters.canonicalTargetBasisHash,
        localStateInput: {
            setupContext,
            trusteeIdentity: localTrusteeIdentity,
            trusteeRosterPosition: localTrusteeRosterPosition,
            deviceEpoch: 0,
            thresholdShareCommitments: {
                objectType: 'ThresholdShareCommitmentSet',
                ...setupContext,
                recipientRecords: [
                    {
                        recipientIdentity: localTrusteeIdentity,
                        recipientRosterPosition: localTrusteeRosterPosition,
                        recipientCommitmentRoot:
                            thresholdShareCommitmentRecipientRoot,
                    },
                ],
            },
            privateVssEnvelopeCommitments: {
                objectType: 'PrivateVssEnvelopeCommitmentSet',
                ...setupContext,
                participantCount,
                privateVssEnvelopeCommitmentRoot,
                envelopeReferences,
            },
            verifiedPrivateVssShareEnvelopes: privateEnvelopes,
            localTrusteeAggregateOpeningCredentialHandoff:
                localAggregateBundle.localTrusteeAggregateOpeningCredentialHandoff,
            vssShareAcceptances: {
                objectType: 'VssShareAcceptanceSet',
                ...setupContext,
                acceptanceRecords: envelopeReferences.map(
                    (reference, sourceTrusteeRosterPosition) => ({
                        ...setupContext,
                        sourceTrusteeIdentity: reference.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition,
                        recipientIdentity: localTrusteeIdentity,
                        recipientRosterPosition: localTrusteeRosterPosition,
                        privateVssEnvelopeCommitmentRoot,
                        acceptanceRoot: hash(
                            kernel,
                            `acceptance-${String(sourceTrusteeRosterPosition)}`,
                        ),
                    }),
                ),
            },
            storageKeyBytesHex: '41'.repeat(32),
            localStateAeadNonceBytesHex: '51'.repeat(12),
            sealedAggregateThresholdShareAeadNonceBytesHex: '61'.repeat(12),
        },
        ringDegree,
        setupPackage,
    } as const;
};

const targetArtifacts = (
    kernel: TranscriptCoreKernel,
    setupPackage: JsonRecord,
    ringDegree: number,
    targetBasisHash: string,
): TargetArtifacts => {
    const targetId = validatedTargetCiphertext(kernel, [1, 0, 3], [0, 1, 0]);
    const targetOrder = validatedTargetCiphertext(kernel, [1, 0, 2], [0, 1, 0]);
    const targetLayoutHash = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'DirectEncryptedBallotTargetLayout',
            layoutId: 'direct-encrypted-target-projection',
            optionCount: 20,
            targetIdSlotRule: '(option + 1) * [rank < topCount]',
            targetOrderSlotRule: '(rank + 1) * [rank < topCount]',
            slotCount: ringDegree,
        },
    });
    const aggregateCiphertextRoot = hash(kernel, 'aggregate-ciphertext-root');
    const topCount = 2;
    const targetCiphertextHash = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'EncryptedSparseTargetCiphertext',
            aggregateCiphertextRoot,
            topCount,
            tiePolicy: 'higher-sum-first-then-lower-option-index',
            targetLayoutHash,
            targetIdRoot: targetId.ciphertextRoot,
            targetOrderRoot: targetOrder.ciphertextRoot,
            openedIntermediates: [],
        },
    });
    const releaseSetupContext =
        kernel.deriveBgvTargetDecryptionResultReleaseSetupContext({
            setupPackage,
        }) as JsonRecord;
    const targetDecryptionProfileHash = String(
        releaseSetupContext.targetDecryptionParametersHash,
    );
    const targetDecryptionProfileBindingHash = String(
        releaseSetupContext.targetDecryptionParametersBindingHash,
    );
    const targetShareProfileWithoutHash = {
        objectType: 'TargetDecryptionShareProfile',
        targetDecryptionProfileHash,
        targetDecryptionProfileBindingHash,
        decryptionThreshold: 2,
        minimumSharesForInterpolation: 2,
        decryptionShareQuorum: 2,
    } as const;
    const targetShareProfile = {
        ...targetShareProfileWithoutHash,
        targetShareProfileHash: kernel.deriveCanonicalObjectHash({
            value: targetShareProfileWithoutHash,
        }),
    };
    const targetAcceptedRecordWithoutHash = {
        objectType: 'TargetAcceptedRecord',
        boardPosition: 0,
        boardSequence: 0,
        ceremonyId: String(
            (setupPackage.setupContext as JsonRecord).ceremonyId,
        ),
        electionManifestHash: String(
            (setupPackage.setupContext as JsonRecord).manifestHash,
        ),
        evaluatorReplayRecordHash: hash(kernel, 'evaluator-replay'),
        organizerIdentity: 'organizer',
        targetBasisHash,
        targetCiphertextHash,
        targetContextHash: hash(kernel, 'target-context'),
        targetDecryptionParametersHash: targetDecryptionProfileHash,
        targetFinalityCheckpointHash: hash(
            kernel,
            'target-finality-checkpoint',
        ),
        targetFinalityRecordHash: hash(kernel, 'target-finality-record'),
        targetLayoutHash,
        targetPreimageHash: hash(kernel, 'target-preimage'),
        targetProposalHash: hash(kernel, 'target-proposal'),
    } as const;
    const targetAcceptedRecord = {
        ...targetAcceptedRecordWithoutHash,
        targetAcceptedRecordHash: kernel.deriveCanonicalObjectHash({
            value: targetAcceptedRecordWithoutHash,
        }),
    };

    return {
        targetAcceptedRecord,
        targetCiphertextBinding: {
            aggregateCiphertextRoot,
            topCount,
            targetLayoutHash,
        },
        targetCiphertexts: {
            targetIdCanonicalBytesHex: targetId.canonicalBytesHex,
            targetOrderCanonicalBytesHex: targetOrder.canonicalBytesHex,
        },
        targetDecryptionCiphertextHash: targetCiphertextHash,
        targetShareProfile,
    } as const;
};

const createLifecycleArtifacts = async (): LifecycleArtifactsPromise => {
    const kernel = await loadTranscriptCoreKernel();
    const setup = await setupLifecycleArtifacts(kernel);
    const target = targetArtifacts(
        kernel,
        setup.setupPackage,
        setup.ringDegree,
        setup.canonicalTargetBasisHash,
    );

    return { kernel, setup, target } as const;
};

let lifecycleArtifactsPromise:
    | ReturnType<typeof createLifecycleArtifacts>
    | undefined;

const lifecycleArtifacts = (): LifecycleArtifactsPromise => {
    lifecycleArtifactsPromise ??= createLifecycleArtifacts();
    return lifecycleArtifactsPromise;
};

const firstAggregateOpeningCredential = (
    localTargetShareWitness: JsonRecord,
): JsonRecord => {
    const aggregateOpening =
        localTargetShareWitness.aggregateOpening as JsonRecord;
    const aggregateOpeningCredentials =
        aggregateOpening.aggregateOpeningCredentials as JsonRecord[];
    const credential = aggregateOpeningCredentials[0];
    if (credential === undefined) {
        throw new Error(
            'Fixture must contain an aggregate opening credential.',
        );
    }

    return credential;
};

describe('local setup-to-target-share WASM lifecycle', () => {
    it('restores encrypted setup material and generates a target-bound share in WASM', async () => {
        const { kernel, setup, target } = await lifecycleArtifacts();
        const encryptedState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares(
                setup.localStateInput,
            );
        const preparedWitness =
            await restoreAndPrepareLocalTargetDecryptionShareWitness({
                encryptedLocalState: encryptedState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext: setup.localStateInput.setupContext,
                storageKeyBytesHex: setup.localStateInput.storageKeyBytesHex,
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetDecryptionCiphertextHash:
                    target.targetDecryptionCiphertextHash,
                targetShareProfile: target.targetShareProfile,
            });
        await stageBgvTargetDecryptionAggregateOpeningMaterials({
            kernel,
            sources: preparedWitness.aggregateOpeningMaterialSources,
        });
        const targetDecryptionShare =
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness:
                    preparedWitness.localTargetShareWitness,
            });

        expect(targetDecryptionShare).toMatchObject({
            objectType: 'BgvTargetDecryptionShare',
            trusteeIdentity: localTrusteeIdentity,
            rosterPosition: localTrusteeRosterPosition,
            targetAcceptedRecordHash:
                target.targetAcceptedRecord.targetAcceptedRecordHash,
            targetCiphertextHash:
                target.targetAcceptedRecord.targetCiphertextHash,
        });
        expect(targetDecryptionShare.targetDecryptionShareHash).toHaveLength(
            128,
        );
        expect(targetDecryptionShare.shareRoot).toHaveLength(128);
        expect(JSON.stringify(targetDecryptionShare)).not.toContain(
            setup.aggregateMaterialSeedHex,
        );
        expect(
            JSON.stringify(encryptedState.encryptedLocalState),
        ).not.toContain(setup.aggregateMaterialSeedHex);
    });

    it('rejects altered restored openings and a target ciphertext replay', async () => {
        const { kernel, setup, target } = await lifecycleArtifacts();
        const encryptedState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares(
                setup.localStateInput,
            );
        const preparedWitness =
            await restoreAndPrepareLocalTargetDecryptionShareWitness({
                encryptedLocalState: encryptedState.encryptedLocalState,
                expectedLocalStateRoot:
                    encryptedState.localStateCommitment.localStateRoot,
                setupContext: setup.localStateInput.setupContext,
                storageKeyBytesHex: setup.localStateInput.storageKeyBytesHex,
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetDecryptionCiphertextHash:
                    target.targetDecryptionCiphertextHash,
                targetShareProfile: target.targetShareProfile,
            });
        const localTargetShareWitness =
            preparedWitness.localTargetShareWitness as JsonRecord;
        const stageAggregateOpeningMaterial = async (): Promise<void> =>
            stageBgvTargetDecryptionAggregateOpeningMaterials({
                kernel,
                sources: preparedWitness.aggregateOpeningMaterialSources,
            });
        const alteredWitness = structuredClone(localTargetShareWitness);
        const credential = firstAggregateOpeningCredential(alteredWitness);
        credential.aggregateMaterialSeedHex = '00'.repeat(64);

        await stageAggregateOpeningMaterial();
        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness: alteredWitness,
            }),
        ).toThrow(/credential commitment root/u);

        const messageAlteredSources =
            preparedWitness.aggregateOpeningMaterialSources.map(
                (source, sourceIndex) => ({
                    ...source,
                    pullChunk: async (request: {
                        readonly abortSignal?: AbortSignal;
                        readonly chunkIndex: number;
                        readonly expectedByteLength: number;
                    }): Promise<ArrayBuffer | undefined> => {
                        const chunk = await source.pullChunk(request);
                        if (
                            chunk === undefined ||
                            sourceIndex !== 0 ||
                            request.chunkIndex !== 0
                        ) {
                            return chunk;
                        }
                        const alteredChunk = chunk.slice(0);
                        new Uint8Array(alteredChunk)[0] ^= 1;
                        return alteredChunk;
                    },
                }),
            );

        await stageBgvTargetDecryptionAggregateOpeningMaterials({
            kernel,
            sources: messageAlteredSources,
        });
        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness,
            }),
        ).toThrow(/credential commitment root/u);

        const contextAlteredWitness = structuredClone(localTargetShareWitness);
        contextAlteredWitness.setupEpoch = 'changed-setup-epoch';

        await stageAggregateOpeningMaterial();
        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness: contextAlteredWitness,
            }),
        ).toThrow(/credential commitment root/u);

        const identityAlteredWitness = structuredClone(localTargetShareWitness);
        const identityAlteredCredential = firstAggregateOpeningCredential(
            identityAlteredWitness,
        );
        identityAlteredCredential.recipientIdentity =
            'changed-trustee-identity';

        await stageAggregateOpeningMaterial();
        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness: identityAlteredWitness,
            }),
        ).toThrow(/aggregate opening credential recipient identity/u);

        const rootAlteredWitness = structuredClone(localTargetShareWitness);
        const rootAlteredCredential =
            firstAggregateOpeningCredential(rootAlteredWitness);
        rootAlteredCredential.aggregateCommitmentRoot = hash(
            kernel,
            'changed-aggregate-commitment-root',
        );

        await stageAggregateOpeningMaterial();
        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: target.targetCiphertextBinding,
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness: rootAlteredWitness,
            }),
        ).toThrow(/aggregate opening credential commitment root/u);

        await stageAggregateOpeningMaterial();
        expect(() =>
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: setup.setupPackage,
                targetAcceptedRecord: target.targetAcceptedRecord,
                targetCiphertexts: target.targetCiphertexts,
                targetCiphertextBinding: {
                    ...target.targetCiphertextBinding,
                    aggregateCiphertextRoot: hash(
                        kernel,
                        'replayed-aggregate-ciphertext',
                    ),
                },
                targetShareProfile: target.targetShareProfile,
                trusteeIdentity: localTrusteeIdentity,
                localTargetShareWitness,
            }),
        ).toThrow(/does not match the accepted target ciphertext hash/u);
    });
});
