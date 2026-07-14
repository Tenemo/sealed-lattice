import { hexToBytes } from '@noble/hashes/utils.js';
import {
    openCanonicalJsonByteSource,
    sealResetSafeSetupMailbox,
    type AuthenticatedMailboxCarrier,
    type AuthenticatedMailboxKernel,
    type AuthenticatedMailboxSealInput,
    type AuthenticatedMailboxStreamBoundary,
    type BrowserLocalActionRandomnessCapability,
    type BrowserLocalSigningCapability,
    type MailboxCiphertextDescriptor,
} from '@sealed-lattice/crypto';
import {
    type ProtocolHash,
    type VerificationResult,
} from '@sealed-lattice/types';
import {
    canonicalStreamDomains,
    openCanonicalStreamWorkerRuntime,
    openMailboxGcmRuntime,
    type TranscriptCoreKernel,
} from '@sealed-lattice/wasm';

import { copyCanonicalStreamDescriptor } from './canonical-stream-descriptor.js';
import {
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    bytesToHex,
    deriveCollectiveBgvSetupContextHash,
} from './common-fields.js';
import {
    setupProofMaterialReferenceSetForVerificationInput,
    type CanonicalGeneratedSetupProofMaterial,
} from './setup-proof-material-transport.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

type PrivateVssCoefficientOpeningState = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly commitmentRoot: ProtocolHash;
    readonly coefficientMessage: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
};

type PrivateVssSourceTrusteeContributionState = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceParticipantId: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly sourceSigningCapability: BrowserLocalSigningCapability;
    readonly sourceVerificationKey: Uint8Array;
    readonly sourceActionRandomnessCapability: BrowserLocalActionRandomnessCapability;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
    readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
    readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
    readonly coefficientOpenings: readonly PrivateVssCoefficientOpeningState[];
};

type PrivateVssMailboxRecipient = {
    readonly recipientIdentity: string;
    readonly recipientParticipantId: string;
    readonly recipientRosterPosition: number;
    readonly mailboxEncapsulationKey: Uint8Array;
};

type PrivateVssMailboxKernel = Pick<
    TranscriptCoreKernel,
    | 'decodeSignedMailboxEnvelope'
    | 'decodeStreamDescriptor'
    | 'deriveMailboxEnvelopeHash'
    | 'deriveMailboxKemCiphertextHash'
    | 'deriveSetupMailboxSlotHash'
    | 'encodeActionRandomnessDerivationInput'
    | 'deriveActionRandomnessCommitment'
    | 'encodePrivateRandomBlockInput'
    | 'encodeMailboxAssociatedData'
    | 'encodeMailboxKeyScheduleInput'
    | 'encodeSignedMailboxEnvelope'
    | 'encodeStreamDescriptor'
    | 'exportedFunctionNames'
> &
    AuthenticatedMailboxKernel;

type PrivateVssMailboxDeliveryKernel = {
    readonly deriveCanonicalObjectHash: (input: {
        readonly value: unknown;
    }) => ProtocolHash;
    readonly exportCanonicalProofMaterial: (input: {
        readonly proofFamily: typeof privateVssShareProofFamily;
        readonly proofMaterialRoot: ProtocolHash;
    }) => Promise<CanonicalGeneratedSetupProofMaterial>;
    readonly verifyPrivateVssShareEnvelope: (input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly sourceTrusteeCoefficientCommitmentRecord: unknown;
        readonly sourceTrusteeCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly privateEnvelope: unknown;
        readonly transportedPrivateVssShareProofMaterial?: unknown;
        readonly expectedPrivateEnvelopeHash?: ProtocolHash;
        readonly expectedLocalVerificationRoot?: ProtocolHash;
    }) => VerificationResult<{
        readonly privateEnvelopeHash: ProtocolHash;
        readonly localVerificationRoot: ProtocolHash;
    }>;
};

type PrivateVssMailboxDeliverySetInput = {
    readonly kernel: PrivateVssMailboxDeliveryKernel;
    readonly mailboxKernel: PrivateVssMailboxKernel;
    readonly foundationContext: Readonly<{
        readonly suiteId: ProtocolHash;
        readonly ceremonyContextHash: ProtocolHash;
        readonly actionContextHash: ProtocolHash;
    }>;
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly sourceTrusteeContributionStates: readonly PrivateVssSourceTrusteeContributionState[];
    readonly recipients: readonly PrivateVssMailboxRecipient[];
    readonly mailboxOutboundCache: AuthenticatedMailboxSealInput['outboundCache'];
    readonly emitMailboxCiphertextChunk: AuthenticatedMailboxSealInput['emitCiphertextChunk'];
};

type PrivateVssMailboxSourceTrusteeDeliveryInput = Omit<
    PrivateVssMailboxDeliverySetInput,
    'sourceTrusteeContributionStates'
> & {
    readonly sourceTrusteeContributionState: PrivateVssSourceTrusteeContributionState;
};

type PrivateVssMailboxDeliveryContext = Omit<
    PrivateVssMailboxDeliverySetInput,
    'sourceTrusteeContributionStates' | 'recipients'
>;

const privateVssEnvelopeCommitmentSetReferenceRootInput = (
    envelopeReference: JsonRecord,
): JsonRecord => {
    const {
        mailboxCarrier: mailboxCarrierForRecipientTransport,
        transportedPrivateVssShareProofMaterial:
            transportedPrivateVssShareProofMaterialForRecipientTransport,
        ...rootInput
    } = envelopeReference;
    void mailboxCarrierForRecipientTransport;
    void transportedPrivateVssShareProofMaterialForRecipientTransport;

    return rootInput;
};

const privateVssEnvelopeCommitmentSetRootInput = (
    input: Pick<
        PrivateVssMailboxDeliverySetInput,
        'setupContext' | 'publicMatrixSeedHash' | 'vssCoefficientCommitmentRoot'
    >,
    commitmentSet: JsonRecord,
): JsonRecord => ({
    objectType: commitmentSet.objectType,
    setupContextHash: deriveCollectiveBgvSetupContextHash(input.setupContext),
    publicMatrixSeedHash: input.publicMatrixSeedHash,
    vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
    envelopeReferences: (commitmentSet.envelopeReferences as JsonRecord[]).map(
        privateVssEnvelopeCommitmentSetReferenceRootInput,
    ),
});

type PrivateVssMailboxDeliverySet = Readonly<
    JsonRecord & {
        readonly objectType: 'PrivateVssEnvelopeCommitmentSet';
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly envelopeReferences: readonly PrivateVssEnvelopeCommitment[];
    }
>;

export type PrivateVssEnvelopeCommitment = Readonly<
    JsonRecord & {
        readonly objectType: 'PrivateVssEnvelopeCommitment';
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly mailboxEnvelopeHash: ProtocolHash;
        readonly mailboxCarrier?: AuthenticatedMailboxCarrier;
        readonly localVerificationRoot: ProtocolHash;
        readonly transportedPrivateVssShareProofMaterial?: TransportedPrivateVssShareProofMaterialSet;
    }
>;

type PrivateVssMailboxDeliverySetFromReferencesInput = Pick<
    PrivateVssMailboxDeliverySetInput,
    | 'kernel'
    | 'setupContext'
    | 'publicMatrixSeedHash'
    | 'vssCoefficientCommitmentRoot'
    | 'participantCount'
> & {
    readonly envelopeReferences: readonly PrivateVssEnvelopeCommitment[];
};

type TransportedPrivateVssShareProofMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedPrivateVssShareProofMaterial';
        readonly proofMaterialRoot: ProtocolHash;
        readonly descriptorBytes: Uint8Array;
    }
>;

type TransportedPrivateVssShareProofMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedPrivateVssShareProofMaterialSet';
        readonly proofMaterials: readonly TransportedPrivateVssShareProofMaterial[];
    }
>;

const privateEnvelopeAadObjectType = 'PrivateVssEnvelopeAad';
const privateVssShareProofFamily = 'vss-opening-carry';

const mailboxStreamBoundary = (
    kernel: PrivateVssMailboxKernel,
): AuthenticatedMailboxStreamBoundary => {
    const runtime = openCanonicalStreamWorkerRuntime({ kernel });

    return Object.freeze({
        openWriter: (input: { readonly totalByteLength: number }) => {
            const writer = runtime.openWriter({
                streamDomain: canonicalStreamDomains.privateMailboxCiphertext,
                totalByteLength: input.totalByteLength,
            });
            return Object.freeze({
                absorbChunk: (chunkIndex: number, bytes: ArrayBuffer): void =>
                    writer.absorbChunk(chunkIndex, bytes),
                cancel: (): void => writer.cancel(),
                chunkCount: writer.chunkCount,
                finish: (): MailboxCiphertextDescriptor => {
                    const descriptorBytes = writer.finish();
                    try {
                        return kernel.decodeStreamDescriptor({
                            canonicalBytesHex: bytesToHex(descriptorBytes),
                        }).value;
                    } finally {
                        descriptorBytes.fill(0);
                    }
                },
                state: () => writer.state(),
                totalByteLength: writer.totalByteLength,
            });
        },
        openVerifier: (input: {
            readonly descriptor: MailboxCiphertextDescriptor;
        }) => {
            const descriptorBytes = hexToBytes(
                kernel.encodeStreamDescriptor(input.descriptor)
                    .canonicalBytesHex,
            );
            try {
                const verifier = runtime.openVerifier({
                    descriptorBytes,
                    streamDomain:
                        canonicalStreamDomains.privateMailboxCiphertext,
                });
                return Object.freeze({
                    absorbChunk: (
                        chunkIndex: number,
                        bytes: ArrayBuffer,
                    ): void => verifier.absorbChunk(chunkIndex, bytes),
                    cancel: (): void => verifier.cancel(),
                    chunkCount: verifier.chunkCount,
                    finish: (): void => verifier.finish(),
                    state: () => verifier.state(),
                    totalByteLength: verifier.totalByteLength,
                });
            } finally {
                descriptorBytes.fill(0);
            }
        },
    });
};

const sortedByRosterPosition = <Entry>(
    entries: readonly Entry[],
    rosterPosition: (entry: Entry) => number,
    entryLabel: string,
): Entry[] => {
    const sortedEntries = [...entries].sort(
        (left, right) => rosterPosition(left) - rosterPosition(right),
    );
    const seenRosterPositions = new Set<number>();
    for (const entry of sortedEntries) {
        const position = rosterPosition(entry);
        assertNonNegativeSafeInteger(position, `${entryLabel} roster position`);
        if (seenRosterPositions.has(position)) {
            throw new Error(`${entryLabel} roster positions must be distinct.`);
        }
        seenRosterPositions.add(position);
    }

    return sortedEntries;
};

const sortedBySourceTrusteeThenRecipient = (
    envelopeReferences: readonly PrivateVssEnvelopeCommitment[],
): PrivateVssEnvelopeCommitment[] =>
    [...envelopeReferences].sort((left, right) => {
        const sourceOrder =
            assertNonNegativeSafeInteger(
                left.sourceTrusteeRosterPosition,
                'private VSS envelope reference source trustee roster position',
            ) -
            assertNonNegativeSafeInteger(
                right.sourceTrusteeRosterPosition,
                'private VSS envelope reference source trustee roster position',
            );

        return sourceOrder === 0
            ? assertNonNegativeSafeInteger(
                  left.recipientRosterPosition,
                  'private VSS envelope reference recipient roster position',
              ) -
                  assertNonNegativeSafeInteger(
                      right.recipientRosterPosition,
                      'private VSS envelope reference recipient roster position',
                  )
            : sourceOrder;
    });

const assertFullRosterPositions = (
    positions: readonly number[],
    participantCount: number,
    entryLabel: string,
): void => {
    if (positions.length !== participantCount) {
        throw new Error(
            `${entryLabel} count must match the accepted participant count.`,
        );
    }
    positions.forEach((position, expectedPosition) => {
        if (position !== expectedPosition) {
            throw new Error(
                `${entryLabel} roster positions must be contiguous from zero.`,
            );
        }
    });
};

const assertFullEnvelopeReferenceCoverage = (
    envelopeReferences: readonly PrivateVssEnvelopeCommitment[],
    participantCount: number,
): void => {
    if (envelopeReferences.length !== participantCount * participantCount) {
        throw new Error(
            'private VSS envelope reference count must match the accepted participant square.',
        );
    }
    const observedPairs = new Set<string>();
    envelopeReferences.forEach((envelopeReference, envelopeReferenceIndex) => {
        const sourceTrusteeRosterPosition = assertNonNegativeSafeInteger(
            envelopeReference.sourceTrusteeRosterPosition,
            `private VSS envelope reference ${String(envelopeReferenceIndex)} source trustee roster position`,
        );
        const recipientRosterPosition = assertNonNegativeSafeInteger(
            envelopeReference.recipientRosterPosition,
            `private VSS envelope reference ${String(envelopeReferenceIndex)} recipient roster position`,
        );
        assertNonNegativeSafeInteger(
            sourceTrusteeRosterPosition,
            `private VSS envelope reference ${String(envelopeReferenceIndex)} source trustee roster position`,
        );
        assertNonNegativeSafeInteger(
            recipientRosterPosition,
            `private VSS envelope reference ${String(envelopeReferenceIndex)} recipient roster position`,
        );
        if (
            sourceTrusteeRosterPosition >= participantCount ||
            recipientRosterPosition >= participantCount
        ) {
            throw new Error(
                'private VSS envelope reference roster positions must be inside the accepted participant count.',
            );
        }
        const pairKey = `${String(sourceTrusteeRosterPosition)}:${String(
            recipientRosterPosition,
        )}`;
        if (observedPairs.has(pairKey)) {
            throw new Error(
                'private VSS envelope references must have distinct source-recipient pairs.',
            );
        }
        observedPairs.add(pairKey);
    });

    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < participantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        for (
            let recipientRosterPosition = 0;
            recipientRosterPosition < participantCount;
            recipientRosterPosition += 1
        ) {
            if (
                !observedPairs.has(
                    `${String(sourceTrusteeRosterPosition)}:${String(
                        recipientRosterPosition,
                    )}`,
                )
            ) {
                throw new Error(
                    'private VSS envelope references must cover every source-recipient pair.',
                );
            }
        }
    }
};

const shareValuesForRecipient = (
    coefficientMessagesByShamirIndex: readonly (readonly number[])[],
    recipientRosterPosition: number,
    rnsPrime: number,
    ringDegree: number,
): readonly number[] => {
    const trusteePoint = BigInt(recipientRosterPosition + 1);
    const trusteePointPowers: bigint[] = [];
    let trusteePointPower = 1n;
    for (const _coefficientMessages of coefficientMessagesByShamirIndex) {
        trusteePointPowers.push(trusteePointPower);
        trusteePointPower *= trusteePoint;
    }
    const rnsPrimeWide = BigInt(rnsPrime);
    const shareValues: number[] = [];
    for (
        let coefficientPosition = 0;
        coefficientPosition < ringDegree;
        coefficientPosition += 1
    ) {
        const unreducedValue = coefficientMessagesByShamirIndex.reduce(
            (accumulatedValue, coefficientMessages, shamirCoefficientIndex) => {
                const coefficientMessage =
                    coefficientMessages[coefficientPosition];
                if (coefficientMessage === undefined) {
                    throw new Error(
                        'VSS coefficient message length must match ringDegree.',
                    );
                }

                return (
                    accumulatedValue +
                    BigInt(coefficientMessage) *
                        trusteePointPowers[shamirCoefficientIndex]
                );
            },
            0n,
        );
        shareValues.push(Number(unreducedValue % rnsPrimeWide));
    }

    return shareValues;
};

const privateEnvelopeAad = (
    input: PrivateVssMailboxDeliveryContext,
    sourceTrusteeState: PrivateVssSourceTrusteeContributionState,
    recipient: PrivateVssMailboxRecipient,
): JsonRecord => ({
    objectType: privateEnvelopeAadObjectType,
    setupContextHash: deriveCollectiveBgvSetupContextHash(input.setupContext),
    publicMatrixSeedHash: input.publicMatrixSeedHash,
    vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
    sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition: sourceTrusteeState.sourceTrusteeRosterPosition,
    recipientIdentity: recipient.recipientIdentity,
    recipientRosterPosition: recipient.recipientRosterPosition,
    sourceTrusteeCommitmentRoot: sourceTrusteeState.sourceTrusteeCommitmentRoot,
});

const transportPrivateVssShareProofMaterial = (
    kernel: PrivateVssMailboxDeliveryKernel,
    proofRecord: JsonRecord,
    canonicalMaterial: CanonicalGeneratedSetupProofMaterial,
): {
    readonly proofRecord: JsonRecord;
    readonly proofMaterial: TransportedPrivateVssShareProofMaterial;
} => {
    const proofBytesHash = assertProtocolHash(
        proofRecord.proofBytesHash,
        'privateVssShareProof.proofBytesHash',
    );
    assertProtocolHash(
        proofRecord.statementHash,
        'privateVssShareProof.statementHash',
    );
    const expectedProofMaterialRoot = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'SetupProofMaterialReference',
            proofFamily: 'vss-opening-carry',
            proofBytesHash,
        },
    });
    const proofMaterialRoot = assertProtocolHash(
        proofRecord.proofMaterialRoot,
        'privateVssShareProof.proofMaterialRoot',
    );
    if (proofMaterialRoot !== expectedProofMaterialRoot) {
        throw new Error(
            'privateVssShareProof.proofMaterialRoot must match its semantic proof reference.',
        );
    }
    const transportedProofRecord = {
        ...proofRecord,
        proofMaterialRoot,
    };

    return {
        proofRecord: transportedProofRecord,
        proofMaterial: {
            objectType: 'SetupTransportedPrivateVssShareProofMaterial',
            proofMaterialRoot,
            descriptorBytes: copyCanonicalStreamDescriptor(
                canonicalMaterial.descriptorBytes,
                'canonical generated proof material descriptorBytes',
            ),
        },
    };
};

type PrivateVssShareEnvelopeBuild = Readonly<{
    readonly privateEnvelope: JsonRecord;
    readonly transportedPrivateVssShareProofMaterial?: TransportedPrivateVssShareProofMaterialSet;
}>;

const refuseUnreservedPrivateVssShareProof = (): {
    readonly privateVssShareProof: JsonRecord;
} => {
    throw new Error(
        'Private VSS envelope generation requires one source-batched durable proof application per source trustee; per-recipient, per-limb proofs are not authorized.',
    );
};

const privateEnvelope = async (
    input: PrivateVssMailboxDeliveryContext,
    sourceTrusteeState: PrivateVssSourceTrusteeContributionState,
    recipient: PrivateVssMailboxRecipient,
    privateEnvelopeAadHash: ProtocolHash,
): Promise<PrivateVssShareEnvelopeBuild> => {
    const transportedProofMaterials: TransportedPrivateVssShareProofMaterial[] =
        [];
    const rnsShareOpenings: JsonRecord[] = [];
    for (
        let rnsLimbIndex = 0;
        rnsLimbIndex < input.qSharePrimes.length;
        rnsLimbIndex += 1
    ) {
        const rnsPrime = input.qSharePrimes[rnsLimbIndex];
        if (rnsPrime === undefined) {
            throw new Error('Q_share prime schedule is incomplete.');
        }
        const coefficientOpenings = sourceTrusteeState.coefficientOpenings
            .filter(
                (opening) =>
                    opening.rnsLimbIndex === rnsLimbIndex &&
                    opening.rnsPrime === rnsPrime,
            )
            .sort(
                (left, right) =>
                    left.shamirCoefficientIndex - right.shamirCoefficientIndex,
            );
        if (coefficientOpenings.length === 0) {
            throw new Error(
                'Source trustee local VSS state must contain every Q_share limb.',
            );
        }
        const coefficientMessagesByShamirIndex = coefficientOpenings.map(
            (opening) => {
                if (opening.coefficientMessage.length !== input.ringDegree) {
                    throw new Error(
                        'VSS coefficient message length must match ringDegree.',
                    );
                }

                return opening.coefficientMessage;
            },
        );
        const shareValues = shareValuesForRecipient(
            coefficientMessagesByShamirIndex,
            recipient.recipientRosterPosition,
            rnsPrime,
            input.ringDegree,
        );
        const coefficientCommitmentRoots = coefficientOpenings.map(
            (opening) => opening.commitmentRoot,
        );
        const generatedProof = refuseUnreservedPrivateVssShareProof();
        const proofRecord = generatedProof.privateVssShareProof;
        const proofMaterialRoot = assertProtocolHash(
            proofRecord.proofMaterialRoot,
            'privateVssShareProof.proofMaterialRoot',
        );
        const canonicalMaterial =
            await input.kernel.exportCanonicalProofMaterial({
                proofFamily: privateVssShareProofFamily,
                proofMaterialRoot,
            });
        const transportedProof = transportPrivateVssShareProofMaterial(
            input.kernel,
            proofRecord,
            canonicalMaterial,
        );
        transportedProofMaterials.push(transportedProof.proofMaterial);
        const privateVssShareProof = transportedProof.proofRecord;

        rnsShareOpenings.push({
            objectType: 'PrivateVssShareLimbOpening',
            rnsLimbIndex,
            rnsPrime,
            shareValues,
            coefficientCommitmentRoots,
            privateVssShareProof,
        });
    }

    const privateShareEnvelope = {
        objectType: 'PrivateVssShareEnvelope',
        setupContextHash: deriveCollectiveBgvSetupContextHash(
            input.setupContext,
        ),
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        privateEnvelopeAadHash,
        sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition:
            sourceTrusteeState.sourceTrusteeRosterPosition,
        recipientIdentity: recipient.recipientIdentity,
        recipientRosterPosition: recipient.recipientRosterPosition,
        sourceTrusteeCommitmentRoot:
            sourceTrusteeState.sourceTrusteeCommitmentRoot,
        rnsShareOpenings,
    };

    if (transportedProofMaterials.length === 0) {
        return { privateEnvelope: privateShareEnvelope };
    }

    return {
        privateEnvelope: privateShareEnvelope,
        transportedPrivateVssShareProofMaterial: {
            objectType: 'SetupTransportedPrivateVssShareProofMaterialSet',
            proofMaterials: transportedProofMaterials,
        },
    };
};

const createEnvelopeCommitment = async (
    input: PrivateVssMailboxDeliveryContext,
    sourceTrusteeState: PrivateVssSourceTrusteeContributionState,
    recipient: PrivateVssMailboxRecipient,
): Promise<PrivateVssEnvelopeCommitment> => {
    const associatedData = privateEnvelopeAad(
        input,
        sourceTrusteeState,
        recipient,
    );
    const associatedDataHash = input.kernel.deriveCanonicalObjectHash({
        value: associatedData,
    });
    const privateShareEnvelopeBuild = await privateEnvelope(
        input,
        sourceTrusteeState,
        recipient,
        associatedDataHash,
    );
    const localVerification = input.kernel.verifyPrivateVssShareEnvelope({
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        sourceTrusteeCoefficientCommitmentRecord:
            sourceTrusteeState.sourceTrusteeCoefficientCommitmentRecord,
        sourceTrusteeCoefficientCommitmentMaterialRecords:
            sourceTrusteeState.sourceTrusteeCoefficientCommitmentMaterialRecords,
        privateEnvelope: privateShareEnvelopeBuild.privateEnvelope,
        ...(privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial ===
        undefined
            ? {}
            : {
                  transportedPrivateVssShareProofMaterial:
                      setupProofMaterialReferenceSetForVerificationInput(
                          privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial,
                      ),
              }),
    });
    if (!localVerification.isValid) {
        throw new Error(
            `Private VSS envelope failed local verification: ${localVerification.refusalReason}.`,
        );
    }
    const { privateEnvelopeHash, localVerificationRoot } =
        localVerification.value;
    const plaintextSource = openCanonicalJsonByteSource(
        privateShareEnvelopeBuild.privateEnvelope,
    );
    const pullPlaintextChunk: AuthenticatedMailboxSealInput['pullPlaintextChunk'] =
        ({ chunkIndex, expectedByteLength }) =>
            Promise.resolve(
                plaintextSource.pullChunk({
                    chunkIndex,
                    expectedByteLength,
                }),
            );
    let mailboxDelivery: AuthenticatedMailboxCarrier;
    try {
        mailboxDelivery = await sealResetSafeSetupMailbox({
            associatedData: {
                suiteId: input.foundationContext.suiteId,
                ceremonyContextHash:
                    input.foundationContext.ceremonyContextHash,
                actionContextHash: input.foundationContext.actionContextHash,
                rosterHash: input.setupContext.rosterHash,
                sourceParticipantId: sourceTrusteeState.sourceParticipantId,
                recipientParticipantId: recipient.recipientParticipantId,
                producerSequence: String(
                    sourceTrusteeState.sourceTrusteeRosterPosition *
                        input.participantCount +
                        recipient.recipientRosterPosition,
                ),
                payloadType: 2,
                statementHash: privateEnvelopeHash,
                orderedMaterialRoots: [
                    sourceTrusteeState.sourceTrusteeCommitmentRoot,
                    ...(privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial?.proofMaterials.map(
                        (proofMaterial) => proofMaterial.proofMaterialRoot,
                    ) ?? []),
                ],
            },
            emitCiphertextChunk: input.emitMailboxCiphertextChunk,
            gcmRuntime: openMailboxGcmRuntime({
                kernel: input.mailboxKernel,
            }),
            kernel: input.mailboxKernel,
            outboundCache: input.mailboxOutboundCache,
            plaintextByteLength: plaintextSource.byteLength,
            pullPlaintextChunk,
            recipientEncapsulationKey: recipient.mailboxEncapsulationKey,
            sourceSigningCapability: sourceTrusteeState.sourceSigningCapability,
            sourceVerificationKey: sourceTrusteeState.sourceVerificationKey,
            actionRandomnessCapability:
                sourceTrusteeState.sourceActionRandomnessCapability,
            streamBoundary: mailboxStreamBoundary(input.mailboxKernel),
        });
    } finally {
        plaintextSource.cancel();
    }
    const commitmentWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitment',
        sourceTrusteeIdentity: sourceTrusteeState.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition:
            sourceTrusteeState.sourceTrusteeRosterPosition,
        recipientIdentity: recipient.recipientIdentity,
        recipientRosterPosition: recipient.recipientRosterPosition,
        privateEnvelopeHash,
        mailboxEnvelopeHash: mailboxDelivery.envelopeHash,
        mailboxCarrier: mailboxDelivery,
        localVerificationRoot,
        ...(privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial ===
        undefined
            ? {}
            : {
                  transportedPrivateVssShareProofMaterial:
                      privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial,
              }),
    } as const satisfies JsonRecord;

    return commitmentWithoutRoot satisfies PrivateVssEnvelopeCommitment;
};

const createPrivateVssMailboxSourceTrusteeDeliveryReferences = async (
    input: PrivateVssMailboxSourceTrusteeDeliveryInput,
): Promise<readonly PrivateVssEnvelopeCommitment[]> => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertNonNegativeSafeInteger(
        input.sourceTrusteeContributionState.sourceTrusteeRosterPosition,
        'source trustee contribution state roster position',
    );
    if (
        input.sourceTrusteeContributionState.sourceTrusteeRosterPosition >=
        input.participantCount
    ) {
        throw new Error(
            'source trustee contribution state roster position must be inside the accepted participant count.',
        );
    }
    const recipients = sortedByRosterPosition(
        input.recipients,
        (recipient) => recipient.recipientRosterPosition,
        'mailbox recipient',
    );
    assertFullRosterPositions(
        recipients.map((recipient) => recipient.recipientRosterPosition),
        input.participantCount,
        'mailbox recipient',
    );

    const envelopeReferences: PrivateVssEnvelopeCommitment[] = [];
    for (const recipient of recipients) {
        envelopeReferences.push(
            await createEnvelopeCommitment(
                input,
                input.sourceTrusteeContributionState,
                recipient,
            ),
        );
    }

    return envelopeReferences;
};

const createPrivateVssMailboxDeliverySetFromReferences = (
    input: PrivateVssMailboxDeliverySetFromReferencesInput,
): PrivateVssMailboxDeliverySet => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    const envelopeReferences = sortedBySourceTrusteeThenRecipient(
        input.envelopeReferences,
    );
    assertFullEnvelopeReferenceCoverage(
        envelopeReferences,
        input.participantCount,
    );

    const commitmentSetWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitmentSet',
        envelopeReferences,
    } as const satisfies JsonRecord;

    return {
        ...commitmentSetWithoutRoot,
        privateVssEnvelopeCommitmentRoot:
            input.kernel.deriveCanonicalObjectHash({
                value: privateVssEnvelopeCommitmentSetRootInput(
                    input,
                    commitmentSetWithoutRoot,
                ),
            }),
    } satisfies PrivateVssMailboxDeliverySet;
};

export const createPrivateVssMailboxDeliverySet = async (
    input: PrivateVssMailboxDeliverySetInput,
): Promise<PrivateVssMailboxDeliverySet> => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    const sourceTrusteeStates = sortedByRosterPosition(
        input.sourceTrusteeContributionStates,
        (sourceTrusteeState) => sourceTrusteeState.sourceTrusteeRosterPosition,
        'source trustee contribution state',
    );
    const recipients = sortedByRosterPosition(
        input.recipients,
        (recipient) => recipient.recipientRosterPosition,
        'mailbox recipient',
    );
    assertFullRosterPositions(
        sourceTrusteeStates.map(
            (sourceTrusteeState) =>
                sourceTrusteeState.sourceTrusteeRosterPosition,
        ),
        input.participantCount,
        'source trustee contribution state',
    );
    assertFullRosterPositions(
        recipients.map((recipient) => recipient.recipientRosterPosition),
        input.participantCount,
        'mailbox recipient',
    );

    const envelopeReferences: PrivateVssEnvelopeCommitment[] = [];
    for (const sourceTrusteeContributionState of sourceTrusteeStates) {
        envelopeReferences.push(
            ...(await createPrivateVssMailboxSourceTrusteeDeliveryReferences({
                ...input,
                sourceTrusteeContributionState,
                recipients,
            })),
        );
    }

    return createPrivateVssMailboxDeliverySetFromReferences({
        kernel: input.kernel,
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        participantCount: input.participantCount,
        envelopeReferences,
    });
};
