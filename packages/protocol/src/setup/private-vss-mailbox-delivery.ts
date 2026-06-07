import {
    encryptPrivateVssMailboxEnvelope,
    hash512Hex,
    privateVssMailboxEncryptionProfileId,
    setupProofMaterialFullObjectHashHex,
    type PrivateVssEncryptedEnvelope,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { setupProofProfileId } from './same-secret-consistency-records.js';

type JsonRecord = Record<string, unknown>;

type PrivateVssSetupContext = Readonly<
    Record<string, unknown> & {
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
    }
>;

export type PrivateVssCoefficientOpeningState = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly commitmentRoot: ProtocolHash;
    readonly coefficientMessage: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
};

export type PrivateVssDealerContributionState = {
    readonly dealerIdentity: string;
    readonly dealerRosterPosition: number;
    readonly dealerCommitmentRoot: ProtocolHash;
    readonly dealerCoefficientCommitmentRecord: unknown;
    readonly dealerCoefficientCommitmentMaterialRecords: readonly unknown[];
    readonly coefficientOpenings: readonly PrivateVssCoefficientOpeningState[];
};

export type PrivateVssMailboxRecipient = {
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly mailboxPublicKeyBytesHex: string;
};

export type PrivateVssShareProofFactoryInput = {
    readonly setupContext: PrivateVssSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly privateEnvelopeAadHash: ProtocolHash;
    readonly dealerContributionState: PrivateVssDealerContributionState;
    readonly recipient: PrivateVssMailboxRecipient;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly shareValues: readonly number[];
    readonly coefficientCommitmentRoots: readonly ProtocolHash[];
};

export type PrivateVssShareProofFactory = (
    input: PrivateVssShareProofFactoryInput,
) => JsonRecord;

export type PrivateVssShareProofRandomness = {
    readonly source: 'fresh-csprng' | 'development-deterministic-fixture';
    readonly seedHex: string;
};

export type PrivateVssShareProofRandomnessFactory = (
    input: PrivateVssShareProofFactoryInput,
) => PrivateVssShareProofRandomness;

export type PrivateVssMailboxDeliveryKernel = {
    readonly deriveProtocolHash: (input: {
        readonly namespace: string;
        readonly value: unknown;
    }) => ProtocolHash;
    readonly generatePrivateVssShareProof?: (input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly privateEnvelopeAadHash: ProtocolHash;
        readonly dealerCoefficientCommitmentRecord: unknown;
        readonly dealerCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly shareValues: readonly number[];
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
        readonly openingRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
        readonly proofRandomnessSource?:
            | 'fresh-csprng'
            | 'development-deterministic-fixture';
        readonly proofRandomnessSeedHex: string;
    }) => {
        readonly privateVssShareProof: JsonRecord;
    };
    readonly verifyPrivateVssShareEnvelope: (input: {
        readonly setupContext: unknown;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly dealerCoefficientCommitmentRecord: unknown;
        readonly dealerCoefficientCommitmentMaterialRecords: readonly unknown[];
        readonly privateEnvelope: unknown;
        readonly transportedPrivateVssShareProofMaterial?: unknown;
        readonly expectedPrivateEnvelopeHash?: ProtocolHash;
        readonly expectedLocalVerificationRoot?: ProtocolHash;
    }) => {
        readonly ok: boolean;
        readonly privateEnvelopeHash: ProtocolHash | null;
        readonly localVerificationRoot: ProtocolHash | null;
        readonly refusedObjects: readonly {
            readonly reasonCode: string;
            readonly message: string;
            readonly objectPath?: string;
        }[];
    };
};

export type PrivateVssMailboxDeliverySetInput = {
    readonly kernel: PrivateVssMailboxDeliveryKernel;
    readonly setupContext: PrivateVssSetupContext;
    readonly phaseOrderHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly deliveryPhaseNumber: number;
    readonly verificationPhaseNumber: number;
    readonly privateVssShareProofMaterialEncoding?:
        | typeof embeddedPrivateVssShareProofBytesEncoding
        | typeof transportedSetupProofMaterialEncoding;
    readonly privateVssShareProofFactory?: PrivateVssShareProofFactory;
    readonly privateVssShareProofRandomnessFactory?: PrivateVssShareProofRandomnessFactory;
    readonly dealerContributionStates: readonly PrivateVssDealerContributionState[];
    readonly recipients: readonly PrivateVssMailboxRecipient[];
};

export type PrivateVssMailboxDealerDeliveryInput = Omit<
    PrivateVssMailboxDeliverySetInput,
    'dealerContributionStates'
> & {
    readonly dealerContributionState: PrivateVssDealerContributionState;
};

type PrivateVssMailboxDeliveryContext = Omit<
    PrivateVssMailboxDeliverySetInput,
    'dealerContributionStates' | 'recipients'
>;

const privateVssEnvelopeCommitmentRootInput = (
    envelopeReference: JsonRecord,
): JsonRecord => {
    const {
        encryptedEnvelope: encryptedEnvelopeForRecipientTransport,
        transportedPrivateVssShareProofMaterial:
            transportedPrivateVssShareProofMaterialForRecipientTransport,
        ...rootInput
    } = envelopeReference;
    void encryptedEnvelopeForRecipientTransport;
    void transportedPrivateVssShareProofMaterialForRecipientTransport;

    return rootInput;
};

const privateVssEnvelopeCommitmentSetRootInput = (
    commitmentSet: JsonRecord,
): JsonRecord => ({
    ...commitmentSet,
    envelopeReferences: (commitmentSet.envelopeReferences as JsonRecord[]).map(
        privateVssEnvelopeCommitmentRootInput,
    ),
});

export type PrivateVssMailboxDeliverySet = Readonly<
    JsonRecord & {
        readonly objectType: 'PrivateVssEnvelopeCommitmentSet';
        readonly objectVersion: 1;
        readonly mailboxEncryptionProfileId: typeof privateVssMailboxEncryptionProfileId;
        readonly privateVssEnvelopeCommitmentRoot: ProtocolHash;
        readonly envelopeReferences: readonly PrivateVssEnvelopeCommitment[];
    }
>;

export type PrivateVssEnvelopeCommitment = Readonly<
    JsonRecord & {
        readonly objectType: 'PrivateVssEnvelopeCommitment';
        readonly objectVersion: 1;
        readonly privateEnvelopeHash: ProtocolHash;
        readonly encryptedEnvelopeHash: ProtocolHash;
        readonly privateEnvelopeAad: JsonRecord;
        readonly privateEnvelopeAadHash: ProtocolHash;
        readonly encryptedEnvelope: PrivateVssEncryptedEnvelope;
        readonly recipientMailboxPublicKeyHash: ProtocolHash;
        readonly localVerificationRoot: ProtocolHash;
        readonly transportedPrivateVssShareProofMaterial?: TransportedPrivateVssShareProofMaterialSet;
        readonly privateEnvelopeCommitmentRoot: ProtocolHash;
    }
>;

export type TransportedPrivateVssShareProofChunk = Readonly<
    JsonRecord & {
        readonly chunkIndex: number;
        readonly bytesHex: string;
    }
>;

export type TransportedPrivateVssShareProofMaterial = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedPrivateVssShareProofMaterial';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof privateVssShareProofFamily;
        readonly proofMaterialRoot: ProtocolHash;
        readonly chunkSizeBytes: typeof setupProofTransportChunkSizeBytes;
        readonly chunkCount: number;
        readonly totalByteLength: number;
        readonly fullObjectHash: ProtocolHash;
        readonly chunkHashes: readonly ProtocolHash[];
        readonly chunkRoot: ProtocolHash;
        readonly chunks: readonly TransportedPrivateVssShareProofChunk[];
    }
>;

export type TransportedPrivateVssShareProofMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SetupTransportedPrivateVssShareProofMaterialSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof privateVssShareProofFamily;
        readonly proofMaterials: readonly TransportedPrivateVssShareProofMaterial[];
    }
>;

const privateEnvelopeDeliveryContentType = 'private-vss-share-envelope';
const privateEnvelopeObjectType = 'PrivateVssShareEnvelope';
const privateEnvelopeAadObjectType = 'PrivateVssEnvelopeAad';
const localOpeningAcceptedStatus = 'accepted-local-private-vss-opening';
const recipientVerificationRequirement =
    'recipient-verifies-private-vss-opening-before-acceptance';
const setupProfileId = 'CollectiveBgvSetup-v1';
const privateVssShareProofFamily = 'vss-opening-carry';
const embeddedPrivateVssShareProofBytesEncoding =
    'embedded-binary-proof-bytes-hex';
const transportedSetupProofMaterialEncoding = 'binary-chunked-proof-bytes';
const setupProofTransportChunkSizeBytes = 1_048_576;
const privateVssShareProofBytesHashDomain =
    'sealed-lattice/setup/private-vss-share/lnp-proof-bytes-v1';
const textEncoder = new TextEncoder();
const lowercaseHexPattern = /^[0-9a-f]+$/u;
const protocolHashPattern = /^[0-9a-f]{128}$/u;

const validatePositiveSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const validateSafeRosterPosition = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertProtocolHash = (
    value: unknown,
    fieldName: string,
): ProtocolHash => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(
            `${fieldName} must be a lowercase 512-bit protocol hash.`,
        );
    }

    return value;
};

const assertNonNegativeSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

const assertString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${fieldName} must be a non-empty string.`);
    }

    return value;
};

const assertLowercaseEvenHex = (value: string, fieldName: string): void => {
    if (
        value.length === 0 ||
        value.length % 2 !== 0 ||
        !lowercaseHexPattern.test(value)
    ) {
        throw new TypeError(
            `${fieldName} must be non-empty lowercase even-length hex.`,
        );
    }
};

const hexToBytes = (hex: string, fieldName: string): Uint8Array => {
    assertLowercaseEvenHex(hex, fieldName);
    const output = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < output.length; byteIndex += 1) {
        output[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return output;
};

const bytesToHex = (bytes: Uint8Array): string =>
    [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

const varUintBytes = (value: number, fieldName: string): Uint8Array => {
    assertNonNegativeSafeInteger(value, fieldName);
    const bytes: number[] = [];
    let remainingValue = value;
    for (;;) {
        let byte = remainingValue & 0x7f;
        remainingValue = Math.floor(remainingValue / 128);
        if (remainingValue !== 0) {
            byte |= 0x80;
        }
        bytes.push(byte);
        if (remainingValue === 0) {
            break;
        }
    }

    return Uint8Array.from(bytes);
};

const splitProofBytesIntoChunks = (
    proofBytes: Uint8Array,
): readonly Uint8Array[] => {
    const chunks: Uint8Array[] = [];
    for (
        let chunkStart = 0;
        chunkStart < proofBytes.byteLength;
        chunkStart += setupProofTransportChunkSizeBytes
    ) {
        chunks.push(
            proofBytes.slice(
                chunkStart,
                Math.min(
                    chunkStart + setupProofTransportChunkSizeBytes,
                    proofBytes.byteLength,
                ),
            ),
        );
    }

    return chunks;
};

const setupProofMaterialChunkHash = (
    proofFamily: string,
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex('sealed-lattice/setup/proof-material/chunk-v1', [
        textEncoder.encode(proofFamily),
        textEncoder.encode(fullObjectHash),
        varUintBytes(chunkIndex, 'chunkIndex'),
        chunk,
    ]);

const setupProofChunkManifestRoot = (
    kernel: PrivateVssMailboxDeliveryKernel,
    proofFamily: string,
    chunkHashes: readonly ProtocolHash[],
    fullObjectHash: ProtocolHash,
    totalByteLength: number,
): ProtocolHash =>
    kernel.deriveProtocolHash({
        namespace: 'SetupProofChunkManifestRoot',
        value: {
            objectType: 'SetupProofMaterialChunkManifest',
            objectVersion: 1,
            setupProofProfileId,
            proofFamily,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: chunkHashes.length,
            totalByteLength,
            chunkHashes,
            fullObjectHash,
        },
    });

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
        validateSafeRosterPosition(position, `${entryLabel} roster position`);
        if (seenRosterPositions.has(position)) {
            throw new Error(`${entryLabel} roster positions must be distinct.`);
        }
        seenRosterPositions.add(position);
    }

    return sortedEntries;
};

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
    dealerState: PrivateVssDealerContributionState,
    recipient: PrivateVssMailboxRecipient,
    envelopeSequenceNumber: number,
): JsonRecord => ({
    objectType: privateEnvelopeAadObjectType,
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    mailboxEncryptionProfileId: privateVssMailboxEncryptionProfileId,
    privateEnvelopeObjectType,
    ciphertextContentType: privateEnvelopeDeliveryContentType,
    ceremonyId: input.setupContext.ceremonyId,
    manifestHash: input.setupContext.manifestHash,
    rosterHash: input.setupContext.rosterHash,
    setupProfileHash: input.setupContext.setupProfileHash,
    qShareHash: input.setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        input.setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: input.setupContext.commitmentProfileHash,
    setupEpoch: input.setupContext.setupEpoch,
    phaseOrderHash: input.phaseOrderHash,
    publicMatrixSeedHash: input.publicMatrixSeedHash,
    vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
    dealerIdentity: dealerState.dealerIdentity,
    dealerRosterPosition: dealerState.dealerRosterPosition,
    recipientIdentity: recipient.recipientIdentity,
    recipientRosterPosition: recipient.recipientRosterPosition,
    dealerCommitmentRoot: dealerState.dealerCommitmentRoot,
    envelopeSequenceNumber,
    deliveryPhaseNumber: input.deliveryPhaseNumber,
    verificationPhaseNumber: input.verificationPhaseNumber,
    recipientVerificationRequirement,
});

const transportPrivateVssShareProofMaterial = (
    kernel: PrivateVssMailboxDeliveryKernel,
    dealerState: PrivateVssDealerContributionState,
    proofRecord: JsonRecord,
): {
    readonly proofRecord: JsonRecord;
    readonly proofMaterial: TransportedPrivateVssShareProofMaterial;
} => {
    const proofBytesHex = assertString(
        proofRecord.proofBytesHex,
        'privateVssShareProof.proofBytesHex',
    );
    const proofBytes = hexToBytes(
        proofBytesHex,
        'privateVssShareProof.proofBytesHex',
    );
    const proofSizeBytes = assertNonNegativeSafeInteger(
        proofRecord.proofSizeBytes,
        'privateVssShareProof.proofSizeBytes',
    );
    if (proofSizeBytes !== proofBytes.byteLength) {
        throw new Error(
            'privateVssShareProof.proofSizeBytes must match proofBytesHex.',
        );
    }
    const proofBytesHash = assertProtocolHash(
        proofRecord.proofBytesHash,
        'privateVssShareProof.proofBytesHash',
    );
    const expectedProofBytesHash = hash512Hex(
        privateVssShareProofBytesHashDomain,
        [proofBytes],
    );
    if (proofBytesHash !== expectedProofBytesHash) {
        throw new Error(
            'privateVssShareProof.proofBytesHash must match proofBytesHex before transport.',
        );
    }
    const chunks = splitProofBytesIntoChunks(proofBytes);
    if (chunks.length === 0) {
        throw new Error(
            'privateVssShareProof proofBytesHex must produce at least one transported chunk.',
        );
    }
    const totalByteLength = chunks.reduce(
        (accumulatedLength, chunk) => accumulatedLength + chunk.byteLength,
        0,
    );
    const fullObjectHash = setupProofMaterialFullObjectHashHex(
        privateVssShareProofFamily,
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        setupProofMaterialChunkHash(
            privateVssShareProofFamily,
            fullObjectHash,
            chunkIndex,
            chunk,
        ),
    );
    const chunkRoot = setupProofChunkManifestRoot(
        kernel,
        privateVssShareProofFamily,
        chunkHashes,
        fullObjectHash,
        totalByteLength,
    );
    const statementHash = assertProtocolHash(
        proofRecord.statementHash,
        'privateVssShareProof.statementHash',
    );
    const relationCommitmentHash = assertProtocolHash(
        proofRecord.relationCommitmentHash,
        'privateVssShareProof.relationCommitmentHash',
    );
    const tboxCommitmentPrefixHash = assertProtocolHash(
        proofRecord.tboxCommitmentPrefixHash,
        'privateVssShareProof.tboxCommitmentPrefixHash',
    );
    const proofMaterialRoot = kernel.deriveProtocolHash({
        namespace: 'SetupProofMaterialRoot',
        value: {
            objectType: 'SetupProofMaterialReference',
            objectVersion: 1,
            setupProfileId,
            setupProofProfileId,
            proofFamily: privateVssShareProofFamily,
            proofBytesEncoding: transportedSetupProofMaterialEncoding,
            trusteeIdentity: dealerState.dealerIdentity,
            trusteeRosterPosition: dealerState.dealerRosterPosition,
            statementHash,
            relationCommitmentHash,
            tboxCommitmentPrefixHash,
            proofSizeBytes,
            proofBytesHash,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: chunkHashes.length,
            totalByteLength,
            fullObjectHash,
            chunkRoot,
            chunkHashes,
        },
    });
    const transportedProofRecord = { ...proofRecord };
    delete transportedProofRecord.proofBytesHex;
    transportedProofRecord.proofBytesEncoding =
        transportedSetupProofMaterialEncoding;
    transportedProofRecord.proofMaterialRoot = proofMaterialRoot;
    transportedProofRecord.proofChunkSizeBytes =
        setupProofTransportChunkSizeBytes;
    transportedProofRecord.proofChunkCount = chunkHashes.length;
    transportedProofRecord.proofTotalByteLength = totalByteLength;
    transportedProofRecord.proofFullObjectHash = fullObjectHash;
    transportedProofRecord.proofChunkRoot = chunkRoot;
    transportedProofRecord.proofChunkHashes = chunkHashes;

    return {
        proofRecord: transportedProofRecord,
        proofMaterial: {
            objectType: 'SetupTransportedPrivateVssShareProofMaterial',
            objectVersion: 1,
            setupProfileId,
            setupProofProfileId,
            proofFamily: privateVssShareProofFamily,
            proofMaterialRoot,
            chunkSizeBytes: setupProofTransportChunkSizeBytes,
            chunkCount: chunkHashes.length,
            totalByteLength,
            fullObjectHash,
            chunkHashes,
            chunkRoot,
            chunks: chunks.map((chunk, chunkIndex) => ({
                chunkIndex,
                bytesHex: bytesToHex(chunk),
            })),
        },
    };
};

type PrivateVssShareEnvelopeBuild = Readonly<{
    readonly privateEnvelope: JsonRecord;
    readonly transportedPrivateVssShareProofMaterial?: TransportedPrivateVssShareProofMaterialSet;
}>;

const privateEnvelope = (
    input: PrivateVssMailboxDeliveryContext,
    dealerState: PrivateVssDealerContributionState,
    recipient: PrivateVssMailboxRecipient,
    privateEnvelopeAadHash: ProtocolHash,
): PrivateVssShareEnvelopeBuild => {
    const proofMaterialEncoding =
        input.privateVssShareProofMaterialEncoding ??
        embeddedPrivateVssShareProofBytesEncoding;
    if (
        proofMaterialEncoding !== embeddedPrivateVssShareProofBytesEncoding &&
        proofMaterialEncoding !== transportedSetupProofMaterialEncoding
    ) {
        throw new Error(
            'privateVssShareProofMaterialEncoding must be embedded-binary-proof-bytes-hex or binary-chunked-proof-bytes.',
        );
    }
    const transportedProofMaterials: TransportedPrivateVssShareProofMaterial[] =
        [];
    const rnsShareOpenings = input.qSharePrimes.map(
        (rnsPrime, rnsLimbIndex) => {
            const coefficientOpenings = dealerState.coefficientOpenings
                .filter(
                    (opening) =>
                        opening.rnsLimbIndex === rnsLimbIndex &&
                        opening.rnsPrime === rnsPrime,
                )
                .sort(
                    (left, right) =>
                        left.shamirCoefficientIndex -
                        right.shamirCoefficientIndex,
                );
            if (coefficientOpenings.length === 0) {
                throw new Error(
                    'Dealer local VSS state must contain every Q_share limb.',
                );
            }
            const coefficientMessagesByShamirIndex = coefficientOpenings.map(
                (opening) => {
                    if (
                        opening.coefficientMessage.length !== input.ringDegree
                    ) {
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
            const proofFactoryInput = {
                setupContext: input.setupContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                privateEnvelopeAadHash,
                dealerContributionState: dealerState,
                recipient,
                rnsLimbIndex,
                rnsPrime,
                ringDegree: input.ringDegree,
                shareValues,
                coefficientCommitmentRoots,
            };
            const generatedPrivateVssShareProof =
                input.privateVssShareProofFactory?.(proofFactoryInput) ??
                (() => {
                    if (
                        input.kernel.generatePrivateVssShareProof ===
                            undefined ||
                        input.privateVssShareProofRandomnessFactory ===
                            undefined
                    ) {
                        throw new Error(
                            'Private VSS mailbox delivery requires recipient-local zero-knowledge privateVssShareProof generation; plaintext aggregate openings and carry witnesses are refused.',
                        );
                    }
                    const proofRandomness =
                        input.privateVssShareProofRandomnessFactory(
                            proofFactoryInput,
                        );
                    const generatedProof =
                        input.kernel.generatePrivateVssShareProof({
                            setupContext: input.setupContext,
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            privateEnvelopeAadHash,
                            dealerCoefficientCommitmentRecord:
                                dealerState.dealerCoefficientCommitmentRecord,
                            dealerCoefficientCommitmentMaterialRecords:
                                dealerState.dealerCoefficientCommitmentMaterialRecords,
                            recipientIdentity: recipient.recipientIdentity,
                            recipientRosterPosition:
                                recipient.recipientRosterPosition,
                            rnsLimbIndex,
                            rnsPrime,
                            ringDegree: input.ringDegree,
                            shareValues,
                            coefficientCommitmentRoots,
                            coefficientMessagesByShamirIndex,
                            openingRandomnessByShamirIndex:
                                coefficientOpenings.map(
                                    (opening) => opening.randomnessByColumn,
                                ),
                            proofRandomnessSource: proofRandomness.source,
                            proofRandomnessSeedHex: proofRandomness.seedHex,
                        });

                    return generatedProof.privateVssShareProof;
                })();
            const privateVssShareProof =
                proofMaterialEncoding === transportedSetupProofMaterialEncoding
                    ? (() => {
                          const transportedProof =
                              transportPrivateVssShareProofMaterial(
                                  input.kernel,
                                  dealerState,
                                  generatedPrivateVssShareProof,
                              );
                          transportedProofMaterials.push(
                              transportedProof.proofMaterial,
                          );

                          return transportedProof.proofRecord;
                      })()
                    : generatedPrivateVssShareProof;

            return {
                objectType: 'PrivateVssShareLimbOpening',
                objectVersion: 1,
                rnsLimbIndex,
                rnsPrime,
                shareValues,
                coefficientCommitmentRoots,
                privateVssShareProof,
            };
        },
    );

    const privateShareEnvelope = {
        objectType: privateEnvelopeObjectType,
        objectVersion: 1,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        privateEnvelopeAadHash,
        dealerIdentity: dealerState.dealerIdentity,
        dealerRosterPosition: dealerState.dealerRosterPosition,
        recipientIdentity: recipient.recipientIdentity,
        recipientRosterPosition: recipient.recipientRosterPosition,
        dealerCommitmentRoot: dealerState.dealerCommitmentRoot,
        rnsShareOpenings,
    };

    if (transportedProofMaterials.length === 0) {
        return { privateEnvelope: privateShareEnvelope };
    }

    return {
        privateEnvelope: privateShareEnvelope,
        transportedPrivateVssShareProofMaterial: {
            objectType: 'SetupTransportedPrivateVssShareProofMaterialSet',
            objectVersion: 1,
            setupProfileId,
            setupProofProfileId,
            proofFamily: privateVssShareProofFamily,
            proofMaterials: transportedProofMaterials,
        },
    };
};

const createEnvelopeCommitment = async (
    input: PrivateVssMailboxDeliveryContext,
    dealerState: PrivateVssDealerContributionState,
    recipient: PrivateVssMailboxRecipient,
): Promise<PrivateVssEnvelopeCommitment> => {
    const envelopeSequenceNumber =
        dealerState.dealerRosterPosition * input.participantCount +
        recipient.recipientRosterPosition;
    const associatedData = privateEnvelopeAad(
        input,
        dealerState,
        recipient,
        envelopeSequenceNumber,
    );
    const associatedDataHash = input.kernel.deriveProtocolHash({
        namespace: 'PrivateVssEnvelopeAadHash',
        value: associatedData,
    });
    const privateShareEnvelopeBuild = privateEnvelope(
        input,
        dealerState,
        recipient,
        associatedDataHash,
    );
    const localVerification = input.kernel.verifyPrivateVssShareEnvelope({
        setupContext: input.setupContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        dealerCoefficientCommitmentRecord:
            dealerState.dealerCoefficientCommitmentRecord,
        dealerCoefficientCommitmentMaterialRecords:
            dealerState.dealerCoefficientCommitmentMaterialRecords,
        privateEnvelope: privateShareEnvelopeBuild.privateEnvelope,
        ...(privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial ===
        undefined
            ? {}
            : {
                  transportedPrivateVssShareProofMaterial:
                      privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial,
              }),
    });
    if (
        !localVerification.ok ||
        localVerification.privateEnvelopeHash === null ||
        localVerification.localVerificationRoot === null
    ) {
        const refusal = localVerification.refusedObjects[0];
        throw new Error(
            refusal === undefined
                ? 'Private VSS envelope failed local verification.'
                : `Private VSS envelope failed local verification: ${refusal.reasonCode}: ${refusal.message}`,
        );
    }
    const encryptedDelivery = await encryptPrivateVssMailboxEnvelope({
        privateEnvelope: privateShareEnvelopeBuild.privateEnvelope,
        privateEnvelopeAad: associatedData,
        recipientMailboxPublicKeyBytesHex: recipient.mailboxPublicKeyBytesHex,
    });
    if (
        encryptedDelivery.privateEnvelopeHash !==
            localVerification.privateEnvelopeHash ||
        encryptedDelivery.privateEnvelopeAadHash !== associatedDataHash
    ) {
        throw new Error(
            'Private VSS mailbox encryption did not preserve the verified envelope binding.',
        );
    }

    const commitmentWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitment',
        objectVersion: 1,
        mailboxEncryptionProfileId: privateVssMailboxEncryptionProfileId,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        dealerIdentity: dealerState.dealerIdentity,
        dealerRosterPosition: dealerState.dealerRosterPosition,
        recipientIdentity: recipient.recipientIdentity,
        recipientRosterPosition: recipient.recipientRosterPosition,
        dealerCommitmentRoot: dealerState.dealerCommitmentRoot,
        envelopeSequenceNumber,
        deliveryPhaseNumber: input.deliveryPhaseNumber,
        verificationPhaseNumber: input.verificationPhaseNumber,
        privateEnvelopeHash: localVerification.privateEnvelopeHash,
        encryptedEnvelopeHash:
            encryptedDelivery.encryptedEnvelope.encryptedEnvelopeHash,
        privateEnvelopeAad: associatedData,
        privateEnvelopeAadHash: associatedDataHash,
        encryptedEnvelope: encryptedDelivery.encryptedEnvelope,
        recipientMailboxPublicKeyHash:
            encryptedDelivery.encryptedEnvelope.recipientMailboxPublicKeyHash,
        localVerificationRoot: localVerification.localVerificationRoot,
        ...(privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial ===
        undefined
            ? {}
            : {
                  transportedPrivateVssShareProofMaterial:
                      privateShareEnvelopeBuild.transportedPrivateVssShareProofMaterial,
              }),
        openingVerificationStatus: localOpeningAcceptedStatus,
    } as const satisfies JsonRecord;

    return {
        ...commitmentWithoutRoot,
        privateEnvelopeCommitmentRoot: input.kernel.deriveProtocolHash({
            namespace: 'PrivateVssEnvelopeCommitmentRoot',
            value: privateVssEnvelopeCommitmentRootInput(commitmentWithoutRoot),
        }),
    } satisfies PrivateVssEnvelopeCommitment;
};

export const createPrivateVssMailboxDealerDeliveryReferences = async (
    input: PrivateVssMailboxDealerDeliveryInput,
): Promise<readonly PrivateVssEnvelopeCommitment[]> => {
    validatePositiveSafeInteger(input.participantCount, 'participantCount');
    validatePositiveSafeInteger(input.ringDegree, 'ringDegree');
    validateSafeRosterPosition(
        input.dealerContributionState.dealerRosterPosition,
        'dealer contribution state roster position',
    );
    if (
        input.dealerContributionState.dealerRosterPosition >=
        input.participantCount
    ) {
        throw new Error(
            'dealer contribution state roster position must be inside the accepted participant count.',
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

    return Promise.all(
        recipients.map((recipient) =>
            createEnvelopeCommitment(
                input,
                input.dealerContributionState,
                recipient,
            ),
        ),
    );
};

export const createPrivateVssMailboxDeliverySet = async (
    input: PrivateVssMailboxDeliverySetInput,
): Promise<PrivateVssMailboxDeliverySet> => {
    validatePositiveSafeInteger(input.participantCount, 'participantCount');
    validatePositiveSafeInteger(input.ringDegree, 'ringDegree');
    const dealerStates = sortedByRosterPosition(
        input.dealerContributionStates,
        (dealerState) => dealerState.dealerRosterPosition,
        'dealer contribution state',
    );
    const recipients = sortedByRosterPosition(
        input.recipients,
        (recipient) => recipient.recipientRosterPosition,
        'mailbox recipient',
    );
    assertFullRosterPositions(
        dealerStates.map((dealerState) => dealerState.dealerRosterPosition),
        input.participantCount,
        'dealer contribution state',
    );
    assertFullRosterPositions(
        recipients.map((recipient) => recipient.recipientRosterPosition),
        input.participantCount,
        'mailbox recipient',
    );

    const envelopeReferences = (
        await Promise.all(
            dealerStates.map((dealerContributionState) =>
                createPrivateVssMailboxDealerDeliveryReferences({
                    ...input,
                    dealerContributionState,
                    recipients,
                }),
            ),
        )
    ).flat();

    const commitmentSetWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitmentSet',
        objectVersion: 1,
        mailboxEncryptionProfileId: privateVssMailboxEncryptionProfileId,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        participantCount: input.participantCount,
        envelopeCount: input.participantCount * input.participantCount,
        deliveryPhaseNumber: input.deliveryPhaseNumber,
        verificationPhaseNumber: input.verificationPhaseNumber,
        envelopeReferences,
    } as const satisfies JsonRecord;

    return {
        ...commitmentSetWithoutRoot,
        privateVssEnvelopeCommitmentRoot: input.kernel.deriveProtocolHash({
            namespace: 'PrivateVssEnvelopeCommitmentRoot',
            value: privateVssEnvelopeCommitmentSetRootInput(
                commitmentSetWithoutRoot,
            ),
        }),
    } satisfies PrivateVssMailboxDeliverySet;
};
