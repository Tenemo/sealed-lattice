import {
    canonicalJson,
    deriveCanonicalObjectHash,
    hash512Hex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { setupProofTransportChunkSizeBytes } from '../setup-proof-material-transport.js';

import {
    type BinaryChunkedPublicEvaluationKeyMaterialTransport,
    type GaloisKeyContributingShareRoot,
    type GaloisKeyRootReference,
    type GaloisKeyShareBatch,
    type GaloisKeyShareBatchRootReference,
    type GaloisKeyShareMaterialRecord,
    type JsonRecord,
    type PublicEvaluationKeyMaterialReference,
    type PublicEvaluationKeyMaterialTransportInput,
    type PublicEvaluationKeySet,
    type PublicEvaluationKeySetInput,
    type RelinearizationKeyRootReference,
    type RelinearizationKeyShareRounds,
    type TransportedPublicEvaluationKeyMaterialSet,
    evaluationKeyShareComponentMaterialEncoding,
    publicEvaluationKeyMaterialEncoding,
    publicEvaluationKeyMaterialMagic,
    publicEvaluationKeyMaterialTransportObjectType,
    publicEvaluationKeyMaterialTransportSetObjectType,
    publicEvaluationKeyTransportMaterialEncoding,
    textEncoder,
} from './constants-and-types.js';
import {
    assertPositiveSafeInteger,
    assertProtocolHash,
    bytesToHex,
    u64LittleEndianBytes,
} from './encoding.js';
import {
    assertContextMatches,
    contextFields,
    validateCommonInput,
} from './share-records.js';

const galoisShareMaterialForSchedule = (
    batch: GaloisKeyShareBatch,
    rotation: number,
    level: number,
): GaloisKeyShareMaterialRecord => {
    const materialRecords = batch.galoisKeyShareMaterialRecords.filter(
        (materialRecord) =>
            materialRecord.rotation === rotation &&
            materialRecord.level === level,
    );
    if (materialRecords.length !== 1) {
        throw new Error(
            'galoisKeyShareBatches is missing a scheduled material record.',
        );
    }

    return materialRecords[0];
};

export function createPublicEvaluationKeySet(
    input: PublicEvaluationKeySetInput,
): PublicEvaluationKeySet {
    validateCommonInput(input);
    assertContextMatches(
        input.setupContext,
        input.relinearizationKeyShareRounds,
        'relinearizationKeyShareRounds',
    );
    if (
        input.relinearizationKeyShareRounds.evaluatorKeyScheduleRoot !==
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot ||
        input.relinearizationKeyShareRounds.sameSecretProofFamilyBindingRoot !==
            input.sameSecretProofFamilyBindingRoot ||
        input.relinearizationKeyShareRounds
            .publicKeyShareSuccinctProofSetRoot !==
            input.publicKeyShareSuccinctProofSetRoot
    ) {
        throw new Error(
            'relinearizationKeyShareRounds must match the accepted evaluation-key binding.',
        );
    }
    const roundOneAggregateRootByLevel = new Map(
        input.relinearizationKeyShareRounds.roundOneAggregateRoots.map(
            (entry) => [entry.level, entry.roundOneAggregateRoot] as const,
        ),
    );
    const roundTwoAggregateRootByLevel = new Map(
        input.relinearizationKeyShareRounds.roundTwoAggregateRoots.map(
            (entry) => [entry.level, entry.roundTwoAggregateRoot] as const,
        ),
    );
    const relinearizationKeyRoots =
        input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
            (scheduleEntry) => {
                const { level } = scheduleEntry;
                const roundOneAggregateRoot =
                    roundOneAggregateRootByLevel.get(level);
                const roundTwoAggregateRoot =
                    roundTwoAggregateRootByLevel.get(level);
                if (
                    roundOneAggregateRoot === undefined ||
                    roundTwoAggregateRoot === undefined
                ) {
                    throw new Error(
                        'relinearizationKeyShareRounds is missing a scheduled aggregate root.',
                    );
                }
                const decompositionDigitCount = level + 1;
                const relinearizationKeyRoot = deriveCanonicalObjectHash({
                    objectType: 'RelinearizationKeyAggregate',
                    materialEncoding: publicEvaluationKeyMaterialEncoding,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareSuccinctProofSetRoot:
                        input.publicKeyShareSuccinctProofSetRoot,
                    relinearizationKeyShareRoundsRoot:
                        input.relinearizationKeyShareRounds
                            .relinearizationKeyShareRoundsRoot,
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    roundOneAggregateRoot,
                    roundTwoAggregateRoot,
                });

                return {
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    roundOneAggregateRoot,
                    roundTwoAggregateRoot,
                    relinearizationKeyRoot,
                } satisfies RelinearizationKeyRootReference;
            },
        );

    const sortedGaloisBatches = [...input.galoisKeyShareBatches].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (sortedGaloisBatches.length !== input.participantCount) {
        throw new Error(
            'galoisKeyShareBatches must contain one batch per participant.',
        );
    }
    sortedGaloisBatches.forEach((batch, expectedRosterPosition) => {
        assertContextMatches(input.setupContext, batch, 'galoisKeyShareBatch');
        if (batch.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'galoisKeyShareBatches roster positions must be contiguous from zero.',
            );
        }
        if (
            batch.evaluatorKeyScheduleRoot !==
                input.evaluatorKeySchedule.evaluatorKeyScheduleRoot ||
            batch.sameSecretProofFamilyBindingRoot !==
                input.sameSecretProofFamilyBindingRoot ||
            batch.publicKeyShareSuccinctProofSetRoot !==
                input.publicKeyShareSuccinctProofSetRoot ||
            batch.requiredGaloisSetHash !==
                input.evaluatorKeySchedule.requiredGaloisSetHash
        ) {
            throw new Error(
                'galoisKeyShareBatches must match the accepted evaluation-key binding.',
            );
        }
    });
    const galoisKeyShareBatchRoots = sortedGaloisBatches.map((batch) => ({
        trusteeIdentity: batch.trusteeIdentity,
        trusteeRosterPosition: batch.trusteeRosterPosition,
        galoisKeyShareBatchRoot: batch.galoisKeyShareBatchRoot,
    })) satisfies GaloisKeyShareBatchRootReference[];
    const galoisKeyRoots =
        input.evaluatorKeySchedule.requiredGaloisKeySchedule.map(
            (scheduleEntry) => {
                const { rotation, level } = scheduleEntry;
                const decompositionDigitCount = level + 1;
                const contributingShareRoots = sortedGaloisBatches.map(
                    (batch) => {
                        const materialRecord = galoisShareMaterialForSchedule(
                            batch,
                            rotation,
                            level,
                        );

                        return {
                            trusteeIdentity: batch.trusteeIdentity,
                            trusteeRosterPosition: batch.trusteeRosterPosition,
                            galoisKeyShareRoot:
                                materialRecord.galoisKeyShareRoot,
                        } satisfies GaloisKeyContributingShareRoot;
                    },
                );
                const galoisKeyRoot = deriveCanonicalObjectHash({
                    objectType: 'GaloisKeyAggregate',
                    materialEncoding: publicEvaluationKeyMaterialEncoding,
                    evaluatorKeyScheduleRoot:
                        input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                    publicKeyShareSuccinctProofSetRoot:
                        input.publicKeyShareSuccinctProofSetRoot,
                    galoisKeyCrpRoot:
                        input.evaluatorKeySchedule.galoisKeyCrpRoot,
                    requiredGaloisSetHash:
                        input.evaluatorKeySchedule.requiredGaloisSetHash,
                    rotation,
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    contributingShareRoots,
                });

                return {
                    rotation,
                    level,
                    decompositionDigitCount,
                    rnsLimbCount: decompositionDigitCount,
                    galoisKeyRoot,
                    contributingShareRoots,
                } satisfies GaloisKeyRootReference;
            },
        );
    if (input.publicEvaluationKeyMaterialReference !== undefined) {
        const reference = input.publicEvaluationKeyMaterialReference;
        if (
            reference.publicEvaluationKeyMaterialEncoding !==
            publicEvaluationKeyTransportMaterialEncoding
        ) {
            throw new Error(
                'publicEvaluationKeyMaterialReference uses an unsupported material encoding.',
            );
        }
        assertProtocolHash(
            reference.publicEvaluationKeyMaterialRoot,
            'publicEvaluationKeyMaterialRoot',
        );
        assertProtocolHash(
            reference.publicEvaluationKeyMaterialFullObjectHash,
            'publicEvaluationKeyMaterialFullObjectHash',
        );
        assertProtocolHash(
            reference.publicEvaluationKeyMaterialChunkRoot,
            'publicEvaluationKeyMaterialChunkRoot',
        );
        assertPositiveSafeInteger(
            reference.publicEvaluationKeyMaterialChunkSizeBytes,
            'publicEvaluationKeyMaterialChunkSizeBytes',
        );
        assertPositiveSafeInteger(
            reference.publicEvaluationKeyMaterialChunkCount,
            'publicEvaluationKeyMaterialChunkCount',
        );
        assertPositiveSafeInteger(
            reference.publicEvaluationKeyMaterialTotalByteLength,
            'publicEvaluationKeyMaterialTotalByteLength',
        );
        if (
            reference.publicEvaluationKeyMaterialChunkHashes.length !==
            reference.publicEvaluationKeyMaterialChunkCount
        ) {
            throw new Error(
                'publicEvaluationKeyMaterialChunkHashes must match publicEvaluationKeyMaterialChunkCount.',
            );
        }
        reference.publicEvaluationKeyMaterialChunkHashes.forEach(
            (chunkHash, chunkIndex) => {
                assertProtocolHash(
                    chunkHash,
                    `publicEvaluationKeyMaterialChunkHashes[${chunkIndex}]`,
                );
            },
        );
    }

    const evaluationKeysWithoutHash = {
        objectType: 'PublicEvaluationKeySet',
        materialEncoding: publicEvaluationKeyMaterialEncoding,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretProofFamilyBindingRoot,
        publicKeyShareSuccinctProofSetRoot:
            input.publicKeyShareSuccinctProofSetRoot,
        relinearizationKeyShareRoundsRoot:
            input.relinearizationKeyShareRounds
                .relinearizationKeyShareRoundsRoot,
        relinearizationLevelSchedule:
            input.evaluatorKeySchedule.relinearizationLevelSchedule,
        relinearizationKeyRoots,
        requiredGaloisSetHash: input.evaluatorKeySchedule.requiredGaloisSetHash,
        requiredGaloisKeySchedule:
            input.evaluatorKeySchedule.requiredGaloisKeySchedule,
        galoisKeyShareBatchRoots,
        galoisKeyRoots,
        ...(input.publicEvaluationKeyMaterialReference ?? {}),
        // Carry an optional committed-material aggregate binding through verbatim
        // so it enters the canonical evaluationKeySetHash the same object the
        // kernel recomputes over. Absent by default.
        ...(input.aggregateBinding === undefined
            ? {}
            : { aggregateBinding: input.aggregateBinding }),
    } as const satisfies Omit<PublicEvaluationKeySet, 'evaluationKeySetHash'>;

    return {
        ...evaluationKeysWithoutHash,
        evaluationKeySetHash: deriveCanonicalObjectHash(
            evaluationKeysWithoutHash,
        ),
    } satisfies PublicEvaluationKeySet;
}

const relinearizationShareMaterialManifest = (
    relinearizationKeyShareRounds: RelinearizationKeyShareRounds,
): readonly JsonRecord[] => {
    const entries: {
        readonly level: number;
        readonly roundOrder: number;
        readonly trusteeRosterPosition: number;
        readonly entry: JsonRecord;
    }[] = [];
    const recordGroups = [
        {
            round: 'round-one',
            roundOrder: 0,
            records: relinearizationKeyShareRounds.roundOneRecords,
            shareRootFieldName: 'roundOneShareRoot',
            recordRootFieldName: 'roundOneRecordRoot',
        },
        {
            round: 'round-two',
            roundOrder: 1,
            records: relinearizationKeyShareRounds.roundTwoRecords,
            shareRootFieldName: 'roundTwoShareRoot',
            recordRootFieldName: 'roundTwoRecordRoot',
        },
    ] as const;

    recordGroups.forEach((group) => {
        group.records.forEach((record) => {
            const recordFields = record as JsonRecord;
            entries.push({
                level: record.level,
                roundOrder: group.roundOrder,
                trusteeRosterPosition: record.trusteeRosterPosition,
                entry: {
                    round: group.round,
                    trusteeIdentity: record.trusteeIdentity,
                    trusteeRosterPosition: record.trusteeRosterPosition,
                    level: record.level,
                    keySwitchMaterialEncoding: record.keySwitchMaterialEncoding,
                    keySwitchDomain: record.keySwitchDomain,
                    keySwitchSeedHex: record.keySwitchSeedHex,
                    keySwitchComponentVectorRoot:
                        record.keySwitchComponentVectorRoot,
                    keySwitchComponentMaterialRoot:
                        recordFields.keySwitchComponentMaterialRoot ?? null,
                    shareRoot: recordFields[group.shareRootFieldName],
                    recordRoot: recordFields[group.recordRootFieldName],
                },
            });
        });
    });

    return entries
        .sort(
            (left, right) =>
                left.level - right.level ||
                left.roundOrder - right.roundOrder ||
                left.trusteeRosterPosition - right.trusteeRosterPosition,
        )
        .map((entry) => entry.entry);
};

const galoisShareMaterialManifest = (
    galoisKeyShareBatches: readonly GaloisKeyShareBatch[],
): readonly JsonRecord[] => {
    const entries: {
        readonly rotation: number;
        readonly level: number;
        readonly trusteeRosterPosition: number;
        readonly entry: JsonRecord;
    }[] = [];
    galoisKeyShareBatches.forEach((batch) => {
        batch.galoisKeyShareMaterialRecords.forEach((materialRecord) => {
            const materialFields = materialRecord as JsonRecord;
            entries.push({
                rotation: materialRecord.rotation,
                level: materialRecord.level,
                trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                entry: {
                    trusteeIdentity: materialRecord.trusteeIdentity,
                    trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                    rotation: materialRecord.rotation,
                    level: materialRecord.level,
                    keySwitchMaterialEncoding:
                        materialRecord.keySwitchMaterialEncoding,
                    keySwitchDomain: materialRecord.keySwitchDomain,
                    keySwitchSeedHex: materialRecord.keySwitchSeedHex,
                    keySwitchComponentVectorRoot:
                        materialRecord.keySwitchComponentVectorRoot,
                    keySwitchComponentMaterialRoot:
                        materialFields.keySwitchComponentMaterialRoot ?? null,
                    galoisKeyShareRoot: materialRecord.galoisKeyShareRoot,
                },
            });
        });
    });

    return entries
        .sort(
            (left, right) =>
                left.rotation - right.rotation ||
                left.level - right.level ||
                left.trusteeRosterPosition - right.trusteeRosterPosition,
        )
        .map((entry) => entry.entry);
};

const publicEvaluationKeyMaterialManifest = (
    input: PublicEvaluationKeyMaterialTransportInput,
    evaluationKeys: PublicEvaluationKeySet,
): JsonRecord => ({
    objectType: 'PublicEvaluationKeyMaterialManifest',
    materialEncoding: publicEvaluationKeyMaterialEncoding,
    materialTransportEncoding: publicEvaluationKeyTransportMaterialEncoding,
    ...contextFields(input.setupContext),
    participantCount: input.participantCount,
    rnsLimbCount: input.qSharePrimes.length,
    evaluatorKeyScheduleRoot: evaluationKeys.evaluatorKeyScheduleRoot,
    sameSecretProofFamilyBindingRoot:
        evaluationKeys.sameSecretProofFamilyBindingRoot,
    publicKeyShareSuccinctProofSetRoot:
        evaluationKeys.publicKeyShareSuccinctProofSetRoot,
    relinearizationKeyShareRoundsRoot:
        evaluationKeys.relinearizationKeyShareRoundsRoot,
    relinearizationLevelSchedule: evaluationKeys.relinearizationLevelSchedule,
    relinearizationKeyRoots: evaluationKeys.relinearizationKeyRoots,
    relinearizationShareMaterialRoots: relinearizationShareMaterialManifest(
        input.relinearizationKeyShareRounds,
    ),
    requiredGaloisSetHash: evaluationKeys.requiredGaloisSetHash,
    requiredGaloisKeySchedule: evaluationKeys.requiredGaloisKeySchedule,
    galoisKeyShareBatchRoots: evaluationKeys.galoisKeyShareBatchRoots,
    galoisKeyRoots: evaluationKeys.galoisKeyRoots,
    galoisShareMaterialRoots: galoisShareMaterialManifest(
        input.galoisKeyShareBatches,
    ),
});

const encodePublicEvaluationKeyMaterialManifest = (
    manifest: JsonRecord,
): Uint8Array => {
    const manifestBytes = textEncoder.encode(canonicalJson(manifest));
    const materialBytes = new Uint8Array(
        publicEvaluationKeyMaterialMagic.byteLength + manifestBytes.byteLength,
    );
    materialBytes.set(publicEvaluationKeyMaterialMagic, 0);
    materialBytes.set(manifestBytes, publicEvaluationKeyMaterialMagic.length);

    return materialBytes;
};

const publicEvaluationKeyMaterialChunks = (
    materialBytes: Uint8Array,
): readonly Uint8Array[] => {
    if (materialBytes.byteLength === 0) {
        throw new Error(
            'public evaluation-key material transport requires bytes.',
        );
    }
    const chunks: Uint8Array[] = [];
    for (
        let byteOffset = 0;
        byteOffset < materialBytes.byteLength;
        byteOffset += setupProofTransportChunkSizeBytes
    ) {
        chunks.push(
            materialBytes.slice(
                byteOffset,
                byteOffset + setupProofTransportChunkSizeBytes,
            ),
        );
    }

    return chunks;
};

const publicEvaluationKeyMaterialFullObjectHash = (
    totalByteLength: number,
    chunks: readonly Uint8Array[],
): ProtocolHash =>
    hash512Hex(
        'sealed-lattice/setup/public-evaluation-key-material/full-object',
        [u64LittleEndianBytes(totalByteLength, 'totalByteLength'), ...chunks],
    );

const publicEvaluationKeyMaterialChunkHash = (
    fullObjectHash: ProtocolHash,
    chunkIndex: number,
    chunk: Uint8Array,
): ProtocolHash =>
    hash512Hex('sealed-lattice/setup/public-evaluation-key-material/chunk', [
        textEncoder.encode(fullObjectHash),
        u64LittleEndianBytes(chunkIndex, 'chunkIndex'),
        chunk,
    ]);

const publicEvaluationKeyMaterialTransportHashes = (
    chunks: readonly Uint8Array[],
): Readonly<{
    readonly fullObjectHash: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly chunkRoot: ProtocolHash;
    readonly totalByteLength: number;
}> => {
    if (chunks.length === 0) {
        throw new Error(
            'public evaluation-key material transport requires at least one chunk.',
        );
    }
    const totalByteLength = chunks.reduce((byteLength, chunk, chunkIndex) => {
        if (chunk.byteLength === 0) {
            throw new Error(
                'public evaluation-key material chunks must be non-empty.',
            );
        }
        if (chunk.byteLength > setupProofTransportChunkSizeBytes) {
            throw new Error(
                'public evaluation-key material chunk exceeds the accepted chunk size.',
            );
        }
        if (
            chunkIndex + 1 < chunks.length &&
            chunk.byteLength !== setupProofTransportChunkSizeBytes
        ) {
            throw new Error(
                'public evaluation-key material contains a short non-final chunk.',
            );
        }

        return byteLength + chunk.byteLength;
    }, 0);
    const fullObjectHash = publicEvaluationKeyMaterialFullObjectHash(
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        publicEvaluationKeyMaterialChunkHash(fullObjectHash, chunkIndex, chunk),
    );
    const chunkRoot = deriveCanonicalObjectHash({
        objectType: 'PublicEvaluationKeyMaterialChunkManifest',
        materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
        chunkCount: chunkHashes.length,
        totalByteLength,
        chunkHashes,
        fullObjectHash,
    });

    return {
        fullObjectHash,
        chunkHashes,
        chunkRoot,
        totalByteLength,
    };
};

const publicEvaluationKeyMaterialReferenceRoot = (
    evaluationKeys: PublicEvaluationKeySet,
    expectedMaterialManifest: JsonRecord,
    transportHashes: ReturnType<
        typeof publicEvaluationKeyMaterialTransportHashes
    >,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'PublicEvaluationKeyMaterialReference',
        materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
        ceremonyId: evaluationKeys.ceremonyId,
        manifestHash: evaluationKeys.manifestHash,
        rosterHash: evaluationKeys.rosterHash,
        setupParametersHash: evaluationKeys.setupParametersHash,
        setupEpoch: evaluationKeys.setupEpoch,
        evaluatorKeyScheduleRoot: evaluationKeys.evaluatorKeyScheduleRoot,
        sameSecretProofFamilyBindingRoot:
            evaluationKeys.sameSecretProofFamilyBindingRoot,
        publicKeyShareSuccinctProofSetRoot:
            evaluationKeys.publicKeyShareSuccinctProofSetRoot,
        relinearizationKeyShareRoundsRoot:
            evaluationKeys.relinearizationKeyShareRoundsRoot,
        requiredGaloisSetHash: evaluationKeys.requiredGaloisSetHash,
        expectedMaterialManifest,
        chunkCount: transportHashes.chunkHashes.length,
        totalByteLength: transportHashes.totalByteLength,
        fullObjectHash: transportHashes.fullObjectHash,
        chunkRoot: transportHashes.chunkRoot,
        chunkHashes: transportHashes.chunkHashes,
    });

const expectedPublicEvaluationKeyComponentMaterialRoots = (
    input: PublicEvaluationKeyMaterialTransportInput,
): ReadonlySet<ProtocolHash> => {
    const roots = new Set<ProtocolHash>();
    const collectRoot = (record: JsonRecord): void => {
        if (
            record.keySwitchMaterialEncoding !==
            evaluationKeyShareComponentMaterialEncoding
        ) {
            return;
        }
        const root = record.keySwitchComponentMaterialRoot;
        if (typeof root !== 'string') {
            throw new TypeError(
                'binary evaluation-key share records must carry keySwitchComponentMaterialRoot.',
            );
        }
        assertProtocolHash(root, 'keySwitchComponentMaterialRoot');
        roots.add(root);
    };

    input.relinearizationKeyShareRounds.roundOneRecords.forEach((record) =>
        collectRoot(record),
    );
    input.relinearizationKeyShareRounds.roundTwoRecords.forEach((record) =>
        collectRoot(record),
    );
    input.galoisKeyShareBatches.forEach((batch) =>
        batch.galoisKeyShareMaterialRecords.forEach((materialRecord) =>
            collectRoot(materialRecord),
        ),
    );

    return roots;
};

const assertPublicEvaluationKeyComponentMaterialCoverage = (
    input: PublicEvaluationKeyMaterialTransportInput,
): void => {
    const expectedRoots =
        expectedPublicEvaluationKeyComponentMaterialRoots(input);
    const componentMaterials =
        input.transportedEvaluationKeyShareComponentMaterial
            ?.componentMaterials ?? [];
    if (expectedRoots.size === 0) {
        if (componentMaterials.length !== 0) {
            throw new Error(
                'transportedEvaluationKeyShareComponentMaterial must not be supplied when evaluation-key records do not use binary component material.',
            );
        }

        return;
    }
    if (componentMaterials.length === 0) {
        throw new Error(
            'transportedEvaluationKeyShareComponentMaterial is required for binary evaluation-key component material.',
        );
    }

    const suppliedRoots = new Set<ProtocolHash>();
    componentMaterials.forEach((componentMaterial, componentIndex) => {
        const materialRoot = componentMaterial.keySwitchComponentMaterialRoot;
        if (typeof materialRoot !== 'string') {
            throw new TypeError(
                `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(componentIndex)}.keySwitchComponentMaterialRoot must be a protocol hash.`,
            );
        }
        assertProtocolHash(
            materialRoot,
            `transportedEvaluationKeyShareComponentMaterial.componentMaterials.${String(componentIndex)}.keySwitchComponentMaterialRoot`,
        );
        if (suppliedRoots.has(materialRoot)) {
            throw new Error(
                'transportedEvaluationKeyShareComponentMaterial contains duplicate key-switch component material roots.',
            );
        }
        suppliedRoots.add(materialRoot);
    });
    if (
        suppliedRoots.size !== expectedRoots.size ||
        [...expectedRoots].some(
            (expectedRoot) => !suppliedRoots.has(expectedRoot),
        )
    ) {
        throw new Error(
            'transportedEvaluationKeyShareComponentMaterial must cover every binary evaluation-key component material root.',
        );
    }
};

export const createBinaryChunkedPublicEvaluationKeyMaterialTransport = (
    input: PublicEvaluationKeyMaterialTransportInput,
): BinaryChunkedPublicEvaluationKeyMaterialTransport => {
    const evaluationKeysWithoutMaterialReference =
        createPublicEvaluationKeySet(input);
    const manifest = publicEvaluationKeyMaterialManifest(
        input,
        evaluationKeysWithoutMaterialReference,
    );
    const materialBytes = encodePublicEvaluationKeyMaterialManifest(manifest);
    const chunks = publicEvaluationKeyMaterialChunks(materialBytes);
    const transportHashes = publicEvaluationKeyMaterialTransportHashes(chunks);
    const publicEvaluationKeyMaterialRoot =
        publicEvaluationKeyMaterialReferenceRoot(
            evaluationKeysWithoutMaterialReference,
            manifest,
            transportHashes,
        );
    const publicEvaluationKeyMaterialReference = {
        publicEvaluationKeyMaterialEncoding:
            publicEvaluationKeyTransportMaterialEncoding,
        publicEvaluationKeyMaterialRoot,
        publicEvaluationKeyMaterialChunkSizeBytes:
            setupProofTransportChunkSizeBytes,
        publicEvaluationKeyMaterialChunkCount:
            transportHashes.chunkHashes.length,
        publicEvaluationKeyMaterialTotalByteLength:
            transportHashes.totalByteLength,
        publicEvaluationKeyMaterialFullObjectHash:
            transportHashes.fullObjectHash,
        publicEvaluationKeyMaterialChunkRoot: transportHashes.chunkRoot,
        publicEvaluationKeyMaterialChunkHashes: transportHashes.chunkHashes,
    } satisfies PublicEvaluationKeyMaterialReference;
    const evaluationKeys = createPublicEvaluationKeySet({
        ...input,
        publicEvaluationKeyMaterialReference,
    });
    assertPublicEvaluationKeyComponentMaterialCoverage(input);
    const transportedPublicEvaluationKeyMaterial = {
        objectType: publicEvaluationKeyMaterialTransportSetObjectType,
        materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
        publicEvaluationKeyMaterials: [
            {
                objectType: publicEvaluationKeyMaterialTransportObjectType,
                materialEncoding: publicEvaluationKeyTransportMaterialEncoding,
                ...contextFields(input.setupContext),
                evaluationKeySetHash: evaluationKeys.evaluationKeySetHash,
                publicEvaluationKeyMaterialRoot,
                chunkCount: transportHashes.chunkHashes.length,
                totalByteLength: transportHashes.totalByteLength,
                fullObjectHash: transportHashes.fullObjectHash,
                chunkRoot: transportHashes.chunkRoot,
                chunkHashes: transportHashes.chunkHashes,
                chunks: chunks.map((chunk, chunkIndex) => ({
                    chunkIndex,
                    bytesHex: bytesToHex(chunk),
                })),
            },
        ],
    } satisfies TransportedPublicEvaluationKeyMaterialSet;

    return {
        evaluationKeys,
        publicEvaluationKeyMaterialReference,
        transportedPublicEvaluationKeyMaterial,
    };
};
