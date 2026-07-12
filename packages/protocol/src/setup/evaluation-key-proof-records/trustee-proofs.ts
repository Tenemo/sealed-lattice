import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';

import {
    setupProofMaterialRecordTransportFields,
    setupProofMaterialTransportChunks,
    setupProofMaterialTransportMetadata,
} from '../setup-proof-material-transport.js';

import {
    type EvaluationKeyShareComponentMaterialChunk,
    type EvaluationKeyShareComponentMaterialChunkStream,
    type EvaluationKeyShareProofFamily,
    type JsonRecord,
    type RelinearizationKeyShareRounds,
    type TransportedEvaluationKeyShareComponentMaterialSet,
    type TransportedEvaluationKeyShareProofMaterialSet,
    type TrusteeEvaluationKeyProofRecord,
    type TrusteeEvaluationKeyProofSet,
    type TrusteeEvaluationKeyProofsInput,
    type TrusteeEvaluationKeyStatementKey,
    type TrusteeEvaluationKeyWitnessInput,
    evaluationKeyShareComponentMaterialEncoding,
    evaluationKeyShareComponentMaterialMagic,
    evaluationKeyShareProofTransportObjectType,
    evaluationKeyShareProofTransportSetObjectType,
    setupProofMaterialTransportEncoding,
    trusteeEvaluationKeyProofBytesHashDomain,
    trusteeEvaluationKeyProofFamily,
} from './constants-and-types.js';
import {
    assertLowercaseHex,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    assertJsonRecord,
    bytesFromHex,
    coefficientVectorFromLittleEndianHex,
    evaluationKeyShareComponentVectorHash,
    evaluationKeyShareComponentVectorRoot,
    freshProofRandomnessHex,
    nonNegativeIntegerRecordField,
    stringRecordField,
} from './encoding.js';
import {
    assertContextMatches,
    contextFields,
    validateCommonInput,
} from './share-records.js';

const componentMaterialChunkBytes = (
    value: unknown,
    fieldPath: string,
): ArrayBuffer => {
    if (Object.prototype.toString.call(value) !== '[object ArrayBuffer]') {
        throw new TypeError(`${fieldPath} must be an ArrayBuffer.`);
    }
    return value as ArrayBuffer;
};

// The ordered binary chunk records for one transported component material: either
// embedded inline on the component material (the additive inline path) or
// carried out of band in the parallel chunk streams keyed by
// keySwitchComponentMaterialRoot (the streamed path the terminal verify uses).
const componentMaterialChunkRecords = (
    componentMaterial: JsonRecord,
    keySwitchComponentMaterialRoot: string,
    componentMaterialChunkStreams:
        | readonly EvaluationKeyShareComponentMaterialChunkStream[]
        | undefined,
    objectPath: string,
): readonly EvaluationKeyShareComponentMaterialChunk[] => {
    const inlineChunks = componentMaterial.chunks;
    if (inlineChunks !== undefined) {
        if (!Array.isArray(inlineChunks) || inlineChunks.length === 0) {
            throw new Error(
                `${objectPath} transported component material chunks must be a non-empty array.`,
            );
        }

        return inlineChunks.map((chunkValue, chunkIndex) => {
            const chunk = assertJsonRecord(
                chunkValue,
                `componentMaterial.chunks.${String(chunkIndex)}`,
            );

            return {
                chunkIndex: assertNonNegativeSafeInteger(
                    chunk.chunkIndex,
                    `componentMaterial.chunks.${String(chunkIndex)}.chunkIndex`,
                ),
                bytes: componentMaterialChunkBytes(
                    chunk.bytes,
                    `componentMaterial.chunks.${String(chunkIndex)}.bytes`,
                ),
            };
        });
    }
    const matchingChunkStreams = (componentMaterialChunkStreams ?? []).filter(
        (chunkStream) =>
            chunkStream.keySwitchComponentMaterialRoot ===
            keySwitchComponentMaterialRoot,
    );
    if (matchingChunkStreams.length !== 1) {
        throw new Error(
            `${objectPath} transported component material has no inline chunks and must match exactly one component material chunk stream.`,
        );
    }
    const chunks = matchingChunkStreams[0].chunks;
    if (chunks.length === 0) {
        throw new Error(
            `${objectPath} transported component material chunk stream must be a non-empty array.`,
        );
    }

    return chunks;
};

// Decode one record's full public component-b material, mirroring the kernel
// decoder: from embedded canonical component vector entries, or from the
// binary chunked transport referenced by keySwitchComponentMaterialRoot. The
// binary transport bytes come from the component material's inline chunks when
// present, otherwise from the parallel component material chunk streams.
const componentBVectorsFromMaterial = (
    proofFamily: EvaluationKeyShareProofFamily,
    record: JsonRecord,
    qSharePrimes: readonly number[],
    transportedComponentMaterial:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | undefined,
    componentMaterialChunkStreams:
        | readonly EvaluationKeyShareComponentMaterialChunkStream[]
        | undefined,
    objectPath: string,
): number[][][] => {
    const level = nonNegativeIntegerRecordField(record, 'level', objectPath);
    const ringDegree = nonNegativeIntegerRecordField(
        record,
        'ringDegree',
        objectPath,
    );
    const digitCount = level + 1;
    if (digitCount > qSharePrimes.length) {
        throw new Error(`${objectPath}.level is outside the Q_share basis.`);
    }
    const materialEncoding = stringRecordField(
        record,
        'keySwitchMaterialEncoding',
        objectPath,
    );
    if (materialEncoding === 'embedded-full-key-switch-component-vectors') {
        const entriesValue = record.keySwitchComponentVectors;
        if (!Array.isArray(entriesValue)) {
            throw new TypeError(
                `${objectPath}.keySwitchComponentVectors must be an array.`,
            );
        }
        if (entriesValue.length !== digitCount * digitCount) {
            throw new Error(
                `${objectPath}.keySwitchComponentVectors must contain one vector per digit and RNS limb.`,
            );
        }
        const componentBByDigit: number[][][] = Array.from(
            { length: digitCount },
            () => Array.from({ length: digitCount }, () => [] as number[]),
        );
        entriesValue.forEach((entryValue, entryIndex) => {
            const entry = assertJsonRecord(
                entryValue,
                `${objectPath}.keySwitchComponentVectors.${String(entryIndex)}`,
            );
            const entryPath = `${objectPath}.keySwitchComponentVectors.${String(entryIndex)}`;
            const digitIndex = nonNegativeIntegerRecordField(
                entry,
                'digitIndex',
                entryPath,
            );
            const rnsLimbIndex = nonNegativeIntegerRecordField(
                entry,
                'rnsLimbIndex',
                entryPath,
            );
            if (digitIndex >= digitCount || rnsLimbIndex >= digitCount) {
                throw new Error(
                    `${entryPath} component vector index is outside the proof level.`,
                );
            }
            if (
                nonNegativeIntegerRecordField(entry, 'rnsPrime', entryPath) !==
                    qSharePrimes[rnsLimbIndex] ||
                entry.component !== 'b' ||
                nonNegativeIntegerRecordField(
                    entry,
                    'coefficientByteLength',
                    entryPath,
                ) !==
                    ringDegree * 8
            ) {
                throw new Error(
                    `${entryPath} component vector metadata does not match the proof level.`,
                );
            }
            if (componentBByDigit[digitIndex][rnsLimbIndex].length !== 0) {
                throw new Error(
                    `${entryPath} repeats a digit and RNS limb component vector.`,
                );
            }
            const coefficients = coefficientVectorFromLittleEndianHex(
                stringRecordField(entry, 'coefficientsLeHex', entryPath),
                ringDegree,
                `${entryPath}.coefficientsLeHex`,
            );
            if (
                coefficients.some(
                    (coefficient) => coefficient >= qSharePrimes[rnsLimbIndex],
                )
            ) {
                throw new Error(
                    `${entryPath} contains non-canonical Q_share residues.`,
                );
            }
            if (
                stringRecordField(
                    entry,
                    'coefficientVectorHash512',
                    entryPath,
                ) !== evaluationKeyShareComponentVectorHash(coefficients)
            ) {
                throw new Error(
                    `${entryPath} coefficient hash does not match coefficientsLeHex.`,
                );
            }
            componentBByDigit[digitIndex][rnsLimbIndex] = [...coefficients];
        });
        const expectedRoot = evaluationKeyShareComponentVectorRoot(
            proofFamily,
            stringRecordField(record, 'keySwitchDomain', objectPath),
            stringRecordField(record, 'keySwitchSeedHex', objectPath),
            level,
            ringDegree,
            entriesValue as JsonRecord[],
        );
        if (
            stringRecordField(
                record,
                'keySwitchComponentVectorRoot',
                objectPath,
            ) !== expectedRoot
        ) {
            throw new Error(
                `${objectPath}.keySwitchComponentVectorRoot does not match the embedded public material.`,
            );
        }

        return componentBByDigit;
    }
    if (materialEncoding !== evaluationKeyShareComponentMaterialEncoding) {
        throw new Error(
            `${objectPath}.keySwitchMaterialEncoding is not accepted.`,
        );
    }
    if (transportedComponentMaterial === undefined) {
        throw new Error(
            `${objectPath} uses binary component material but no transportedEvaluationKeyShareComponentMaterial was supplied.`,
        );
    }
    const expectedMaterialRoot = stringRecordField(
        record,
        'keySwitchComponentMaterialRoot',
        objectPath,
    );
    const matchingMaterials =
        transportedComponentMaterial.componentMaterials.filter(
            (componentMaterial) =>
                componentMaterial.keySwitchComponentMaterialRoot ===
                expectedMaterialRoot,
        );
    if (matchingMaterials.length !== 1) {
        throw new Error(
            `${objectPath} transported component material must match exactly one keySwitchComponentMaterialRoot.`,
        );
    }
    const componentMaterial = assertJsonRecord(
        matchingMaterials[0],
        'componentMaterial',
    );
    const chunkRecords = componentMaterialChunkRecords(
        componentMaterial,
        expectedMaterialRoot,
        componentMaterialChunkStreams,
        objectPath,
    );
    const materialBytesParts = chunkRecords.map((chunk, chunkIndex) => {
        if (chunk.chunkIndex !== chunkIndex) {
            throw new Error(
                'transported component material chunks must be in ascending chunk-index order.',
            );
        }

        return new Uint8Array(chunk.bytes);
    });
    const totalByteLength = materialBytesParts.reduce(
        (byteLength, part) => byteLength + part.byteLength,
        0,
    );
    const materialBytes = new Uint8Array(totalByteLength);
    let writeOffset = 0;
    for (const part of materialBytesParts) {
        materialBytes.set(part, writeOffset);
        writeOffset += part.byteLength;
    }
    const view = new DataView(
        materialBytes.buffer,
        materialBytes.byteOffset,
        materialBytes.byteLength,
    );
    let cursor = 0;
    const readWord = (): number => {
        if (cursor + 8 > materialBytes.byteLength) {
            throw new Error(
                'transported component material ended unexpectedly.',
            );
        }
        const word = view.getBigUint64(cursor, true);
        cursor += 8;
        if (word > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error(
                'transported component material contains a value outside the JavaScript safe integer range.',
            );
        }

        return Number(word);
    };
    for (
        let magicIndex = 0;
        magicIndex < evaluationKeyShareComponentMaterialMagic.length;
        magicIndex += 1
    ) {
        if (
            materialBytes[magicIndex] !==
            evaluationKeyShareComponentMaterialMagic[magicIndex]
        ) {
            throw new Error(
                'transported component material has the wrong format marker.',
            );
        }
    }
    cursor = evaluationKeyShareComponentMaterialMagic.length;
    const decodedLevel = readWord();
    const decodedRingDegree = readWord();
    const decodedDigitCount = readWord();
    const decodedLimbCount = readWord();
    if (
        decodedLevel !== level ||
        decodedRingDegree !== ringDegree ||
        decodedDigitCount !== digitCount ||
        decodedLimbCount !== digitCount
    ) {
        throw new Error(
            'transported component material shape does not match the share record.',
        );
    }
    const componentBByDigit: number[][][] = [];
    for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
        const componentBByLimb: number[][] = [];
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < digitCount;
            rnsLimbIndex += 1
        ) {
            if (
                readWord() !== digitIndex ||
                readWord() !== rnsLimbIndex ||
                readWord() !== qSharePrimes[rnsLimbIndex] ||
                readWord() !== ringDegree
            ) {
                throw new Error(
                    'transported component material record order or metadata is invalid.',
                );
            }
            const coefficients: number[] = [];
            for (
                let coefficientIndex = 0;
                coefficientIndex < ringDegree;
                coefficientIndex += 1
            ) {
                const coefficient = readWord();
                if (coefficient >= qSharePrimes[rnsLimbIndex]) {
                    throw new Error(
                        'transported component material contains non-canonical Q_share residues.',
                    );
                }
                coefficients.push(coefficient);
            }
            componentBByLimb.push(coefficients);
        }
        componentBByDigit.push(componentBByLimb);
    }
    if (cursor !== materialBytes.byteLength) {
        throw new Error('transported component material has trailing bytes.');
    }

    return componentBByDigit;
};

const relinearizationRecordForTrusteeAndLevel = (
    records: readonly JsonRecord[],
    trusteeRosterPosition: number,
    level: number,
    recordFieldName: string,
): JsonRecord => {
    const matchingRecords = records.filter(
        (record) =>
            record.trusteeRosterPosition === trusteeRosterPosition &&
            record.level === level,
    );
    if (matchingRecords.length !== 1) {
        throw new Error(
            `${recordFieldName} must contain exactly one record per scheduled trustee and level.`,
        );
    }

    return matchingRecords[0];
};

// The public round-one aggregate diagonal per scheduled level: for digit j,
// the sum over every trustee of its round-one component b at (digit j, limb j)
// mod the j-th Q_share prime. Mirrors the kernel recomputation so the prover
// statement matches the verifier-rebuilt statement.
const roundOnePublicAggregateDiagonals = (
    relinearizationKeyShareRounds: RelinearizationKeyShareRounds,
    qSharePrimes: readonly number[],
    participantCount: number,
    transportedComponentMaterial:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | undefined,
    componentMaterialChunkStreams:
        | readonly EvaluationKeyShareComponentMaterialChunkStream[]
        | undefined,
): ReadonlyMap<number, number[][]> => {
    const aggregatesByLevel = new Map<
        number,
        { aggregate: number[][]; contributionCount: number }
    >();
    relinearizationKeyShareRounds.roundOneRecords.forEach((record) => {
        const recordFields = record as JsonRecord;
        const level = nonNegativeIntegerRecordField(
            recordFields,
            'level',
            'roundOneRecords',
        );
        const digitCount = level + 1;
        const components = componentBVectorsFromMaterial(
            'relinearization-key-share',
            recordFields,
            qSharePrimes,
            transportedComponentMaterial,
            componentMaterialChunkStreams,
            'roundOneRecords',
        );
        const ringDegree = components[0]?.[0]?.length ?? 0;
        if (ringDegree === 0) {
            throw new Error(
                'round-one component material does not cover the aggregate diagonal.',
            );
        }
        let aggregateEntry = aggregatesByLevel.get(level);
        if (aggregateEntry === undefined) {
            aggregateEntry = {
                aggregate: Array.from({ length: digitCount }, () =>
                    Array.from({ length: ringDegree }, () => 0),
                ),
                contributionCount: 0,
            };
            aggregatesByLevel.set(level, aggregateEntry);
        }
        for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
            const modulus = qSharePrimes[digitIndex];
            const diagonal = components[digitIndex]?.[digitIndex];
            if (diagonal?.length !== ringDegree) {
                throw new Error(
                    'round-one component material does not cover the aggregate diagonal.',
                );
            }
            const accumulated = aggregateEntry.aggregate[digitIndex];
            for (
                let coefficientIndex = 0;
                coefficientIndex < ringDegree;
                coefficientIndex += 1
            ) {
                accumulated[coefficientIndex] =
                    (accumulated[coefficientIndex] +
                        diagonal[coefficientIndex]) %
                    modulus;
            }
        }
        aggregateEntry.contributionCount += 1;
    });
    const aggregateDiagonalsByLevel = new Map<number, number[][]>();
    for (const [level, aggregateEntry] of aggregatesByLevel) {
        if (aggregateEntry.contributionCount !== participantCount) {
            throw new Error(
                'round-one aggregate requires one component contribution per trustee.',
            );
        }
        aggregateDiagonalsByLevel.set(level, aggregateEntry.aggregate);
    }

    return aggregateDiagonalsByLevel;
};

export const createTrusteeEvaluationKeyProofs = (
    input: TrusteeEvaluationKeyProofsInput,
): TrusteeEvaluationKeyProofSet => {
    const trusteeReferences = validateCommonInput(input);
    assertProtocolHash(
        input.keySwitchDecompositionHash,
        'keySwitchDecompositionHash',
    );
    assertContextMatches(
        input.setupContext,
        input.relinearizationKeyShareRounds,
        'relinearizationKeyShareRounds',
    );
    if (
        input.relinearizationKeyShareRounds.evaluatorKeyScheduleRoot !==
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot ||
        input.relinearizationKeyShareRounds
            .publicKeyShareSuccinctProofSetRoot !==
            input.publicKeyShareSuccinctProofSetRoot
    ) {
        throw new Error(
            'relinearizationKeyShareRounds must match the accepted evaluation-key binding.',
        );
    }
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
    });
    const witnessesByRosterPosition = new Map<
        number,
        TrusteeEvaluationKeyWitnessInput
    >();
    input.trusteeWitnesses.forEach((witness) => {
        assertNonNegativeSafeInteger(
            witness.trusteeRosterPosition,
            'trusteeWitnesses.trusteeRosterPosition',
        );
        if (witnessesByRosterPosition.has(witness.trusteeRosterPosition)) {
            throw new Error(
                'trusteeWitnesses must not repeat a trustee roster position.',
            );
        }
        witnessesByRosterPosition.set(witness.trusteeRosterPosition, witness);
    });
    const sameSecretBridgeStatementSet = input.sameSecretBridgeStatementSet;
    assertContextMatches(
        input.setupContext,
        sameSecretBridgeStatementSet,
        'sameSecretBridgeStatementSet',
    );
    assertProtocolHash(
        sameSecretBridgeStatementSet.publicMatrixSeedHash,
        'sameSecretBridgeStatementSet.publicMatrixSeedHash',
    );
    if (
        sameSecretBridgeStatementSet.participantCount !==
            input.participantCount ||
        sameSecretBridgeStatementSet.statementRecords.length !==
            input.participantCount
    ) {
        throw new Error(
            'sameSecretBridgeStatementSet must contain one statement per participant.',
        );
    }
    if (
        sameSecretBridgeStatementSet.publicMatrixSeedHash !==
        input.evaluatorKeySchedule.publicMatrixSeedHash
    ) {
        throw new Error(
            'sameSecretBridgeStatementSet.publicMatrixSeedHash must match evaluatorKeySchedule.publicMatrixSeedHash.',
        );
    }
    const bridgeStatementsByRosterPosition = new Map(
        sameSecretBridgeStatementSet.statementRecords.map(
            (statementRecord, expectedRosterPosition) => {
                assertContextMatches(
                    input.setupContext,
                    statementRecord,
                    'sameSecretBridgeStatementSet.statementRecords',
                );
                const expectedTrusteeReference =
                    trusteeReferences[expectedRosterPosition];
                if (
                    expectedTrusteeReference === undefined ||
                    statementRecord.trusteeRosterPosition !==
                        expectedRosterPosition ||
                    statementRecord.trusteeIdentity !==
                        expectedTrusteeReference.trusteeIdentity
                ) {
                    throw new Error(
                        'sameSecretBridgeStatementSet statement records must follow the canonical trustee roster order.',
                    );
                }
                if (
                    statementRecord.publicMatrixSeedHash !==
                        sameSecretBridgeStatementSet.publicMatrixSeedHash ||
                    statementRecord.ringDegree !==
                        sameSecretBridgeStatementSet.ringDegree
                ) {
                    throw new Error(
                        'sameSecretBridgeStatementSet statement records must match the set randomness and ring degree.',
                    );
                }
                if (
                    statementRecord.sourceConstantCoefficientCommitments
                        .length !== input.qSharePrimes.length
                ) {
                    throw new Error(
                        'sameSecretBridgeStatementSet source constant commitments must cover every source RNS limb.',
                    );
                }
                statementRecord.sourceConstantCoefficientCommitments.forEach(
                    (sourceCommitmentRecord, expectedRnsLimbIndex) => {
                        const sourceCommitment = assertJsonRecord(
                            sourceCommitmentRecord.commitment,
                            'sameSecretBridgeStatementSet.sourceConstantCoefficientCommitments.commitment',
                        );
                        if (
                            sourceCommitmentRecord.rnsLimbIndex !==
                                expectedRnsLimbIndex ||
                            sourceCommitmentRecord.rnsPrime !==
                                input.qSharePrimes[expectedRnsLimbIndex] ||
                            sourceCommitmentRecord.shamirCoefficientIndex !==
                                0 ||
                            sourceCommitment.objectType !== 'SetupCommitment' ||
                            sourceCommitment.sourceRnsLimbIndex !==
                                expectedRnsLimbIndex ||
                            sourceCommitment.sourceMessageModulus !==
                                sourceCommitmentRecord.rnsPrime ||
                            sourceCommitment.shamirCoefficientIndex !== 0 ||
                            sourceCommitment.ringDegree !==
                                sameSecretBridgeStatementSet.ringDegree ||
                            !Array.isArray(sourceCommitment.commitmentLimbs)
                        ) {
                            throw new Error(
                                'sameSecretBridgeStatementSet source constant commitments must carry canonical source-limb bodies in order.',
                            );
                        }
                    },
                );

                return [
                    statementRecord.trusteeRosterPosition,
                    statementRecord,
                ] as const;
            },
        ),
    );
    if (bridgeStatementsByRosterPosition.size !== input.participantCount) {
        throw new Error(
            'sameSecretBridgeStatementSet must not repeat a trustee roster position.',
        );
    }

    const scheduledLevels =
        input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
            (entry) => entry.level,
        );
    const aggregateDiagonalsByLevel = roundOnePublicAggregateDiagonals(
        input.relinearizationKeyShareRounds,
        input.qSharePrimes,
        input.participantCount,
        input.transportedEvaluationKeyShareComponentMaterial,
        input.evaluationKeyShareComponentMaterialChunkStreams,
    );

    const proofRecords = trusteeReferences.map((trusteeReference) => {
        const witness = witnessesByRosterPosition.get(
            trusteeReference.trusteeRosterPosition,
        );
        if (witness === undefined) {
            throw new Error(
                'trusteeWitnesses must contain one witness per participant.',
            );
        }
        const bridgeStatement = bridgeStatementsByRosterPosition.get(
            trusteeReference.trusteeRosterPosition,
        );
        if (bridgeStatement === undefined) {
            throw new Error(
                'sameSecretBridgeStatementSet must contain one statement per participant.',
            );
        }
        const sourceConstantCommitment =
            bridgeStatement.sourceConstantCoefficientCommitments[0];
        if (sourceConstantCommitment === undefined) {
            throw new Error(
                'sameSecretBridgeStatementSet must carry the source-limb-zero constant commitment.',
            );
        }
        const sourceConstantCoefficientCommitmentRoot =
            deriveCanonicalObjectHash(sourceConstantCommitment.commitment);
        const statementKeys: TrusteeEvaluationKeyStatementKey[] = [];
        let ringDegree: number | undefined;
        const recordRingDegree = (record: JsonRecord): void => {
            const observed = nonNegativeIntegerRecordField(
                record,
                'ringDegree',
                'evaluationKeyShareRecord',
            );
            if (ringDegree === undefined) {
                ringDegree = observed;
            } else if (ringDegree !== observed) {
                throw new Error(
                    'evaluation-key share records must agree on one ring degree.',
                );
            }
        };
        for (const level of scheduledLevels) {
            const record = relinearizationRecordForTrusteeAndLevel(
                input.relinearizationKeyShareRounds.roundOneRecords,
                trusteeReference.trusteeRosterPosition,
                level,
                'roundOneRecords',
            );
            recordRingDegree(record);
            statementKeys.push({
                proofFamily: 'relinearization-round-one',
                level,
                keySwitchDomain: stringRecordField(
                    record,
                    'keySwitchDomain',
                    'roundOneRecords',
                ),
                keySwitchSeedHex: stringRecordField(
                    record,
                    'keySwitchSeedHex',
                    'roundOneRecords',
                ),
                componentBByDigit: componentBVectorsFromMaterial(
                    'relinearization-key-share',
                    record,
                    input.qSharePrimes,
                    input.transportedEvaluationKeyShareComponentMaterial,
                    input.evaluationKeyShareComponentMaterialChunkStreams,
                    'roundOneRecords',
                ),
            });
        }
        for (const level of scheduledLevels) {
            const record = relinearizationRecordForTrusteeAndLevel(
                input.relinearizationKeyShareRounds.roundTwoRecords,
                trusteeReference.trusteeRosterPosition,
                level,
                'roundTwoRecords',
            );
            recordRingDegree(record);
            const aggregateDiagonal = aggregateDiagonalsByLevel.get(level);
            if (aggregateDiagonal === undefined) {
                throw new Error(
                    'round-one public aggregate diagonal is missing for a scheduled level.',
                );
            }
            statementKeys.push({
                proofFamily: 'relinearization-round-two',
                level,
                keySwitchDomain: stringRecordField(
                    record,
                    'keySwitchDomain',
                    'roundTwoRecords',
                ),
                keySwitchSeedHex: stringRecordField(
                    record,
                    'keySwitchSeedHex',
                    'roundTwoRecords',
                ),
                componentBByDigit: componentBVectorsFromMaterial(
                    'relinearization-key-share',
                    record,
                    input.qSharePrimes,
                    input.transportedEvaluationKeyShareComponentMaterial,
                    input.evaluationKeyShareComponentMaterialChunkStreams,
                    'roundTwoRecords',
                ),
                roundOneAggregateDiagonal: aggregateDiagonal,
            });
        }
        const batch =
            sortedGaloisBatches[trusteeReference.trusteeRosterPosition];
        for (const scheduleEntry of input.evaluatorKeySchedule
            .requiredGaloisKeySchedule) {
            const materialRecords = batch.galoisKeyShareMaterialRecords.filter(
                (materialRecord) =>
                    materialRecord.rotation === scheduleEntry.rotation &&
                    materialRecord.level === scheduleEntry.level,
            );
            if (materialRecords.length !== 1) {
                throw new Error(
                    'galoisKeyShareMaterialRecords must contain exactly one record per scheduled rotation and level.',
                );
            }
            const materialRecord = materialRecords[0] as JsonRecord;
            recordRingDegree(materialRecord);
            statementKeys.push({
                proofFamily: 'galois-rotation',
                rotation: scheduleEntry.rotation,
                level: scheduleEntry.level,
                keySwitchDomain: stringRecordField(
                    materialRecord,
                    'keySwitchDomain',
                    'galoisKeyShareMaterialRecords',
                ),
                keySwitchSeedHex: stringRecordField(
                    materialRecord,
                    'keySwitchSeedHex',
                    'galoisKeyShareMaterialRecords',
                ),
                componentBByDigit: componentBVectorsFromMaterial(
                    'galois-key-share',
                    materialRecord,
                    input.qSharePrimes,
                    input.transportedEvaluationKeyShareComponentMaterial,
                    input.evaluationKeyShareComponentMaterialChunkStreams,
                    'galoisKeyShareMaterialRecords',
                ),
            });
        }
        if (ringDegree === undefined) {
            throw new Error(
                'trustee evaluation-key statement requires at least one share record.',
            );
        }
        if (ringDegree !== bridgeStatement.ringDegree) {
            throw new Error(
                'sameSecretBridgeStatementSet ring degree must match the evaluation-key share records.',
            );
        }
        if (witness.errorCoefficientsByKey.length !== statementKeys.length) {
            throw new Error(
                'trusteeWitnesses.errorCoefficientsByKey must contain one error vector set per statement key.',
            );
        }
        const proofRandomnessSeedHex = freshProofRandomnessHex();
        const proofRandomnessNonceHex = freshProofRandomnessHex();
        const generatedProof = input.trusteeEvaluationKeyProofGenerator({
            context: {
                ceremonyId: input.setupContext.ceremonyId,
                manifestHash: input.setupContext.manifestHash,
                rosterHash: input.setupContext.rosterHash,
                trusteeIdentity: trusteeReference.trusteeIdentity,
                trusteeRosterPosition: trusteeReference.trusteeRosterPosition,
                setupEpoch: input.setupContext.setupEpoch,
                requiredGaloisSetHash:
                    input.evaluatorKeySchedule.requiredGaloisSetHash,
                evaluatorKeyScheduleRoot:
                    input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
                keySwitchDecompositionHash: input.keySwitchDecompositionHash,
                sourceConstantCoefficientCommitmentRoot:
                    sourceConstantCoefficientCommitmentRoot,
            },
            ringDegree,
            keys: statementKeys,
            sameSecretLinkage: {
                publicMatrixSeedHash: bridgeStatement.publicMatrixSeedHash,
                commitments: [sourceConstantCommitment.commitment],
            },
            secretCoefficients: witness.secretCoefficients,
            errorCoefficientsByKey: witness.errorCoefficientsByKey,
            negativeIndicatorCoefficients:
                witness.negativeIndicatorCoefficients,
            openingRandomnessByLimb: witness.openingRandomnessByLimb,
            proofRandomnessSeedHex,
            proofRandomnessNonceHex,
        });
        if (generatedProof.operation !== 'generateTrusteeEvaluationKeyProof') {
            throw new Error(
                'trusteeEvaluationKeyProofGenerator returned the wrong operation.',
            );
        }
        assertProtocolHash(
            generatedProof.statementHash,
            'generatedProof.statementHash',
        );
        assertNonEmptyString(
            generatedProof.proofBytesHex,
            'generatedProof.proofBytesHex',
        );
        assertLowercaseHex(
            generatedProof.proofBytesHex,
            'generatedProof.proofBytesHex',
        );
        if (
            generatedProof.proofBytesHex.length !==
            generatedProof.proofByteLength * 2
        ) {
            throw new Error(
                'generatedProof.proofBytesHex length must match proofByteLength.',
            );
        }
        const proofBytes = bytesFromHex(
            generatedProof.proofBytesHex,
            'generatedProof.proofBytesHex',
        );
        const recordWithoutRoot = {
            objectType: 'TrusteeEvaluationKeyProof',
            proofFamily: trusteeEvaluationKeyProofFamily,
            ...contextFields(input.setupContext),
            trusteeIdentity: trusteeReference.trusteeIdentity,
            trusteeRosterPosition: trusteeReference.trusteeRosterPosition,
            statementHash: generatedProof.statementHash,
            proofBytesHash: hash512Hex(
                trusteeEvaluationKeyProofBytesHashDomain,
                [proofBytes],
            ),
            proofBytesHex: generatedProof.proofBytesHex,
        } as JsonRecord;

        return {
            ...recordWithoutRoot,
            trusteeEvaluationKeyProofRoot:
                deriveCanonicalObjectHash(recordWithoutRoot),
        } as TrusteeEvaluationKeyProofRecord;
    });
    if (proofRecords.length === 0) {
        throw new Error(
            'trustee evaluation-key proofs require at least one participant.',
        );
    }

    const galoisKeyShareBatchRoots = sortedGaloisBatches.map((batch) => ({
        trusteeIdentity: batch.trusteeIdentity,
        trusteeRosterPosition: batch.trusteeRosterPosition,
        galoisKeyShareBatchRoot: batch.galoisKeyShareBatchRoot,
    }));
    const proofSetWithoutRoot = {
        objectType: 'TrusteeEvaluationKeyProofSet',
        proofFamily: trusteeEvaluationKeyProofFamily,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        evaluatorKeyScheduleRoot:
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot,
        requiredGaloisSetHash: input.evaluatorKeySchedule.requiredGaloisSetHash,
        keySwitchDecompositionHash: input.keySwitchDecompositionHash,
        publicKeyShareSetRoot: input.evaluatorKeySchedule.publicKeyShareSetRoot,
        publicKeyShareSuccinctProofSetRoot:
            input.publicKeyShareSuccinctProofSetRoot,
        relinearizationCrpRoot:
            input.evaluatorKeySchedule.relinearizationCrpRoot,
        galoisKeyCrpRoot: input.evaluatorKeySchedule.galoisKeyCrpRoot,
        publicMatrixSeedHash: input.evaluatorKeySchedule.publicMatrixSeedHash,
        relinearizationKeyShareRoundsRoot:
            input.relinearizationKeyShareRounds
                .relinearizationKeyShareRoundsRoot,
        galoisKeyShareBatchRoots,
        proofRecords,
    } as const satisfies Omit<
        TrusteeEvaluationKeyProofSet,
        'trusteeEvaluationKeyProofSetRoot'
    >;

    return {
        ...proofSetWithoutRoot,
        trusteeEvaluationKeyProofSetRoot:
            deriveCanonicalObjectHash(proofSetWithoutRoot),
    } satisfies TrusteeEvaluationKeyProofSet;
};

export type TrusteeEvaluationKeyProofMaterialTransport = Readonly<{
    readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
    readonly transportedEvaluationKeyShareProofMaterial: TransportedEvaluationKeyShareProofMaterialSet;
}>;

// Move every trustee proof's embedded bytes into binary chunked transport and
// rebind the record and set roots, mirroring the kernel terminal-transport
// flow: the proof record keeps the transport reference, the chunks travel in
// the request-side transported proof material set.
export const transportTrusteeEvaluationKeyProofSet = (
    proofSet: TrusteeEvaluationKeyProofSet,
): TrusteeEvaluationKeyProofMaterialTransport => {
    const transportedProofMaterials: JsonRecord[] = [];
    const transportedProofRecords = proofSet.proofRecords.map((proofRecord) => {
        const recordFields = proofRecord as JsonRecord;
        const proofBytesHex = stringRecordField(
            recordFields,
            'proofBytesHex',
            'proofRecords',
        );
        const proofBytes = bytesFromHex(
            proofBytesHex,
            'proofRecords.proofBytesHex',
        );
        if (
            hash512Hex(trusteeEvaluationKeyProofBytesHashDomain, [
                proofBytes,
            ]) !== proofRecord.proofBytesHash
        ) {
            throw new Error(
                'proofRecords.proofBytesHash must match proofBytesHex before transport.',
            );
        }
        const proofMaterialTransport = setupProofMaterialTransportMetadata(
            proofBytes,
            'proofRecords.proofBytesHex must produce at least one transported chunk.',
        );
        const proofMaterialRoot = deriveCanonicalObjectHash({
            objectType: 'TrusteeEvaluationKeyProofMaterialReference',
            proofFamily: trusteeEvaluationKeyProofFamily,
            trusteeIdentity: proofRecord.trusteeIdentity,
            trusteeRosterPosition: proofRecord.trusteeRosterPosition,
            statementHash: proofRecord.statementHash,
            proofBytesHash: proofRecord.proofBytesHash,
        });
        transportedProofMaterials.push({
            objectType: evaluationKeyShareProofTransportObjectType,
            proofFamily: trusteeEvaluationKeyProofFamily,
            ...setupProofMaterialRecordTransportFields(
                proofMaterialRoot,
                setupProofMaterialTransportEncoding,
            ),
            chunks: setupProofMaterialTransportChunks(proofMaterialTransport),
        });
        const transportedRecordWithoutRoot = {
            ...recordFields,
            ...setupProofMaterialRecordTransportFields(
                proofMaterialRoot,
                setupProofMaterialTransportEncoding,
            ),
        } as JsonRecord;
        delete transportedRecordWithoutRoot.proofBytesHex;
        delete transportedRecordWithoutRoot.trusteeEvaluationKeyProofRoot;

        return {
            ...transportedRecordWithoutRoot,
            trusteeEvaluationKeyProofRoot: deriveCanonicalObjectHash(
                transportedRecordWithoutRoot,
            ),
        } as TrusteeEvaluationKeyProofRecord;
    });
    const proofSetWithoutRoot: JsonRecord = {
        ...(proofSet as JsonRecord),
        proofRecords: transportedProofRecords,
    };
    delete proofSetWithoutRoot.trusteeEvaluationKeyProofSetRoot;

    return {
        trusteeEvaluationKeyProofs: {
            ...proofSetWithoutRoot,
            trusteeEvaluationKeyProofSetRoot:
                deriveCanonicalObjectHash(proofSetWithoutRoot),
        } as TrusteeEvaluationKeyProofSet,
        transportedEvaluationKeyShareProofMaterial: {
            objectType: evaluationKeyShareProofTransportSetObjectType,
            proofFamily: trusteeEvaluationKeyProofFamily,
            proofMaterials: transportedProofMaterials,
        },
    };
};
