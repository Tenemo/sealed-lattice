import { deriveCanonicalObjectHash } from "@sealed-lattice/crypto";
import { foundationProfile } from "@sealed-lattice/types";

import { copyCanonicalStreamDescriptor } from "../canonical-stream-descriptor.js";

import {
    type EvaluationKeyShareComponentMaterialChunkSource,
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
    evaluationKeyShareComponentMaterialMagic,
    evaluationKeyShareProofTransportObjectType,
    evaluationKeyShareProofTransportSetObjectType,
} from "./constants-and-types.js";
import {
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    assertJsonRecord,
    coefficientVectorFromLittleEndianHex,
    evaluationKeyShareComponentVectorRoot,
    freshProofRandomnessHex,
    nonNegativeIntegerRecordField,
    stringRecordField,
} from "./encoding.js";
import {
    assertContextMatches,
    contextFields,
    galoisKeySwitchSeed,
    relinearizationKeySwitchSeed,
    validateCommonInput,
} from "./share-records.js";

class BoundedComponentMaterialReader {
    readonly #pullChunk: EvaluationKeyShareComponentMaterialChunkSource["pullChunk"];
    readonly #totalByteLength: number;
    #chunk?: Uint8Array;
    #chunkByteOffset = 0;
    #chunkIndex = 0;
    #consumedByteLength = 0;

    public constructor(
        pullChunk: EvaluationKeyShareComponentMaterialChunkSource["pullChunk"],
        totalByteLength: number,
    ) {
        this.#pullChunk = pullChunk;
        this.#totalByteLength = totalByteLength;
    }

    public async readBytes(byteLength: number): Promise<Uint8Array> {
        const output = new Uint8Array(byteLength);
        let outputOffset = 0;
        while (outputOffset < output.length) {
            await this.#ensureChunk();
            const chunk = this.#chunk;
            if (chunk === undefined) {
                throw new Error(
                    "transported component material ended unexpectedly.",
                );
            }
            const copyByteLength = Math.min(
                chunk.length - this.#chunkByteOffset,
                output.length - outputOffset,
            );
            output.set(
                chunk.subarray(
                    this.#chunkByteOffset,
                    this.#chunkByteOffset + copyByteLength,
                ),
                outputOffset,
            );
            this.#chunkByteOffset += copyByteLength;
            this.#consumedByteLength += copyByteLength;
            outputOffset += copyByteLength;
        }
        return output;
    }

    public async readUnsignedWords(wordCount: number): Promise<number[]> {
        const words: number[] = [];
        while (words.length < wordCount) {
            await this.#ensureChunk();
            const chunk = this.#chunk;
            if (chunk === undefined) {
                throw new Error(
                    "transported component material ended unexpectedly.",
                );
            }
            const availableWordCount = Math.floor(
                (chunk.length - this.#chunkByteOffset) / 8,
            );
            if (availableWordCount === 0) {
                const wordBytes = await this.readBytes(8);
                words.push(this.#wordFromBytes(wordBytes));
                wordBytes.fill(0);
                continue;
            }
            const view = new DataView(
                chunk.buffer,
                chunk.byteOffset,
                chunk.byteLength,
            );
            const readableWordCount = Math.min(
                availableWordCount,
                wordCount - words.length,
            );
            for (
                let readableWordIndex = 0;
                readableWordIndex < readableWordCount;
                readableWordIndex += 1
            ) {
                const word = view.getBigUint64(this.#chunkByteOffset, true);
                if (word > BigInt(Number.MAX_SAFE_INTEGER)) {
                    throw new Error(
                        "transported component material contains a value outside the JavaScript safe integer range.",
                    );
                }
                words.push(Number(word));
                this.#chunkByteOffset += 8;
                this.#consumedByteLength += 8;
            }
        }
        return words;
    }

    public async finish(): Promise<void> {
        if (this.#consumedByteLength !== this.#totalByteLength) {
            throw new Error(
                "transported component material has trailing bytes.",
            );
        }
        this.#releaseChunk();
        const trailingChunk = await this.#pullChunk({
            chunkIndex: this.#chunkIndex,
            expectedByteLength: 0,
        });
        if (trailingChunk !== undefined) {
            new Uint8Array(trailingChunk).fill(0);
            throw new Error(
                "transported component material has trailing chunks.",
            );
        }
    }

    async #ensureChunk(): Promise<void> {
        if (
            this.#chunk !== undefined &&
            this.#chunkByteOffset < this.#chunk.length
        ) {
            return;
        }
        this.#releaseChunk();
        if (this.#consumedByteLength === this.#totalByteLength) {
            return;
        }
        const expectedByteLength = Math.min(
            foundationProfile.streamChunkByteLength,
            this.#totalByteLength - this.#consumedByteLength,
        );
        const chunk = await this.#pullChunk({
            chunkIndex: this.#chunkIndex,
            expectedByteLength,
        });
        if (
            chunk === undefined ||
            Object.prototype.toString.call(chunk) !== "[object ArrayBuffer]" ||
            chunk.byteLength !== expectedByteLength
        ) {
            throw new Error(
                "transported component material source returned the wrong chunk length.",
            );
        }
        this.#chunk = new Uint8Array(chunk);
        this.#chunkByteOffset = 0;
        this.#chunkIndex += 1;
    }

    #releaseChunk(): void {
        this.#chunk?.fill(0);
        this.#chunk = undefined;
        this.#chunkByteOffset = 0;
    }

    #wordFromBytes(bytes: Uint8Array): number {
        const word = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getBigUint64(0, true);
        if (word > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error(
                "transported component material contains a value outside the JavaScript safe integer range.",
            );
        }
        return Number(word);
    }
}

// Decode one record's full public component-b material, mirroring the kernel
// decoder: from embedded canonical component vector entries, or from the
// binary chunked transport referenced by keySwitchComponentMaterialRoot. The
// binary transport bytes come from the component material's inline chunks when
// present, otherwise from the parallel component material chunk streams.
const componentBVectorsFromMaterial = async (
    proofFamily: EvaluationKeyShareProofFamily,
    record: JsonRecord,
    keySwitchDomain: string,
    keySwitchSeedHex: string,
    ringDegree: number,
    qSharePrimes: readonly number[],
    transportedComponentMaterial:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | undefined,
    componentMaterialSourcesByRoot: ReadonlyMap<
        string,
        EvaluationKeyShareComponentMaterialChunkSource
    >,
    usedComponentMaterialRoots: Set<string>,
    objectPath: string,
): Promise<number[][][]> => {
    const level = nonNegativeIntegerRecordField(record, "level", objectPath);
    const digitCount = level + 1;
    if (digitCount > qSharePrimes.length) {
        throw new Error(`${objectPath}.level is outside the Q_share basis.`);
    }
    const entriesValue = record.keySwitchComponentVectors;
    if (Array.isArray(entriesValue)) {
        if (entriesValue.length !== digitCount * digitCount) {
            throw new Error(
                `${objectPath}.keySwitchComponentVectors must contain one vector per digit and RNS limb.`,
            );
        }
        const componentBByDigit: number[][][] = Array.from(
            { length: digitCount },
            () => Array.from({ length: digitCount }, () => [] as number[]),
        );
        const canonicalEntries: JsonRecord[] = [];
        entriesValue.forEach((entryValue, entryIndex) => {
            const entry = assertJsonRecord(
                entryValue,
                `${objectPath}.keySwitchComponentVectors.${String(entryIndex)}`,
            );
            const entryPath = `${objectPath}.keySwitchComponentVectors.${String(entryIndex)}`;
            const digitIndex = nonNegativeIntegerRecordField(
                entry,
                "digitIndex",
                entryPath,
            );
            const rnsLimbIndex = nonNegativeIntegerRecordField(
                entry,
                "rnsLimbIndex",
                entryPath,
            );
            if (digitIndex >= digitCount || rnsLimbIndex >= digitCount) {
                throw new Error(
                    `${entryPath} component vector index is outside the proof level.`,
                );
            }
            const rnsPrime = nonNegativeIntegerRecordField(
                entry,
                "rnsPrime",
                entryPath,
            );
            if (rnsPrime !== qSharePrimes[rnsLimbIndex]) {
                throw new Error(
                    `${entryPath} component vector metadata does not match the proof level.`,
                );
            }
            if (componentBByDigit[digitIndex][rnsLimbIndex].length !== 0) {
                throw new Error(
                    `${entryPath} repeats a digit and RNS limb component vector.`,
                );
            }
            const coefficientsLeHex = stringRecordField(
                entry,
                "coefficientsLeHex",
                entryPath,
            );
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientsLeHex,
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
            canonicalEntries.push({
                digitIndex,
                rnsLimbIndex,
                rnsPrime,
                coefficientsLeHex,
            });
            componentBByDigit[digitIndex][rnsLimbIndex] = [...coefficients];
        });
        const expectedRoot = evaluationKeyShareComponentVectorRoot(
            proofFamily,
            keySwitchDomain,
            keySwitchSeedHex,
            level,
            ringDegree,
            canonicalEntries,
        );
        if (
            stringRecordField(
                record,
                "keySwitchComponentVectorRoot",
                objectPath,
            ) !== expectedRoot
        ) {
            throw new Error(
                `${objectPath}.keySwitchComponentVectorRoot does not match the embedded public material.`,
            );
        }

        return componentBByDigit;
    }
    if (transportedComponentMaterial === undefined) {
        throw new Error(
            `${objectPath} uses binary component material but no transportedEvaluationKeyShareComponentMaterial was supplied.`,
        );
    }
    const expectedMaterialRoot = stringRecordField(
        record,
        "keySwitchComponentMaterialRoot",
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
        "componentMaterial",
    );
    if (componentMaterial.proofFamily !== proofFamily) {
        throw new Error(
            `${objectPath} transported component material must match its proof family.`,
        );
    }
    const descriptorBytes = componentMaterial.descriptorBytes;
    if (
        !ArrayBuffer.isView(descriptorBytes) ||
        Object.prototype.toString.call(descriptorBytes) !==
            "[object Uint8Array]" ||
        (descriptorBytes as Uint8Array).byteLength === 0
    ) {
        throw new TypeError(
            `${objectPath} transported component material requires non-empty descriptorBytes.`,
        );
    }
    const componentMaterialSource =
        componentMaterialSourcesByRoot.get(expectedMaterialRoot);
    if (componentMaterialSource === undefined) {
        throw new Error(
            `${objectPath} transported component material must match exactly one bounded component source.`,
        );
    }
    usedComponentMaterialRoots.add(expectedMaterialRoot);
    const totalByteLength =
        evaluationKeyShareComponentMaterialMagic.byteLength +
        2 * 8 +
        digitCount * digitCount * ringDegree * 8;
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength <= 0) {
        throw new Error(
            `${objectPath} transported component material length is outside the JavaScript safe integer range.`,
        );
    }
    const reader = new BoundedComponentMaterialReader(
        componentMaterialSource.pullChunk,
        totalByteLength,
    );
    const magic = await reader.readBytes(
        evaluationKeyShareComponentMaterialMagic.length,
    );
    for (
        let magicIndex = 0;
        magicIndex < evaluationKeyShareComponentMaterialMagic.length;
        magicIndex += 1
    ) {
        if (
            magic[magicIndex] !==
            evaluationKeyShareComponentMaterialMagic[magicIndex]
        ) {
            throw new Error(
                "transported component material has the wrong format marker.",
            );
        }
    }
    magic.fill(0);
    const [decodedLevel, decodedRingDegree] = await reader.readUnsignedWords(2);
    if (decodedLevel !== level || decodedRingDegree !== ringDegree) {
        throw new Error(
            "transported component material shape does not match the share record.",
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
            const coefficients = await reader.readUnsignedWords(ringDegree);
            if (
                coefficients.some(
                    (coefficient) => coefficient >= qSharePrimes[rnsLimbIndex],
                )
            ) {
                throw new Error(
                    "transported component material contains non-canonical Q_share residues.",
                );
            }
            componentBByLimb.push(coefficients);
        }
        componentBByDigit.push(componentBByLimb);
    }
    await reader.finish();

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
const roundOnePublicAggregateDiagonals = async (
    relinearizationKeyShareRounds: RelinearizationKeyShareRounds,
    evaluatorKeySchedule: TrusteeEvaluationKeyProofsInput["evaluatorKeySchedule"],
    ringDegree: number,
    qSharePrimes: readonly number[],
    participantCount: number,
    transportedComponentMaterial:
        | TransportedEvaluationKeyShareComponentMaterialSet
        | undefined,
    componentMaterialSourcesByRoot: ReadonlyMap<
        string,
        EvaluationKeyShareComponentMaterialChunkSource
    >,
    usedComponentMaterialRoots: Set<string>,
): Promise<ReadonlyMap<number, number[][]>> => {
    const aggregatesByLevel = new Map<
        number,
        { aggregate: number[][]; contributionCount: number }
    >();
    for (const record of relinearizationKeyShareRounds.roundOneRecords) {
        const recordFields = record as JsonRecord;
        const level = nonNegativeIntegerRecordField(
            recordFields,
            "level",
            "roundOneRecords",
        );
        const digitCount = level + 1;
        const components = await componentBVectorsFromMaterial(
            "relinearization-key-share",
            recordFields,
            "relinearization",
            relinearizationKeySwitchSeed(
                evaluatorKeySchedule,
                "round-one",
                level,
            ),
            ringDegree,
            qSharePrimes,
            transportedComponentMaterial,
            componentMaterialSourcesByRoot,
            usedComponentMaterialRoots,
            "roundOneRecords",
        );
        if ((components[0]?.[0]?.length ?? 0) !== ringDegree) {
            throw new Error(
                "round-one component material does not cover the aggregate diagonal.",
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
                    "round-one component material does not cover the aggregate diagonal.",
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
    }
    const aggregateDiagonalsByLevel = new Map<number, number[][]>();
    for (const [level, aggregateEntry] of aggregatesByLevel) {
        if (aggregateEntry.contributionCount !== participantCount) {
            throw new Error(
                "round-one aggregate requires one component contribution per trustee.",
            );
        }
        aggregateDiagonalsByLevel.set(level, aggregateEntry.aggregate);
    }

    return aggregateDiagonalsByLevel;
};

export const createTrusteeEvaluationKeyProofs = async (
    input: TrusteeEvaluationKeyProofsInput,
): Promise<TrusteeEvaluationKeyProofMaterialTransport> => {
    const trusteeReferences = validateCommonInput(input);
    assertContextMatches(
        input.setupContext,
        input.relinearizationKeyShareRounds,
        "relinearizationKeyShareRounds",
    );
    if (
        input.relinearizationKeyShareRounds.evaluatorKeyScheduleRoot !==
            input.evaluatorKeySchedule.evaluatorKeyScheduleRoot ||
        input.relinearizationKeyShareRounds
            .publicKeyShareSuccinctProofSetRoot !==
            input.publicKeyShareSuccinctProofSetRoot
    ) {
        throw new Error(
            "relinearizationKeyShareRounds must match the accepted evaluation-key binding.",
        );
    }
    const sortedGaloisBatches = [...input.galoisKeyShareBatches].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (sortedGaloisBatches.length !== input.participantCount) {
        throw new Error(
            "galoisKeyShareBatches must contain one batch per participant.",
        );
    }
    sortedGaloisBatches.forEach((batch, expectedRosterPosition) => {
        assertContextMatches(input.setupContext, batch, "galoisKeyShareBatch");
        if (batch.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                "galoisKeyShareBatches roster positions must be contiguous from zero.",
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
            "trusteeWitnesses.trusteeRosterPosition",
        );
        if (witnessesByRosterPosition.has(witness.trusteeRosterPosition)) {
            throw new Error(
                "trusteeWitnesses must not repeat a trustee roster position.",
            );
        }
        witnessesByRosterPosition.set(witness.trusteeRosterPosition, witness);
    });
    const sameSecretBridgeStatementSet = input.sameSecretBridgeStatementSet;
    assertContextMatches(
        input.setupContext,
        sameSecretBridgeStatementSet,
        "sameSecretBridgeStatementSet",
    );
    assertProtocolHash(
        sameSecretBridgeStatementSet.publicMatrixSeedHash,
        "sameSecretBridgeStatementSet.publicMatrixSeedHash",
    );
    assertPositiveSafeInteger(
        sameSecretBridgeStatementSet.ringDegree,
        "sameSecretBridgeStatementSet.ringDegree",
    );
    if (
        sameSecretBridgeStatementSet.participantCount !==
            input.participantCount ||
        sameSecretBridgeStatementSet.statementRecords.length !==
            input.participantCount
    ) {
        throw new Error(
            "sameSecretBridgeStatementSet must contain one statement per participant.",
        );
    }
    if (
        sameSecretBridgeStatementSet.publicMatrixSeedHash !==
        input.evaluatorKeySchedule.publicMatrixSeedHash
    ) {
        throw new Error(
            "sameSecretBridgeStatementSet.publicMatrixSeedHash must match evaluatorKeySchedule.publicMatrixSeedHash.",
        );
    }
    const bridgeStatementsByRosterPosition = new Map(
        sameSecretBridgeStatementSet.statementRecords.map(
            (statementRecord, expectedRosterPosition) => {
                assertContextMatches(
                    input.setupContext,
                    statementRecord,
                    "sameSecretBridgeStatementSet.statementRecords",
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
                        "sameSecretBridgeStatementSet statement records must follow the canonical trustee roster order.",
                    );
                }
                if (
                    statementRecord.publicMatrixSeedHash !==
                        sameSecretBridgeStatementSet.publicMatrixSeedHash ||
                    statementRecord.ringDegree !==
                        sameSecretBridgeStatementSet.ringDegree
                ) {
                    throw new Error(
                        "sameSecretBridgeStatementSet statement records must match the set randomness and ring degree.",
                    );
                }
                if (
                    statementRecord.sourceConstantCoefficientCommitments
                        .length !== input.qSharePrimes.length
                ) {
                    throw new Error(
                        "sameSecretBridgeStatementSet source constant commitments must cover every source RNS limb.",
                    );
                }
                statementRecord.sourceConstantCoefficientCommitments.forEach(
                    (sourceCommitmentRecord, expectedRnsLimbIndex) => {
                        const sourceCommitment = assertJsonRecord(
                            sourceCommitmentRecord.commitment,
                            "sameSecretBridgeStatementSet.sourceConstantCoefficientCommitments.commitment",
                        );
                        if (
                            sourceCommitmentRecord.rnsLimbIndex !==
                                expectedRnsLimbIndex ||
                            sourceCommitmentRecord.rnsPrime !==
                                input.qSharePrimes[expectedRnsLimbIndex] ||
                            sourceCommitment.objectType !== "SetupCommitment" ||
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
                                "sameSecretBridgeStatementSet source constant commitments must carry canonical source-limb bodies in order.",
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
            "sameSecretBridgeStatementSet must not repeat a trustee roster position.",
        );
    }

    const scheduledLevels =
        input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
            (entry) => entry.level,
        );
    const componentMaterialSourcesByRoot = new Map<
        string,
        EvaluationKeyShareComponentMaterialChunkSource
    >();
    for (const source of input.evaluationKeyShareComponentMaterialChunkSources ??
        []) {
        assertProtocolHash(
            source.keySwitchComponentMaterialRoot,
            "evaluationKeyShareComponentMaterialChunkSources.keySwitchComponentMaterialRoot",
        );
        if (
            componentMaterialSourcesByRoot.has(
                source.keySwitchComponentMaterialRoot,
            )
        ) {
            throw new Error(
                "evaluationKeyShareComponentMaterialChunkSources must not repeat a material root.",
            );
        }
        componentMaterialSourcesByRoot.set(
            source.keySwitchComponentMaterialRoot,
            source,
        );
    }
    const usedComponentMaterialRoots = new Set<string>();
    const ringDegree = sameSecretBridgeStatementSet.ringDegree;
    const aggregateDiagonalsByLevel = await roundOnePublicAggregateDiagonals(
        input.relinearizationKeyShareRounds,
        input.evaluatorKeySchedule,
        ringDegree,
        input.qSharePrimes,
        input.participantCount,
        input.transportedEvaluationKeyShareComponentMaterial,
        componentMaterialSourcesByRoot,
        usedComponentMaterialRoots,
    );

    const transportedProofMaterials: TransportedEvaluationKeyShareProofMaterialSet["proofMaterials"][number][] =
        [];
    const proofRecords: TrusteeEvaluationKeyProofRecord[] = [];
    for (const trusteeReference of trusteeReferences) {
        const witness = witnessesByRosterPosition.get(
            trusteeReference.trusteeRosterPosition,
        );
        if (witness === undefined) {
            throw new Error(
                "trusteeWitnesses must contain one witness per participant.",
            );
        }
        const bridgeStatement = bridgeStatementsByRosterPosition.get(
            trusteeReference.trusteeRosterPosition,
        );
        if (bridgeStatement === undefined) {
            throw new Error(
                "sameSecretBridgeStatementSet must contain one statement per participant.",
            );
        }
        const sourceConstantCommitment =
            bridgeStatement.sourceConstantCoefficientCommitments[0];
        if (sourceConstantCommitment === undefined) {
            throw new Error(
                "sameSecretBridgeStatementSet must carry the source-limb-zero constant commitment.",
            );
        }
        const sourceConstantCoefficientCommitmentRoot =
            deriveCanonicalObjectHash(sourceConstantCommitment.commitment);
        const statementKeys: TrusteeEvaluationKeyStatementKey[] = [];
        for (const level of scheduledLevels) {
            const record = relinearizationRecordForTrusteeAndLevel(
                input.relinearizationKeyShareRounds.roundOneRecords,
                trusteeReference.trusteeRosterPosition,
                level,
                "roundOneRecords",
            );
            const keySwitchSeedHex = relinearizationKeySwitchSeed(
                input.evaluatorKeySchedule,
                "round-one",
                level,
            );
            statementKeys.push({
                proofFamily: "relinearization-round-one",
                level,
                keySwitchDomain: "relinearization",
                keySwitchSeedHex,
                componentBByDigit: await componentBVectorsFromMaterial(
                    "relinearization-key-share",
                    record,
                    "relinearization",
                    keySwitchSeedHex,
                    ringDegree,
                    input.qSharePrimes,
                    input.transportedEvaluationKeyShareComponentMaterial,
                    componentMaterialSourcesByRoot,
                    usedComponentMaterialRoots,
                    "roundOneRecords",
                ),
            });
        }
        for (const level of scheduledLevels) {
            const record = relinearizationRecordForTrusteeAndLevel(
                input.relinearizationKeyShareRounds.roundTwoRecords,
                trusteeReference.trusteeRosterPosition,
                level,
                "roundTwoRecords",
            );
            const aggregateDiagonal = aggregateDiagonalsByLevel.get(level);
            if (aggregateDiagonal === undefined) {
                throw new Error(
                    "round-one public aggregate diagonal is missing for a scheduled level.",
                );
            }
            const keySwitchSeedHex = relinearizationKeySwitchSeed(
                input.evaluatorKeySchedule,
                "round-two",
                level,
            );
            statementKeys.push({
                proofFamily: "relinearization-round-two",
                level,
                keySwitchDomain: "relinearization",
                keySwitchSeedHex,
                componentBByDigit: await componentBVectorsFromMaterial(
                    "relinearization-key-share",
                    record,
                    "relinearization",
                    keySwitchSeedHex,
                    ringDegree,
                    input.qSharePrimes,
                    input.transportedEvaluationKeyShareComponentMaterial,
                    componentMaterialSourcesByRoot,
                    usedComponentMaterialRoots,
                    "roundTwoRecords",
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
                    "galoisKeyShareMaterialRecords must contain exactly one record per scheduled rotation and level.",
                );
            }
            const materialRecord = materialRecords[0] as JsonRecord;
            const keySwitchDomain = `galois-${String(scheduleEntry.rotation)}`;
            const keySwitchSeedHex = galoisKeySwitchSeed(
                input.evaluatorKeySchedule,
                scheduleEntry.rotation,
                scheduleEntry.level,
            );
            statementKeys.push({
                proofFamily: "galois-rotation",
                rotation: scheduleEntry.rotation,
                level: scheduleEntry.level,
                keySwitchDomain,
                keySwitchSeedHex,
                componentBByDigit: await componentBVectorsFromMaterial(
                    "galois-key-share",
                    materialRecord,
                    keySwitchDomain,
                    keySwitchSeedHex,
                    ringDegree,
                    input.qSharePrimes,
                    input.transportedEvaluationKeyShareComponentMaterial,
                    componentMaterialSourcesByRoot,
                    usedComponentMaterialRoots,
                    "galoisKeyShareMaterialRecords",
                ),
            });
        }
        if (witness.errorCoefficientsByKey.length !== statementKeys.length) {
            throw new Error(
                "trusteeWitnesses.errorCoefficientsByKey must contain one error vector set per statement key.",
            );
        }
        const proofRandomnessSeedHex = freshProofRandomnessHex();
        const proofRandomnessNonceHex = freshProofRandomnessHex();
        const generatedProof = await input.trusteeEvaluationKeyProofGenerator({
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
        assertProtocolHash(
            generatedProof.statementHash,
            "generatedProof.statementHash",
        );
        assertProtocolHash(
            generatedProof.proofBytesHash,
            "generatedProof.proofBytesHash",
        );
        assertProtocolHash(
            generatedProof.proofMaterialRoot,
            "generatedProof.proofMaterialRoot",
        );
        const expectedProofMaterialRoot = deriveCanonicalObjectHash({
            objectType: "TrusteeEvaluationKeyProofMaterialReference",
            trusteeIdentity: trusteeReference.trusteeIdentity,
            trusteeRosterPosition: trusteeReference.trusteeRosterPosition,
            statementHash: generatedProof.statementHash,
            proofBytesHash: generatedProof.proofBytesHash,
        });
        if (generatedProof.proofMaterialRoot !== expectedProofMaterialRoot) {
            throw new Error(
                "generatedProof.proofMaterialRoot must bind the trustee proof identity, statement, and proof hash.",
            );
        }
        transportedProofMaterials.push({
            objectType: evaluationKeyShareProofTransportObjectType,
            proofMaterialRoot: generatedProof.proofMaterialRoot,
            descriptorBytes: copyCanonicalStreamDescriptor(
                generatedProof.canonicalMaterial.descriptorBytes,
                "canonical generated proof material descriptorBytes",
            ),
        });
        proofRecords.push({
            objectType: "TrusteeEvaluationKeyProof",
            ...contextFields(input.setupContext),
            trusteeIdentity: trusteeReference.trusteeIdentity,
            trusteeRosterPosition: trusteeReference.trusteeRosterPosition,
            statementHash: generatedProof.statementHash,
            proofBytesHash: generatedProof.proofBytesHash,
            proofMaterialRoot: generatedProof.proofMaterialRoot,
        } satisfies TrusteeEvaluationKeyProofRecord);
    }
    if (proofRecords.length === 0) {
        throw new Error(
            "trustee evaluation-key proofs require at least one participant.",
        );
    }
    if (
        usedComponentMaterialRoots.size !== componentMaterialSourcesByRoot.size
    ) {
        throw new Error(
            "evaluationKeyShareComponentMaterialChunkSources contains material that no evaluation-key share record references.",
        );
    }

    const trusteeEvaluationKeyProofs = {
        objectType: "TrusteeEvaluationKeyProofSet",
        proofRecords,
    } satisfies TrusteeEvaluationKeyProofSet;

    return {
        trusteeEvaluationKeyProofs,
        transportedEvaluationKeyShareProofMaterial: {
            objectType: evaluationKeyShareProofTransportSetObjectType,
            proofMaterials: transportedProofMaterials,
        },
    };
};

type TrusteeEvaluationKeyProofMaterialTransport = Readonly<{
    readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
    readonly transportedEvaluationKeyShareProofMaterial: TransportedEvaluationKeyShareProofMaterialSet;
}>;
