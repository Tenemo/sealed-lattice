import { foundationProfile, type ProtocolHash } from '@sealed-lattice/types';

import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import {
    bytesToHex,
    deriveCollectiveBgvSetupContextHash,
} from '../common-fields.js';
import { deriveEvaluatorKeyScheduleRoot } from '../evaluator-key-schedule.js';

import {
    type EvaluationKeyShareComponentMaterialStream,
    type RelinearizationKeyShareRounds,
    type TransportedEvaluationKeyShareProofMaterialSet,
    type TrusteeEvaluationKeyProofSet,
    type TrusteeEvaluationKeyProofsInput,
    type TrusteeEvaluationKeyStatementKey,
    type TrusteeEvaluationKeyWitnessInput,
    evaluationKeyShareComponentMaterialMagic,
} from './constants-and-types.js';
import {
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    assertJsonRecord,
    freshProofRandomnessHex,
} from './encoding.js';
import {
    assertSetupContextHashMatches,
    validateCommonInput,
} from './share-records.js';

class BoundedComponentMaterialReader {
    readonly #pullChunk: EvaluationKeyShareComponentMaterialStream['pullChunk'];
    readonly #totalByteLength: number;
    #chunk?: Uint8Array;
    #chunkByteOffset = 0;
    #chunkIndex = 0;
    #consumedByteLength = 0;

    public constructor(
        pullChunk: EvaluationKeyShareComponentMaterialStream['pullChunk'],
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
                    'transported component material ended unexpectedly.',
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

    public async finish(): Promise<void> {
        if (this.#consumedByteLength !== this.#totalByteLength) {
            throw new Error(
                'transported component material has trailing bytes.',
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
                'transported component material has trailing chunks.',
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
            Object.prototype.toString.call(chunk) !== '[object ArrayBuffer]' ||
            chunk.byteLength !== expectedByteLength
        ) {
            throw new Error(
                'transported component material source returned the wrong chunk length.',
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
}

type DecodedEvaluationKeyShareComponentMaterial = Readonly<{
    readonly componentBByDigit: readonly (readonly (readonly number[])[])[];
    readonly componentMaterialBytesHex: string;
}>;

const safeUnsignedWord = (view: DataView, byteOffset: number): number => {
    const value = view.getBigUint64(byteOffset, true);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(
            'transported component material contains a value outside the JavaScript safe integer range.',
        );
    }

    return Number(value);
};

const decodeTransportedComponentMaterial = async (
    componentMaterialStream: EvaluationKeyShareComponentMaterialStream,
    totalByteLength: number,
    level: number,
    ringDegree: number,
    qSharePrimes: readonly number[],
): Promise<DecodedEvaluationKeyShareComponentMaterial> => {
    const digitCount = level + 1;
    const reader = new BoundedComponentMaterialReader(
        componentMaterialStream.pullChunk,
        totalByteLength,
    );
    const materialBytes = await reader.readBytes(totalByteLength);
    try {
        await reader.finish();
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
        const view = new DataView(
            materialBytes.buffer,
            materialBytes.byteOffset,
            materialBytes.byteLength,
        );
        let byteOffset = evaluationKeyShareComponentMaterialMagic.byteLength;
        const componentBByDigit: number[][][] = [];
        for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
            const componentBByLimb: number[][] = [];
            for (
                let rnsLimbIndex = 0;
                rnsLimbIndex < digitCount;
                rnsLimbIndex += 1
            ) {
                const coefficients: number[] = [];
                for (
                    let coefficientIndex = 0;
                    coefficientIndex < ringDegree;
                    coefficientIndex += 1
                ) {
                    const coefficient = safeUnsignedWord(view, byteOffset);
                    byteOffset += 8;
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
        if (byteOffset !== materialBytes.byteLength) {
            throw new Error(
                'transported component material has trailing bytes.',
            );
        }

        return {
            componentBByDigit,
            componentMaterialBytesHex: bytesToHex(materialBytes),
        };
    } finally {
        materialBytes.fill(0);
    }
};

const componentMaterialFromTransport = async (
    expectedMaterialRoot: ProtocolHash,
    level: number,
    ringDegree: number,
    qSharePrimes: readonly number[],
    componentMaterialStreamsByRoot: ReadonlyMap<
        string,
        EvaluationKeyShareComponentMaterialStream
    >,
    decodedComponentMaterialByRoot: Map<
        string,
        Promise<DecodedEvaluationKeyShareComponentMaterial>
    >,
    usedComponentMaterialRoots: Set<string>,
    objectPath: string,
): Promise<DecodedEvaluationKeyShareComponentMaterial> => {
    assertNonNegativeSafeInteger(level, `${objectPath}.level`);
    const digitCount = level + 1;
    if (digitCount > qSharePrimes.length) {
        throw new Error(`${objectPath}.level is outside the Q_share basis.`);
    }
    assertProtocolHash(expectedMaterialRoot, objectPath);
    const componentMaterialStream =
        componentMaterialStreamsByRoot.get(expectedMaterialRoot);
    if (componentMaterialStream === undefined) {
        throw new Error(
            `${objectPath} must have one component material stream in canonical record order.`,
        );
    }
    const descriptorBytes = componentMaterialStream.descriptorBytes;
    if (
        !ArrayBuffer.isView(descriptorBytes) ||
        Object.prototype.toString.call(descriptorBytes) !==
            '[object Uint8Array]' ||
        descriptorBytes.byteLength === 0
    ) {
        throw new TypeError(
            `${objectPath} transported component material requires non-empty descriptorBytes.`,
        );
    }
    if (typeof componentMaterialStream.pullChunk !== 'function') {
        throw new TypeError(
            `${objectPath} component material pullChunk must be a function.`,
        );
    }
    usedComponentMaterialRoots.add(expectedMaterialRoot);
    const totalByteLength =
        evaluationKeyShareComponentMaterialMagic.byteLength +
        digitCount * digitCount * ringDegree * 8;
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength <= 0) {
        throw new Error(
            `${objectPath} transported component material length is outside the JavaScript safe integer range.`,
        );
    }
    let decodedMaterial =
        decodedComponentMaterialByRoot.get(expectedMaterialRoot);
    if (decodedMaterial === undefined) {
        decodedMaterial = decodeTransportedComponentMaterial(
            componentMaterialStream,
            totalByteLength,
            level,
            ringDegree,
            qSharePrimes,
        );
        decodedComponentMaterialByRoot.set(
            expectedMaterialRoot,
            decodedMaterial,
        );
    }

    return decodedMaterial;
};

const relinearizationRecordForTrusteeAndLevel = (
    roots: readonly ProtocolHash[],
    trusteeRosterPosition: number,
    level: number,
    scheduledLevels: readonly number[],
    participantCount: number,
    recordFieldName: string,
): ProtocolHash => {
    const levelIndex = scheduledLevels.indexOf(level);
    const expectedRecordCount = scheduledLevels.length * participantCount;
    if (
        levelIndex < 0 ||
        roots.length !== expectedRecordCount ||
        trusteeRosterPosition >= participantCount
    ) {
        throw new Error(
            `${recordFieldName} must contain exactly one record per scheduled trustee and level.`,
        );
    }
    const root = roots[levelIndex * participantCount + trusteeRosterPosition];
    if (root === undefined) {
        throw new Error(
            `${recordFieldName} must contain exactly one record per scheduled trustee and level.`,
        );
    }

    return root;
};

const componentMaterialStreamsByAuthoritativeRoot = (
    relinearizationKeyShareRounds: RelinearizationKeyShareRounds,
    galoisKeyShareBatches: TrusteeEvaluationKeyProofsInput['galoisKeyShareBatches'],
    componentMaterialStreams: readonly EvaluationKeyShareComponentMaterialStream[],
    scheduledLevelCount: number,
    requiredGaloisKeyCount: number,
    participantCount: number,
): ReadonlyMap<string, EvaluationKeyShareComponentMaterialStream> => {
    const expectedRelinearizationRecordCount =
        scheduledLevelCount * participantCount;
    if (
        relinearizationKeyShareRounds.roundOneKeySwitchComponentMaterialRoots
            .length !== expectedRelinearizationRecordCount ||
        relinearizationKeyShareRounds.roundTwoKeySwitchComponentMaterialRoots
            .length !== expectedRelinearizationRecordCount
    ) {
        throw new Error(
            'Relinearization records must contain exactly one record per scheduled trustee and level.',
        );
    }
    if (galoisKeyShareBatches.length !== participantCount) {
        throw new Error(
            'galoisKeyShareBatches must contain one batch per participant.',
        );
    }

    const authoritativeRoots: Readonly<{
        readonly root: ProtocolHash;
        readonly objectPath: string;
    }>[] = [
        ...relinearizationKeyShareRounds.roundOneKeySwitchComponentMaterialRoots.map(
            (root, rootIndex) => ({
                root,
                objectPath: `relinearizationKeyShareRounds.roundOneKeySwitchComponentMaterialRoots.${String(rootIndex)}`,
            }),
        ),
        ...relinearizationKeyShareRounds.roundTwoKeySwitchComponentMaterialRoots.map(
            (root, rootIndex) => ({
                root,
                objectPath: `relinearizationKeyShareRounds.roundTwoKeySwitchComponentMaterialRoots.${String(rootIndex)}`,
            }),
        ),
        ...galoisKeyShareBatches.flatMap((batch, batchIndex) => {
            if (
                batch.keySwitchComponentMaterialRoots.length !==
                requiredGaloisKeyCount
            ) {
                throw new Error(
                    'keySwitchComponentMaterialRoots must follow the frozen Galois key schedule.',
                );
            }
            return batch.keySwitchComponentMaterialRoots.map(
                (root, rootIndex) => ({
                    root,
                    objectPath: `galoisKeyShareBatches.${String(batchIndex)}.keySwitchComponentMaterialRoots.${String(rootIndex)}`,
                }),
            );
        }),
    ];
    if (componentMaterialStreams.length !== authoritativeRoots.length) {
        throw new Error(
            'evaluationKeyShareComponentMaterialStreams must contain one stream per evaluation-key share record in canonical order.',
        );
    }

    const streamsByRoot = new Map<
        string,
        EvaluationKeyShareComponentMaterialStream
    >();
    authoritativeRoots.forEach(({ root, objectPath }, recordIndex) => {
        assertProtocolHash(root, objectPath);
        if (streamsByRoot.has(root)) {
            throw new Error(
                'Evaluation-key share records must not repeat a component material root.',
            );
        }
        const componentMaterialStream = componentMaterialStreams[recordIndex];
        if (
            componentMaterialStream === null ||
            typeof componentMaterialStream !== 'object'
        ) {
            throw new TypeError(
                `evaluationKeyShareComponentMaterialStreams.${String(recordIndex)} must be an object.`,
            );
        }
        streamsByRoot.set(root, componentMaterialStream);
    });

    return streamsByRoot;
};

// The public round-one aggregate diagonal per scheduled level: for digit j,
// the sum over every trustee of its round-one component b at (digit j, limb j)
// mod the j-th Q_share prime. Mirrors the kernel recomputation so the prover
// statement matches the verifier-rebuilt statement.
const roundOnePublicAggregateDiagonals = async (
    relinearizationKeyShareRounds: RelinearizationKeyShareRounds,
    ringDegree: number,
    qSharePrimes: readonly number[],
    participantCount: number,
    scheduledLevels: readonly number[],
    componentMaterialStreamsByRoot: ReadonlyMap<
        string,
        EvaluationKeyShareComponentMaterialStream
    >,
    decodedComponentMaterialByRoot: Map<
        string,
        Promise<DecodedEvaluationKeyShareComponentMaterial>
    >,
    usedComponentMaterialRoots: Set<string>,
): Promise<ReadonlyMap<number, number[][]>> => {
    if (
        relinearizationKeyShareRounds.roundOneKeySwitchComponentMaterialRoots
            .length !==
        scheduledLevels.length * participantCount
    ) {
        throw new Error(
            'roundOneKeySwitchComponentMaterialRoots must contain one root per scheduled trustee and level.',
        );
    }
    const aggregatesByLevel = new Map<
        number,
        { aggregate: number[][]; contributionCount: number }
    >();
    for (const [
        recordIndex,
        componentMaterialRoot,
    ] of relinearizationKeyShareRounds.roundOneKeySwitchComponentMaterialRoots.entries()) {
        const level =
            scheduledLevels[Math.floor(recordIndex / participantCount)];
        if (level === undefined) {
            throw new Error(
                'roundOneKeySwitchComponentMaterialRoots must follow the frozen relinearization schedule.',
            );
        }
        const digitCount = level + 1;
        const componentMaterial = await componentMaterialFromTransport(
            componentMaterialRoot,
            level,
            ringDegree,
            qSharePrimes,
            componentMaterialStreamsByRoot,
            decodedComponentMaterialByRoot,
            usedComponentMaterialRoots,
            'roundOneKeySwitchComponentMaterialRoots',
        );
        const components = componentMaterial.componentBByDigit;
        if ((components[0]?.[0]?.length ?? 0) !== ringDegree) {
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
    }
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

export const createTrusteeEvaluationKeyProofs = async (
    input: TrusteeEvaluationKeyProofsInput,
): Promise<TrusteeEvaluationKeyProofMaterialTransport> => {
    const trusteeReferences = validateCommonInput(input);
    const participantCount = input.setupContext.participantCount;
    if (input.galoisKeyShareBatches.length !== participantCount) {
        throw new Error(
            'galoisKeyShareBatches must contain one batch per participant.',
        );
    }
    input.galoisKeyShareBatches.forEach((batch) => {
        if (
            batch.keySwitchComponentMaterialRoots.length !==
            input.evaluatorKeySchedule.requiredGaloisKeySchedule.length
        ) {
            throw new Error(
                'keySwitchComponentMaterialRoots must follow the frozen Galois key schedule.',
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
    assertSetupContextHashMatches(
        input.setupContext,
        sameSecretBridgeStatementSet,
        'sameSecretBridgeStatementSet',
    );
    assertProtocolHash(
        sameSecretBridgeStatementSet.publicMatrixSeedHash,
        'sameSecretBridgeStatementSet.publicMatrixSeedHash',
    );
    assertPositiveSafeInteger(
        sameSecretBridgeStatementSet.ringDegree,
        'sameSecretBridgeStatementSet.ringDegree',
    );
    if (
        sameSecretBridgeStatementSet.statementRecords.length !==
        participantCount
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
                const expectedTrusteeReference =
                    trusteeReferences[expectedRosterPosition];
                if (expectedTrusteeReference === undefined) {
                    throw new Error(
                        'sameSecretBridgeStatementSet statement records must follow the canonical trustee roster order.',
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
                            sourceCommitmentRecord,
                            'sameSecretBridgeStatementSet.sourceConstantCoefficientCommitments',
                        );
                        if (
                            sourceCommitment.objectType !== 'SetupCommitment' ||
                            sourceCommitment.sourceRnsLimbIndex !==
                                expectedRnsLimbIndex ||
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

                return [expectedRosterPosition, statementRecord] as const;
            },
        ),
    );
    if (bridgeStatementsByRosterPosition.size !== participantCount) {
        throw new Error(
            'sameSecretBridgeStatementSet must not repeat a trustee roster position.',
        );
    }

    const scheduledLevels =
        input.evaluatorKeySchedule.relinearizationLevelSchedule.map(
            (entry) => entry.level,
        );
    const componentMaterialStreamsByRoot =
        componentMaterialStreamsByAuthoritativeRoot(
            input.relinearizationKeyShareRounds,
            input.galoisKeyShareBatches,
            input.evaluationKeyShareComponentMaterialStreams,
            scheduledLevels.length,
            input.evaluatorKeySchedule.requiredGaloisKeySchedule.length,
            participantCount,
        );
    const usedComponentMaterialRoots = new Set<string>();
    const decodedComponentMaterialByRoot = new Map<
        string,
        Promise<DecodedEvaluationKeyShareComponentMaterial>
    >();
    const ringDegree = sameSecretBridgeStatementSet.ringDegree;
    const aggregateDiagonalsByLevel = await roundOnePublicAggregateDiagonals(
        input.relinearizationKeyShareRounds,
        ringDegree,
        input.qSharePrimes,
        participantCount,
        scheduledLevels,
        componentMaterialStreamsByRoot,
        decodedComponentMaterialByRoot,
        usedComponentMaterialRoots,
    );

    const proofMaterialStreams: TransportedEvaluationKeyShareProofMaterialSet['proofMaterialStreams'][number][] =
        [];
    const proofBytesHashes: ProtocolHash[] = [];
    for (const trusteeReference of trusteeReferences) {
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
        const statementKeys: TrusteeEvaluationKeyStatementKey[] = [];
        for (const level of scheduledLevels) {
            const record = relinearizationRecordForTrusteeAndLevel(
                input.relinearizationKeyShareRounds
                    .roundOneKeySwitchComponentMaterialRoots,
                trusteeReference.trusteeRosterPosition,
                level,
                scheduledLevels,
                participantCount,
                'roundOneKeySwitchComponentMaterialRoots',
            );
            const componentMaterial = await componentMaterialFromTransport(
                record,
                level,
                ringDegree,
                input.qSharePrimes,
                componentMaterialStreamsByRoot,
                decodedComponentMaterialByRoot,
                usedComponentMaterialRoots,
                'roundOneKeySwitchComponentMaterialRoots',
            );
            statementKeys.push({
                proofFamily: 'relinearization-round-one',
                level,
                componentMaterialBytesHex:
                    componentMaterial.componentMaterialBytesHex,
            });
        }
        for (const level of scheduledLevels) {
            const record = relinearizationRecordForTrusteeAndLevel(
                input.relinearizationKeyShareRounds
                    .roundTwoKeySwitchComponentMaterialRoots,
                trusteeReference.trusteeRosterPosition,
                level,
                scheduledLevels,
                participantCount,
                'roundTwoKeySwitchComponentMaterialRoots',
            );
            const aggregateDiagonal = aggregateDiagonalsByLevel.get(level);
            if (aggregateDiagonal === undefined) {
                throw new Error(
                    'round-one public aggregate diagonal is missing for a scheduled level.',
                );
            }
            const componentMaterial = await componentMaterialFromTransport(
                record,
                level,
                ringDegree,
                input.qSharePrimes,
                componentMaterialStreamsByRoot,
                decodedComponentMaterialByRoot,
                usedComponentMaterialRoots,
                'roundTwoKeySwitchComponentMaterialRoots',
            );
            statementKeys.push({
                proofFamily: 'relinearization-round-two',
                level,
                componentMaterialBytesHex:
                    componentMaterial.componentMaterialBytesHex,
                roundOneAggregateDiagonal: aggregateDiagonal,
            });
        }
        const batch =
            input.galoisKeyShareBatches[trusteeReference.trusteeRosterPosition];
        for (const [
            scheduleIndex,
            scheduleEntry,
        ] of input.evaluatorKeySchedule.requiredGaloisKeySchedule.entries()) {
            const materialRoot =
                batch.keySwitchComponentMaterialRoots[scheduleIndex];
            if (materialRoot === undefined) {
                throw new Error(
                    'keySwitchComponentMaterialRoots must follow the frozen Galois key schedule.',
                );
            }
            const componentMaterial = await componentMaterialFromTransport(
                materialRoot,
                scheduleEntry.level,
                ringDegree,
                input.qSharePrimes,
                componentMaterialStreamsByRoot,
                decodedComponentMaterialByRoot,
                usedComponentMaterialRoots,
                'keySwitchComponentMaterialRoots',
            );
            statementKeys.push({
                proofFamily: 'galois-rotation',
                rotation: scheduleEntry.rotation,
                level: scheduleEntry.level,
                componentMaterialBytesHex:
                    componentMaterial.componentMaterialBytesHex,
            });
        }
        if (witness.errorCoefficientsByKey.length !== statementKeys.length) {
            throw new Error(
                'trusteeWitnesses.errorCoefficientsByKey must contain one error vector set per statement key.',
            );
        }
        const proofRandomnessSeedHex = freshProofRandomnessHex();
        const generatedProof = await input.trusteeEvaluationKeyProofGenerator({
            context: {
                setupContextHash: deriveCollectiveBgvSetupContextHash(
                    input.setupContext,
                ),
                trusteeRosterPosition: trusteeReference.trusteeRosterPosition,
                evaluatorKeyScheduleRoot: deriveEvaluatorKeyScheduleRoot(
                    input.evaluatorKeySchedule,
                ),
            },
            keys: statementKeys,
            sameSecretLinkage: {
                publicMatrixSeedHash:
                    sameSecretBridgeStatementSet.publicMatrixSeedHash,
                commitments: [sourceConstantCommitment],
            },
            secretCoefficients: witness.secretCoefficients,
            errorCoefficientsByKey: witness.errorCoefficientsByKey,
            openingRandomnessBySourceLimbAndCommitmentLimb:
                witness.openingRandomnessBySourceLimbAndCommitmentLimb,
            proofRandomnessSeedHex,
        });
        assertProtocolHash(
            generatedProof.proofBytesHash,
            'generatedProof.proofBytesHash',
        );
        if (
            typeof generatedProof.proofMaterialStream.pullChunk !== 'function'
        ) {
            throw new TypeError(
                'generated proof material stream pullChunk must be a function.',
            );
        }
        proofMaterialStreams.push({
            descriptorBytes: copyCanonicalStreamDescriptor(
                generatedProof.proofMaterialStream.descriptorBytes,
                'generated proof material stream descriptorBytes',
            ),
            pullChunk: generatedProof.proofMaterialStream.pullChunk,
        });
        proofBytesHashes.push(generatedProof.proofBytesHash);
    }
    if (proofBytesHashes.length === 0) {
        throw new Error(
            'trustee evaluation-key proofs require at least one participant.',
        );
    }
    if (
        usedComponentMaterialRoots.size !== componentMaterialStreamsByRoot.size
    ) {
        throw new Error(
            'evaluationKeyShareComponentMaterialStreams must match the canonical evaluation-key share records exactly.',
        );
    }

    const trusteeEvaluationKeyProofs = {
        objectType: 'TrusteeEvaluationKeyProofSet',
        proofBytesHashes,
    } satisfies TrusteeEvaluationKeyProofSet;

    return {
        trusteeEvaluationKeyProofs,
        transportedEvaluationKeyShareProofMaterial: {
            proofMaterialStreams,
        },
    };
};

type TrusteeEvaluationKeyProofMaterialTransport = Readonly<{
    readonly trusteeEvaluationKeyProofs: TrusteeEvaluationKeyProofSet;
    readonly transportedEvaluationKeyShareProofMaterial: TransportedEvaluationKeyShareProofMaterialSet;
}>;
