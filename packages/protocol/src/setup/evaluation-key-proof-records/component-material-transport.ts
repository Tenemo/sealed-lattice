import { copyCanonicalStreamDescriptor } from '../canonical-stream-descriptor.js';
import {
    type CanonicalProofMaterialChunkPull,
    setupProofTransportChunkSizeBytes,
} from '../setup-proof-material-transport.js';

import {
    type BinaryChunkedEvaluationKeyShareMaterialTransport,
    type EvaluationKeyShareEmbeddedKeySwitchComponentMaterial,
    type EvaluationKeyShareMaterial,
    type EvaluationKeyShareMaterialTransportInput,
    type EvaluationKeyShareProofFamily,
    type EvaluationKeyTrusteeReference,
    type JsonRecord,
    evaluationKeyShareComponentMaterialEncoding,
    evaluationKeyShareComponentMaterialMagic,
    evaluationKeyShareComponentMaterialTransportObjectType,
    evaluationKeyShareComponentMaterialTransportSetObjectType,
} from './constants-and-types.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertJsonRecord,
    bytesFromHex,
    coefficientVectorFromLittleEndianHex,
    evaluationKeyShareComponentMaterialReferenceRoot,
    evaluationKeyShareComponentVectorHash,
    evaluationKeyShareComponentVectorRoot,
    nonNegativeIntegerRecordField,
    stringRecordField,
} from './encoding.js';
import { assertEmbeddedComponentMaterial } from './share-records.js';

type EvaluationKeyShareTransportWorkItem = Readonly<{
    readonly proofFamily: EvaluationKeyShareProofFamily;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly level: number;
    readonly shareMaterial: EvaluationKeyShareMaterial &
        EvaluationKeyShareEmbeddedKeySwitchComponentMaterial;
}>;

const trusteeIdentityByRosterPosition = (
    trusteeReferences: readonly EvaluationKeyTrusteeReference[],
): ReadonlyMap<number, string> => {
    const identities = new Map<number, string>();
    trusteeReferences.forEach((reference, referenceIndex) => {
        assertNonEmptyString(
            reference.trusteeIdentity,
            `trusteeReferences.${String(referenceIndex)}.trusteeIdentity`,
        );
        assertNonNegativeSafeInteger(
            reference.trusteeRosterPosition,
            `trusteeReferences.${String(referenceIndex)}.trusteeRosterPosition`,
        );
        if (identities.has(reference.trusteeRosterPosition)) {
            throw new Error(
                'trusteeReferences must not repeat trusteeRosterPosition.',
            );
        }
        identities.set(
            reference.trusteeRosterPosition,
            reference.trusteeIdentity,
        );
    });

    return identities;
};

const trusteeIdentityForContribution = (
    identities: ReadonlyMap<number, string>,
    trusteeRosterPosition: number,
    fieldName: string,
): string => {
    const trusteeIdentity = identities.get(trusteeRosterPosition);
    if (trusteeIdentity === undefined) {
        throw new Error(
            `${fieldName} references a trustee roster position without a trustee reference.`,
        );
    }

    return trusteeIdentity;
};

type CanonicalComponentVector = Readonly<{
    readonly digitIndex: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly coefficientByteLength: number;
    readonly coefficientVectorHash512: string;
    readonly coefficientsLeHex: string;
}>;

type ValidatedComponentMaterial = Readonly<{
    readonly componentVectors: readonly CanonicalComponentVector[];
    readonly digitCount: number;
    readonly totalByteLength: number;
}>;

const validatedEvaluationKeyShareComponentMaterial = (
    proofFamily: EvaluationKeyShareProofFamily,
    shareMaterial: EvaluationKeyShareMaterial &
        EvaluationKeyShareEmbeddedKeySwitchComponentMaterial,
    level: number,
): ValidatedComponentMaterial => {
    const digitCount = level + 1;
    if (shareMaterial.keySwitchComponentVectors.length !== digitCount ** 2) {
        throw new Error(
            'evaluation-key component material must contain one vector per scheduled digit and RNS limb.',
        );
    }
    const canonicalComponentVectors: CanonicalComponentVector[] = [];
    for (let digitIndex = 0; digitIndex < digitCount; digitIndex += 1) {
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < digitCount;
            rnsLimbIndex += 1
        ) {
            const componentVector = assertJsonRecord(
                shareMaterial.keySwitchComponentVectors[
                    digitIndex * digitCount + rnsLimbIndex
                ],
                'keySwitchComponentVectors',
            );
            const vectorPath = `keySwitchComponentVectors.${String(
                digitIndex,
            )}.${String(rnsLimbIndex)}`;
            if (
                nonNegativeIntegerRecordField(
                    componentVector,
                    'digitIndex',
                    vectorPath,
                ) !== digitIndex ||
                nonNegativeIntegerRecordField(
                    componentVector,
                    'rnsLimbIndex',
                    vectorPath,
                ) !== rnsLimbIndex ||
                componentVector.component !== 'b'
            ) {
                throw new Error(
                    'evaluation-key component material vectors must be ordered by digit and RNS limb.',
                );
            }
            const rnsPrime = nonNegativeIntegerRecordField(
                componentVector,
                'rnsPrime',
                vectorPath,
            );
            const coefficientByteLength = nonNegativeIntegerRecordField(
                componentVector,
                'coefficientByteLength',
                vectorPath,
            );
            if (coefficientByteLength !== shareMaterial.ringDegree * 8) {
                throw new Error(
                    'evaluation-key component material coefficientByteLength must match ringDegree.',
                );
            }
            const coefficientsLeHex = stringRecordField(
                componentVector,
                'coefficientsLeHex',
                vectorPath,
            );
            const coefficients = coefficientVectorFromLittleEndianHex(
                coefficientsLeHex,
                shareMaterial.ringDegree,
                `${vectorPath}.coefficientsLeHex`,
            );
            if (coefficients.some((coefficient) => coefficient >= rnsPrime)) {
                throw new Error(
                    'evaluation-key component material coefficients must be canonical residues.',
                );
            }
            const coefficientVectorHash =
                evaluationKeyShareComponentVectorHash(coefficients);
            if (
                stringRecordField(
                    componentVector,
                    'coefficientVectorHash512',
                    vectorPath,
                ) !== coefficientVectorHash
            ) {
                throw new Error(
                    'evaluation-key component material coefficient hash must match coefficientsLeHex.',
                );
            }
            canonicalComponentVectors.push({
                digitIndex,
                rnsLimbIndex,
                rnsPrime,
                coefficientByteLength,
                coefficientVectorHash512: coefficientVectorHash,
                coefficientsLeHex,
            });
        }
    }
    const componentVectorRoot = evaluationKeyShareComponentVectorRoot(
        proofFamily,
        shareMaterial.keySwitchDomain,
        shareMaterial.keySwitchSeedHex,
        level,
        shareMaterial.ringDegree,
        canonicalComponentVectors.map((vector) => ({
            ...vector,
            component: 'b',
        })),
    );
    if (componentVectorRoot !== shareMaterial.keySwitchComponentVectorRoot) {
        throw new Error(
            'evaluation-key component material root must match keySwitchComponentVectorRoot before transport.',
        );
    }

    const componentVectorByteLength = 4 * 8 + shareMaterial.ringDegree * 8;
    const totalByteLength =
        evaluationKeyShareComponentMaterialMagic.byteLength +
        4 * 8 +
        canonicalComponentVectors.length * componentVectorByteLength;
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength <= 0) {
        throw new Error(
            'evaluation-key component material byte length is outside the JavaScript safe integer range.',
        );
    }

    return {
        componentVectors: canonicalComponentVectors,
        digitCount,
        totalByteLength,
    };
};

const writeUnsignedWord = (
    destination: Uint8Array,
    byteOffset: number,
    value: number,
): void => {
    const view = new DataView(
        destination.buffer,
        destination.byteOffset,
        destination.byteLength,
    );
    view.setBigUint64(byteOffset, BigInt(value), true);
};

const evaluationKeyShareComponentMaterialSegments = function* (
    level: number,
    ringDegree: number,
    validatedMaterial: ValidatedComponentMaterial,
): Generator<Uint8Array> {
    const header = new Uint8Array(
        evaluationKeyShareComponentMaterialMagic.byteLength + 4 * 8,
    );
    header.set(evaluationKeyShareComponentMaterialMagic);
    let headerOffset = evaluationKeyShareComponentMaterialMagic.byteLength;
    for (const value of [
        level,
        ringDegree,
        validatedMaterial.digitCount,
        validatedMaterial.digitCount,
    ]) {
        writeUnsignedWord(header, headerOffset, value);
        headerOffset += 8;
    }
    yield header;

    for (const componentVector of validatedMaterial.componentVectors) {
        const coefficientBytes = bytesFromHex(
            componentVector.coefficientsLeHex,
            'evaluation-key component coefficientsLeHex',
        );
        if (
            coefficientBytes.byteLength !==
            componentVector.coefficientByteLength
        ) {
            throw new Error(
                'evaluation-key component coefficient bytes must match coefficientByteLength.',
            );
        }
        const encodedVector = new Uint8Array(4 * 8 + coefficientBytes.length);
        writeUnsignedWord(encodedVector, 0, componentVector.digitIndex);
        writeUnsignedWord(encodedVector, 8, componentVector.rnsLimbIndex);
        writeUnsignedWord(encodedVector, 16, componentVector.rnsPrime);
        writeUnsignedWord(encodedVector, 24, ringDegree);
        encodedVector.set(coefficientBytes, 4 * 8);
        coefficientBytes.fill(0);
        yield encodedVector;
    }
};

const sequentialChunkPull = (
    segments: Generator<Uint8Array>,
    totalByteLength: number,
): CanonicalProofMaterialChunkPull => {
    let currentSegment: Uint8Array | undefined;
    let currentSegmentOffset = 0;
    let nextChunkIndex = 0;
    let emittedByteLength = 0;

    return ({ chunkIndex, expectedByteLength }) =>
        Promise.resolve().then(() => {
            if (chunkIndex !== nextChunkIndex) {
                throw new Error(
                    'evaluation-key component material chunks must be pulled in ascending order.',
                );
            }
            if (emittedByteLength === totalByteLength) {
                if (expectedByteLength !== 0) {
                    throw new Error(
                        'evaluation-key component material source was pulled past its declared length.',
                    );
                }
                nextChunkIndex += 1;
                return undefined;
            }
            const remainingByteLength = totalByteLength - emittedByteLength;
            const requiredByteLength = Math.min(
                setupProofTransportChunkSizeBytes,
                remainingByteLength,
            );
            if (expectedByteLength !== requiredByteLength) {
                throw new Error(
                    'evaluation-key component material pull length does not match the canonical chunk boundary.',
                );
            }
            const chunk = new Uint8Array(requiredByteLength);
            let writeOffset = 0;
            while (writeOffset < chunk.length) {
                if (
                    currentSegment === undefined ||
                    currentSegmentOffset === currentSegment.length
                ) {
                    currentSegment?.fill(0);
                    const nextSegment = segments.next();
                    if (nextSegment.done) {
                        throw new Error(
                            'evaluation-key component material encoder ended before its declared length.',
                        );
                    }
                    currentSegment = nextSegment.value;
                    currentSegmentOffset = 0;
                }
                const copyByteLength = Math.min(
                    currentSegment.length - currentSegmentOffset,
                    chunk.length - writeOffset,
                );
                chunk.set(
                    currentSegment.subarray(
                        currentSegmentOffset,
                        currentSegmentOffset + copyByteLength,
                    ),
                    writeOffset,
                );
                currentSegmentOffset += copyByteLength;
                writeOffset += copyByteLength;
            }
            emittedByteLength += chunk.length;
            nextChunkIndex += 1;

            return chunk.buffer;
        });
};

const transportEvaluationKeyShareComponentMaterial = async (
    workItem: EvaluationKeyShareTransportWorkItem,
    writeComponentMaterial: EvaluationKeyShareMaterialTransportInput['writeEvaluationKeyShareComponentMaterial'],
): Promise<
    Readonly<{
        readonly shareMaterial: EvaluationKeyShareMaterial;
        readonly componentMaterial: JsonRecord;
    }>
> => {
    const validatedMaterial = validatedEvaluationKeyShareComponentMaterial(
        workItem.proofFamily,
        workItem.shareMaterial,
        workItem.level,
    );
    const keySwitchComponentMaterialRoot =
        evaluationKeyShareComponentMaterialReferenceRoot(
            workItem.proofFamily,
            workItem.shareMaterial,
            workItem.trusteeIdentity,
            workItem.trusteeRosterPosition,
            workItem.level,
        );
    const shareMaterial: EvaluationKeyShareMaterial = {
        keySwitchDomain: workItem.shareMaterial.keySwitchDomain,
        keySwitchSeedHex: workItem.shareMaterial.keySwitchSeedHex,
        ringDegree: workItem.shareMaterial.ringDegree,
        keySwitchComponentVectorRoot:
            workItem.shareMaterial.keySwitchComponentVectorRoot,
        keySwitchMaterialEncoding: evaluationKeyShareComponentMaterialEncoding,
        keySwitchComponentMaterialRoot,
    };
    const descriptorBytes = copyCanonicalStreamDescriptor(
        await writeComponentMaterial({
            keySwitchComponentMaterialRoot,
            proofFamily: workItem.proofFamily,
            pullChunk: sequentialChunkPull(
                evaluationKeyShareComponentMaterialSegments(
                    workItem.level,
                    workItem.shareMaterial.ringDegree,
                    validatedMaterial,
                ),
                validatedMaterial.totalByteLength,
            ),
            totalByteLength: validatedMaterial.totalByteLength,
        }),
        'writeEvaluationKeyShareComponentMaterial descriptorBytes',
    );

    return {
        shareMaterial,
        componentMaterial: {
            objectType: evaluationKeyShareComponentMaterialTransportObjectType,
            proofFamily: workItem.proofFamily,
            keySwitchMaterialEncoding:
                evaluationKeyShareComponentMaterialEncoding,
            trusteeIdentity: workItem.trusteeIdentity,
            trusteeRosterPosition: workItem.trusteeRosterPosition,
            keySwitchDomain: workItem.shareMaterial.keySwitchDomain,
            keySwitchSeedHex: workItem.shareMaterial.keySwitchSeedHex,
            level: workItem.level,
            ringDegree: workItem.shareMaterial.ringDegree,
            digitCount: workItem.level + 1,
            rnsLimbCount: workItem.level + 1,
            keySwitchComponentVectorRoot:
                workItem.shareMaterial.keySwitchComponentVectorRoot,
            keySwitchComponentMaterialRoot,
            descriptorBytes,
        },
    };
};

export const createBinaryChunkedEvaluationKeyShareMaterialTransport = async (
    input: EvaluationKeyShareMaterialTransportInput,
): Promise<BinaryChunkedEvaluationKeyShareMaterialTransport> => {
    const identities = trusteeIdentityByRosterPosition(input.trusteeReferences);
    const componentMaterials: JsonRecord[] = [];
    const componentRoots = new Set<string>();
    const transportShareMaterial = async (
        workItem: EvaluationKeyShareTransportWorkItem,
    ): Promise<EvaluationKeyShareMaterial> => {
        const componentTransport =
            await transportEvaluationKeyShareComponentMaterial(
                workItem,
                input.writeEvaluationKeyShareComponentMaterial,
            );
        const componentMaterialRoot = stringRecordField(
            componentTransport.componentMaterial,
            'keySwitchComponentMaterialRoot',
            'componentMaterial',
        );
        if (componentRoots.has(componentMaterialRoot)) {
            throw new Error(
                'transported evaluation-key component material contains duplicate roots.',
            );
        }
        componentRoots.add(componentMaterialRoot);
        componentMaterials.push(componentTransport.componentMaterial);

        return componentTransport.shareMaterial;
    };

    const relinearizationRoundOneContributions: BinaryChunkedEvaluationKeyShareMaterialTransport['relinearizationRoundOneContributions'][number][] =
        [];
    for (const contribution of input.relinearizationRoundOneContributions) {
        relinearizationRoundOneContributions.push({
            trusteeRosterPosition: contribution.trusteeRosterPosition,
            level: contribution.level,
            roundOneShareRoot: contribution.roundOneShareRoot,
            shareMaterial: await transportShareMaterial({
                proofFamily: 'relinearization-key-share',
                trusteeIdentity: trusteeIdentityForContribution(
                    identities,
                    contribution.trusteeRosterPosition,
                    'relinearizationRoundOneContributions',
                ),
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                shareMaterial: assertEmbeddedComponentMaterial(
                    contribution.shareMaterial,
                    'relinearizationRoundOneContributions.shareMaterial',
                ),
            }),
        });
    }
    const relinearizationRoundTwoContributions: BinaryChunkedEvaluationKeyShareMaterialTransport['relinearizationRoundTwoContributions'][number][] =
        [];
    for (const contribution of input.relinearizationRoundTwoContributions) {
        relinearizationRoundTwoContributions.push({
            trusteeRosterPosition: contribution.trusteeRosterPosition,
            level: contribution.level,
            roundTwoShareRoot: contribution.roundTwoShareRoot,
            shareMaterial: await transportShareMaterial({
                proofFamily: 'relinearization-key-share',
                trusteeIdentity: trusteeIdentityForContribution(
                    identities,
                    contribution.trusteeRosterPosition,
                    'relinearizationRoundTwoContributions',
                ),
                trusteeRosterPosition: contribution.trusteeRosterPosition,
                level: contribution.level,
                shareMaterial: assertEmbeddedComponentMaterial(
                    contribution.shareMaterial,
                    'relinearizationRoundTwoContributions.shareMaterial',
                ),
            }),
        });
    }
    const galoisKeyShareBatchContributions: BinaryChunkedEvaluationKeyShareMaterialTransport['galoisKeyShareBatchContributions'][number][] =
        [];
    for (const batchContribution of input.galoisKeyShareBatchContributions) {
        const trusteeIdentity = trusteeIdentityForContribution(
            identities,
            batchContribution.trusteeRosterPosition,
            'galoisKeyShareBatchContributions',
        );
        const galoisKeyShares: BinaryChunkedEvaluationKeyShareMaterialTransport['galoisKeyShareBatchContributions'][number]['galoisKeyShares'][number][] =
            [];
        for (const shareContribution of batchContribution.galoisKeyShares) {
            galoisKeyShares.push({
                rotation: shareContribution.rotation,
                level: shareContribution.level,
                galoisKeyShareRoot: shareContribution.galoisKeyShareRoot,
                shareMaterial: await transportShareMaterial({
                    proofFamily: 'galois-key-share',
                    trusteeIdentity,
                    trusteeRosterPosition:
                        batchContribution.trusteeRosterPosition,
                    level: shareContribution.level,
                    shareMaterial: assertEmbeddedComponentMaterial(
                        shareContribution.shareMaterial,
                        'galoisKeyShares.shareMaterial',
                    ),
                }),
            });
        }
        galoisKeyShareBatchContributions.push({
            trusteeRosterPosition: batchContribution.trusteeRosterPosition,
            galoisKeyShares,
        });
    }

    return {
        relinearizationRoundOneContributions,
        relinearizationRoundTwoContributions,
        galoisKeyShareBatchContributions,
        transportedEvaluationKeyShareComponentMaterial: {
            objectType:
                evaluationKeyShareComponentMaterialTransportSetObjectType,
            componentMaterials,
        },
    };
};
