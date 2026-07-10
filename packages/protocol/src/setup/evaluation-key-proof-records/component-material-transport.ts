import { BinaryChunkWriter } from '../binary-chunk-writer.js';
import { setupProofTransportChunkSizeBytes } from '../setup-proof-material-transport.js';

import {
    type BinaryChunkedEvaluationKeyShareMaterialTransport,
    type EvaluationKeyShareComponentMaterialChunkStream,
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
    bytesToHex,
    coefficientVectorFromLittleEndianHex,
    evaluationKeyShareComponentMaterialReferenceRoot,
    evaluationKeyShareComponentMaterialTransportHashes,
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

const encodeEvaluationKeyShareComponentMaterial = (
    proofFamily: EvaluationKeyShareProofFamily,
    shareMaterial: EvaluationKeyShareMaterial &
        EvaluationKeyShareEmbeddedKeySwitchComponentMaterial,
    level: number,
): readonly Uint8Array[] => {
    const digitCount = level + 1;
    if (shareMaterial.keySwitchComponentVectors.length !== digitCount ** 2) {
        throw new Error(
            'evaluation-key component material must contain one vector per scheduled digit and RNS limb.',
        );
    }
    const writer = new BinaryChunkWriter({
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        emptyErrorMessage:
            'evaluation-key component material transport requires bytes.',
    });
    writer.writeBytes(evaluationKeyShareComponentMaterialMagic);
    writer.writeU64LittleEndian(level, 'evaluation-key level');
    writer.writeU64LittleEndian(
        shareMaterial.ringDegree,
        'evaluation-key ringDegree',
    );
    writer.writeU64LittleEndian(digitCount, 'evaluation-key digitCount');
    writer.writeU64LittleEndian(digitCount, 'evaluation-key rnsLimbCount');
    const canonicalComponentVectors: JsonRecord[] = [];
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
                component: 'b',
                coefficientByteLength,
                coefficientVectorHash512: coefficientVectorHash,
                coefficientsLeHex,
            });
            writer.writeU64LittleEndian(
                digitIndex,
                'evaluation-key component digitIndex',
            );
            writer.writeU64LittleEndian(
                rnsLimbIndex,
                'evaluation-key component rnsLimbIndex',
            );
            writer.writeU64LittleEndian(
                rnsPrime,
                'evaluation-key component rnsPrime',
            );
            writer.writeU64LittleEndian(
                shareMaterial.ringDegree,
                'evaluation-key component coefficientCount',
            );
            coefficients.forEach((coefficient) =>
                writer.writeU64LittleEndian(
                    coefficient,
                    'evaluation-key component coefficient',
                ),
            );
        }
    }
    const componentVectorRoot = evaluationKeyShareComponentVectorRoot(
        proofFamily,
        shareMaterial.keySwitchDomain,
        shareMaterial.keySwitchSeedHex,
        level,
        shareMaterial.ringDegree,
        canonicalComponentVectors,
    );
    if (componentVectorRoot !== shareMaterial.keySwitchComponentVectorRoot) {
        throw new Error(
            'evaluation-key component material root must match keySwitchComponentVectorRoot before transport.',
        );
    }

    return writer.finish();
};

const transportEvaluationKeyShareComponentMaterial = (
    workItem: EvaluationKeyShareTransportWorkItem,
): Readonly<{
    readonly shareMaterial: EvaluationKeyShareMaterial;
    readonly componentMaterial: JsonRecord;
    readonly componentMaterialChunkStream: EvaluationKeyShareComponentMaterialChunkStream;
}> => {
    const chunks = encodeEvaluationKeyShareComponentMaterial(
        workItem.proofFamily,
        workItem.shareMaterial,
        workItem.level,
    );
    const transportHashes = evaluationKeyShareComponentMaterialTransportHashes(
        workItem.proofFamily,
        chunks,
    );
    const keySwitchComponentMaterialRoot =
        evaluationKeyShareComponentMaterialReferenceRoot(
            workItem.proofFamily,
            workItem.shareMaterial,
            workItem.trusteeIdentity,
            workItem.trusteeRosterPosition,
            workItem.level,
            transportHashes,
        );
    const shareMaterial: EvaluationKeyShareMaterial = {
        keySwitchDomain: workItem.shareMaterial.keySwitchDomain,
        keySwitchSeedHex: workItem.shareMaterial.keySwitchSeedHex,
        ringDegree: workItem.shareMaterial.ringDegree,
        keySwitchComponentVectorRoot:
            workItem.shareMaterial.keySwitchComponentVectorRoot,
        keySwitchMaterialEncoding: evaluationKeyShareComponentMaterialEncoding,
        keySwitchComponentMaterialRoot,
        keySwitchComponentChunkSizeBytes: setupProofTransportChunkSizeBytes,
        keySwitchComponentChunkCount: transportHashes.chunkHashes.length,
        keySwitchComponentTotalByteLength: transportHashes.totalByteLength,
        keySwitchComponentFullObjectHash: transportHashes.fullObjectHash,
        keySwitchComponentChunkRoot: transportHashes.chunkRoot,
        keySwitchComponentChunkHashes: transportHashes.chunkHashes,
    };

    const componentMaterialChunks = chunks.map((chunk, chunkIndex) => ({
        chunkIndex,
        bytesHex: bytesToHex(chunk),
    }));

    return {
        shareMaterial,
        // The transported component material is a chunkless manifest reference:
        // the terminal accepted-setup verifier refuses inline chunks and instead
        // reads the material from the file-backed component material transport
        // stream, so the raw bytes are carried out of band in the chunk stream
        // below rather than embedded here.
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
            chunkCount: transportHashes.chunkHashes.length,
            totalByteLength: transportHashes.totalByteLength,
            fullObjectHash: transportHashes.fullObjectHash,
            chunkRoot: transportHashes.chunkRoot,
            chunkHashes: transportHashes.chunkHashes,
        },
        componentMaterialChunkStream: {
            keySwitchComponentMaterialRoot,
            proofFamily: workItem.proofFamily,
            chunks: componentMaterialChunks,
        },
    };
};

export const createBinaryChunkedEvaluationKeyShareMaterialTransport = (
    input: EvaluationKeyShareMaterialTransportInput,
): BinaryChunkedEvaluationKeyShareMaterialTransport => {
    const identities = trusteeIdentityByRosterPosition(input.trusteeReferences);
    const componentMaterials: JsonRecord[] = [];
    const componentMaterialChunkStreams: EvaluationKeyShareComponentMaterialChunkStream[] =
        [];
    const componentRoots = new Set<string>();
    const transportShareMaterial = (
        workItem: EvaluationKeyShareTransportWorkItem,
    ): EvaluationKeyShareMaterial => {
        const componentTransport =
            transportEvaluationKeyShareComponentMaterial(workItem);
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
        componentMaterialChunkStreams.push(
            componentTransport.componentMaterialChunkStream,
        );

        return componentTransport.shareMaterial;
    };

    const relinearizationRoundOneContributions =
        input.relinearizationRoundOneContributions.map((contribution) => ({
            trusteeRosterPosition: contribution.trusteeRosterPosition,
            level: contribution.level,
            roundOneShareRoot: contribution.roundOneShareRoot,
            shareMaterial: transportShareMaterial({
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
        }));
    const relinearizationRoundTwoContributions =
        input.relinearizationRoundTwoContributions.map((contribution) => ({
            trusteeRosterPosition: contribution.trusteeRosterPosition,
            level: contribution.level,
            roundTwoShareRoot: contribution.roundTwoShareRoot,
            shareMaterial: transportShareMaterial({
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
        }));
    const galoisKeyShareBatchContributions =
        input.galoisKeyShareBatchContributions.map((batchContribution) => {
            const trusteeIdentity = trusteeIdentityForContribution(
                identities,
                batchContribution.trusteeRosterPosition,
                'galoisKeyShareBatchContributions',
            );

            return {
                trusteeRosterPosition: batchContribution.trusteeRosterPosition,
                galoisKeyShares: batchContribution.galoisKeyShares.map(
                    (shareContribution) => ({
                        rotation: shareContribution.rotation,
                        level: shareContribution.level,
                        galoisKeyShareRoot:
                            shareContribution.galoisKeyShareRoot,
                        shareMaterial: transportShareMaterial({
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
                    }),
                ),
            };
        });

    return {
        relinearizationRoundOneContributions,
        relinearizationRoundTwoContributions,
        galoisKeyShareBatchContributions,
        transportedEvaluationKeyShareComponentMaterial: {
            objectType:
                evaluationKeyShareComponentMaterialTransportSetObjectType,
            componentMaterials,
        },
        evaluationKeyShareComponentMaterialChunkStreams:
            componentMaterialChunkStreams,
    };
};
