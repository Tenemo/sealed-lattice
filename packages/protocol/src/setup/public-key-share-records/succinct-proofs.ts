import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    publicKeyShareProofFamily,
    type JsonRecord,
    type PublicKeyShareMaterialRootReference,
    type PublicKeyShareMaterialSet,
    type PublicKeyShareProofRecord,
    type PublicKeyShareSuccinctProofByteMaterial,
    type PublicKeyShareSuccinctProofMaterial,
    type PublicKeyShareSuccinctProofRecord,
    type PublicKeyShareSuccinctProofSet,
    type PublicKeyShareSuccinctProofSetInput,
    type PublicKeyShareSuccinctTransportedProofBytes,
} from './constants-and-types.js';
import {
    assertLowercaseHexBytes,
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertPositiveSafeInteger,
    assertProtocolHash,
    assertContextMatches,
    contextFields,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';
import { publicKeyShareRecordsByRosterPosition } from './share-statement-records.js';

const publicKeyShareProofRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        'setupContext' | 'participantCount' | 'publicKeyShareProofs'
    >,
): ReadonlyMap<number, PublicKeyShareProofRecord> => {
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    assertProtocolHash(
        input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        'publicKeyShareProofs.publicKeyShareProofSetRoot',
    );
    const proofRecords = sortedByRosterPosition(
        input.publicKeyShareProofs.proofRecords,
    );
    if (proofRecords.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareProofs.proofRecords must contain one proof statement per participant.',
        );
    }
    const recordsByRosterPosition = new Map<
        number,
        PublicKeyShareProofRecord
    >();
    proofRecords.forEach((proofRecord, expectedRosterPosition) => {
        if (proofRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShareProofs.proofRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            proofRecord.publicKeyShareProofRoot,
            'publicKeyShareProofs.proofRecords.publicKeyShareProofRoot',
        );
        recordsByRosterPosition.set(
            proofRecord.trusteeRosterPosition,
            proofRecord,
        );
    });

    return recordsByRosterPosition;
};

type SameSecretBridgeBinding = Readonly<{
    readonly trusteeIdentity: string;
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
    readonly sameSecretBridgeProofRecordRoot: ProtocolHash;
}>;

const sameSecretBridgeBindingsByRosterPosition = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        | 'setupContext'
        | 'participantCount'
        | 'publicMatrixSeedHash'
        | 'sameSecretBridgeStatementSet'
        | 'sameSecretBridgeProofMaterialSet'
    >,
): ReadonlyMap<number, SameSecretBridgeBinding> => {
    const { sameSecretBridgeStatementSet, sameSecretBridgeProofMaterialSet } =
        input;
    assertContextMatches(
        input.setupContext,
        sameSecretBridgeStatementSet,
        'sameSecretBridgeStatementSet',
    );
    assertContextMatches(
        input.setupContext,
        sameSecretBridgeProofMaterialSet,
        'sameSecretBridgeProofMaterialSet',
    );
    assertProtocolHash(
        sameSecretBridgeStatementSet.sameSecretBridgeStatementSetRoot,
        'sameSecretBridgeStatementSet.sameSecretBridgeStatementSetRoot',
    );
    if (
        sameSecretBridgeStatementSet.participantCount !==
            input.participantCount ||
        sameSecretBridgeProofMaterialSet.participantCount !==
            input.participantCount
    ) {
        throw new Error(
            'same-secret bridge statement and proof material sets must match participantCount.',
        );
    }
    if (
        sameSecretBridgeStatementSet.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        sameSecretBridgeProofMaterialSet.publicMatrixSeedHash !==
            input.publicMatrixSeedHash
    ) {
        throw new Error(
            'same-secret bridge statement and proof material sets must match publicMatrixSeedHash.',
        );
    }
    if (
        sameSecretBridgeProofMaterialSet.sameSecretBridgeStatementSetRoot !==
        sameSecretBridgeStatementSet.sameSecretBridgeStatementSetRoot
    ) {
        throw new Error(
            'sameSecretBridgeProofMaterialSet must bind sameSecretBridgeStatementSet.',
        );
    }

    const statementRecords = sortedByRosterPosition(
        sameSecretBridgeStatementSet.statementRecords,
    );
    if (statementRecords.length !== input.participantCount) {
        throw new Error(
            'sameSecretBridgeStatementSet.statementRecords must contain one statement per participant.',
        );
    }
    const proofRecords = sameSecretBridgeProofMaterialSet.proofRecords;
    if (proofRecords.length !== input.participantCount) {
        throw new Error(
            'sameSecretBridgeProofMaterialSet.proofRecords must contain one proof per participant.',
        );
    }
    const proofRecordsByStatementRoot = new Map(
        proofRecords.map((proofRecord) => {
            assertProtocolHash(
                proofRecord.sameSecretBridgeStatementRoot,
                'sameSecretBridgeProofMaterialSet.proofRecords.sameSecretBridgeStatementRoot',
            );
            assertProtocolHash(
                proofRecord.sameSecretBridgeProofRecordRoot,
                'sameSecretBridgeProofMaterialSet.proofRecords.sameSecretBridgeProofRecordRoot',
            );

            return [
                proofRecord.sameSecretBridgeStatementRoot,
                proofRecord,
            ] as const;
        }),
    );
    if (proofRecordsByStatementRoot.size !== proofRecords.length) {
        throw new Error(
            'sameSecretBridgeProofMaterialSet.proofRecords must not repeat a statement root.',
        );
    }

    const bindingsByRosterPosition = new Map<number, SameSecretBridgeBinding>();
    statementRecords.forEach((statementRecord, expectedRosterPosition) => {
        if (statementRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretBridgeStatementSet.statementRecords roster positions must be contiguous from zero.',
            );
        }
        assertNonEmptyString(
            statementRecord.trusteeIdentity,
            'sameSecretBridgeStatementSet.statementRecords.trusteeIdentity',
        );
        assertProtocolHash(
            statementRecord.sameSecretBridgeStatementRoot,
            'sameSecretBridgeStatementSet.statementRecords.sameSecretBridgeStatementRoot',
        );
        const proofRecord = proofRecordsByStatementRoot.get(
            statementRecord.sameSecretBridgeStatementRoot,
        );
        if (proofRecord === undefined) {
            throw new Error(
                'sameSecretBridgeProofMaterialSet must contain one proof for every bridge statement.',
            );
        }
        bindingsByRosterPosition.set(statementRecord.trusteeRosterPosition, {
            trusteeIdentity: statementRecord.trusteeIdentity,
            sameSecretBridgeStatementRoot:
                statementRecord.sameSecretBridgeStatementRoot,
            sameSecretBridgeProofRecordRoot:
                proofRecord.sameSecretBridgeProofRecordRoot,
        });
    });

    return bindingsByRosterPosition;
};

type PublicKeyShareMaterialProofReference =
    PublicKeyShareMaterialRootReference &
        Readonly<{
            readonly publicKeyShareRoot?: ProtocolHash;
        }>;

const publicKeyShareMaterialReferencesByRosterPosition = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        'setupContext' | 'participantCount' | 'publicKeyShareMaterial'
    >,
): ReadonlyMap<number, PublicKeyShareMaterialProofReference> => {
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    assertProtocolHash(
        input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        'publicKeyShareMaterial.publicKeyShareMaterialSetRoot',
    );
    const recordsByRosterPosition = new Map<
        number,
        PublicKeyShareMaterialProofReference
    >();
    const shareMaterialRecords = (
        input.publicKeyShareMaterial as Partial<PublicKeyShareMaterialSet>
    ).shareMaterialRecords;
    const materialReferences: readonly PublicKeyShareMaterialProofReference[] =
        shareMaterialRecords === undefined
            ? sortedByRosterPosition(
                  input.publicKeyShareMaterial.publicKeyShareMaterialRoots,
              )
            : sortedByRosterPosition(shareMaterialRecords).map(
                  (materialRecord) => ({
                      trusteeIdentity: materialRecord.trusteeIdentity,
                      trusteeRosterPosition:
                          materialRecord.trusteeRosterPosition,
                      publicKeyShareRoot: materialRecord.publicKeyShareRoot,
                      publicKeyShareMaterialRoot:
                          materialRecord.publicKeyShareMaterialRoot,
                  }),
              );
    if (materialReferences.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterial.publicKeyShareMaterialRoots must contain one material root per participant.',
        );
    }
    materialReferences.forEach((materialReference, expectedRosterPosition) => {
        if (
            materialReference.trusteeRosterPosition !== expectedRosterPosition
        ) {
            throw new Error(
                'publicKeyShareMaterial.publicKeyShareMaterialRoots roster positions must be contiguous from zero.',
            );
        }
        assertNonEmptyString(
            materialReference.trusteeIdentity,
            'publicKeyShareMaterial.publicKeyShareMaterialRoots.trusteeIdentity',
        );
        assertProtocolHash(
            materialReference.publicKeyShareMaterialRoot,
            'publicKeyShareMaterial.publicKeyShareMaterialRoots.publicKeyShareMaterialRoot',
        );
        const publicKeyShareRoot = materialReference.publicKeyShareRoot;
        if (publicKeyShareRoot !== undefined) {
            if (typeof publicKeyShareRoot !== 'string') {
                throw new TypeError(
                    'publicKeyShareMaterial.shareMaterialRecords.publicKeyShareRoot must be a string.',
                );
            }
            assertProtocolHash(
                publicKeyShareRoot,
                'publicKeyShareMaterial.shareMaterialRecords.publicKeyShareRoot',
            );
        }
        recordsByRosterPosition.set(
            materialReference.trusteeRosterPosition,
            materialReference,
        );
    });

    return recordsByRosterPosition;
};

const validatePublicKeyShareSuccinctProofMaterial = (
    material: PublicKeyShareSuccinctProofMaterial,
    fieldName: string,
): void => {
    if (material.proofFamily !== publicKeyShareProofFamily) {
        throw new Error(`${fieldName}.proofFamily must be public-key share.`);
    }
    assertNonEmptyString(
        material.trusteeIdentity,
        `${fieldName}.trusteeIdentity`,
    );
    assertNonNegativeSafeInteger(
        material.trusteeRosterPosition,
        `${fieldName}.trusteeRosterPosition`,
    );
    assertProtocolHash(material.statementHash, `${fieldName}.statementHash`);
    assertProtocolHash(material.proofBytesHash, `${fieldName}.proofBytesHash`);
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(`${fieldName}.proofBytesHex must be a string.`);
        }
        assertLowercaseHexBytes(proofBytesHex, `${fieldName}.proofBytesHex`);

        return;
    }

    const transportedMaterial =
        material as PublicKeyShareSuccinctTransportedProofBytes;
    if (
        transportedMaterial.proofBytesEncoding !== 'binary-chunked-proof-bytes'
    ) {
        throw new TypeError(
            `${fieldName}.proofBytesEncoding must be binary-chunked-proof-bytes.`,
        );
    }
    assertProtocolHash(
        transportedMaterial.proofMaterialRoot,
        `${fieldName}.proofMaterialRoot`,
    );
    assertPositiveSafeInteger(
        transportedMaterial.proofChunkCount,
        `${fieldName}.proofChunkCount`,
    );
    assertPositiveSafeInteger(
        transportedMaterial.proofTotalByteLength,
        `${fieldName}.proofTotalByteLength`,
    );
    assertProtocolHash(
        transportedMaterial.proofFullObjectHash,
        `${fieldName}.proofFullObjectHash`,
    );
    assertProtocolHash(
        transportedMaterial.proofChunkRoot,
        `${fieldName}.proofChunkRoot`,
    );
    transportedMaterial.proofChunkHashes.forEach((proofChunkHash, chunkIndex) =>
        assertProtocolHash(
            proofChunkHash,
            `${fieldName}.proofChunkHashes.${String(chunkIndex)}`,
        ),
    );
    if (
        transportedMaterial.proofChunkHashes.length !==
        transportedMaterial.proofChunkCount
    ) {
        throw new Error(
            `${fieldName}.proofChunkHashes must match proofChunkCount.`,
        );
    }
};

const publicKeyShareSuccinctProofByteMaterial = (
    material: PublicKeyShareSuccinctProofMaterial,
): PublicKeyShareSuccinctProofByteMaterial => {
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(
                'publicKeyShareSuccinctProofMaterial.proofBytesHex must be a string.',
            );
        }
        return {
            proofBytesHex,
        };
    }

    const transportedMaterial =
        material as PublicKeyShareSuccinctTransportedProofBytes;

    return {
        proofBytesEncoding: transportedMaterial.proofBytesEncoding,
        proofMaterialRoot: transportedMaterial.proofMaterialRoot,
        proofChunkCount: transportedMaterial.proofChunkCount,
        proofTotalByteLength: transportedMaterial.proofTotalByteLength,
        proofFullObjectHash: transportedMaterial.proofFullObjectHash,
        proofChunkRoot: transportedMaterial.proofChunkRoot,
        proofChunkHashes: transportedMaterial.proofChunkHashes,
    };
};

const sortedPublicKeyShareSuccinctProofMaterials = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        'participantCount' | 'proofMaterials'
    >,
): PublicKeyShareSuccinctProofMaterial[] => {
    const proofMaterials = [...input.proofMaterials].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (proofMaterials.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareSuccinctProofMaterials must contain one proof per participant.',
        );
    }
    proofMaterials.forEach((proofMaterial, expectedRosterPosition) => {
        validatePublicKeyShareSuccinctProofMaterial(
            proofMaterial,
            `publicKeyShareSuccinctProofMaterials.${String(expectedRosterPosition)}`,
        );
        if (proofMaterial.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'publicKeyShareSuccinctProofMaterials roster positions must be contiguous from zero.',
            );
        }
    });

    return proofMaterials;
};

export const createPublicKeyShareSuccinctProofSet = (
    input: PublicKeyShareSuccinctProofSetInput,
): PublicKeyShareSuccinctProofSet => {
    validateCommonInput(input);
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareProofs,
        'publicKeyShareProofs',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    if (
        input.publicKeyShareProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareMaterial.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot
    ) {
        throw new Error(
            'public-key succinct proofs must bind the accepted public-key share, statement, and material roots.',
        );
    }

    const shareRecords = publicKeyShareRecordsByRosterPosition(input);
    const proofStatementRecords =
        publicKeyShareProofRecordsByRosterPosition(input);
    const materialReferences =
        publicKeyShareMaterialReferencesByRosterPosition(input);
    const sameSecretBridgeBindings =
        sameSecretBridgeBindingsByRosterPosition(input);
    const proofMaterials = sortedPublicKeyShareSuccinctProofMaterials(input);
    const proofRecords = proofMaterials.map(
        (proofMaterial, expectedRosterPosition) => {
            const shareRecord = shareRecords.get(expectedRosterPosition);
            const proofStatementRecord = proofStatementRecords.get(
                expectedRosterPosition,
            );
            const materialReference = materialReferences.get(
                expectedRosterPosition,
            );
            const sameSecretBridgeBinding = sameSecretBridgeBindings.get(
                expectedRosterPosition,
            );
            if (
                shareRecord === undefined ||
                proofStatementRecord === undefined ||
                materialReference === undefined ||
                sameSecretBridgeBinding === undefined
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must match accepted setup records.',
                );
            }
            if (
                proofMaterial.trusteeIdentity !== shareRecord.trusteeIdentity ||
                proofStatementRecord.trusteeIdentity !==
                    shareRecord.trusteeIdentity ||
                materialReference.trusteeIdentity !==
                    shareRecord.trusteeIdentity ||
                sameSecretBridgeBinding.trusteeIdentity !==
                    shareRecord.trusteeIdentity ||
                proofStatementRecord.publicKeyShareRoot !==
                    shareRecord.publicKeyShareRoot ||
                (materialReference.publicKeyShareRoot !== undefined &&
                    materialReference.publicKeyShareRoot !==
                        shareRecord.publicKeyShareRoot)
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must bind accepted public-key records.',
                );
            }
            const proofRecordWithoutRoot = {
                objectType: 'PublicKeyShareSuccinctProof',
                proofFamily: publicKeyShareProofFamily,
                ...contextFields(input.setupContext),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                ringDegree: input.publicKeyShareMaterial.ringDegree,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                publicKeyShareProofRoot:
                    proofStatementRecord.publicKeyShareProofRoot,
                publicKeyShareMaterialRoot:
                    materialReference.publicKeyShareMaterialRoot,
                sameSecretBridgeStatementRoot:
                    sameSecretBridgeBinding.sameSecretBridgeStatementRoot,
                sameSecretBridgeProofRecordRoot:
                    sameSecretBridgeBinding.sameSecretBridgeProofRecordRoot,
                statementHash: proofMaterial.statementHash,
                proofBytesHash: proofMaterial.proofBytesHash,
                ...publicKeyShareSuccinctProofByteMaterial(proofMaterial),
            } as const satisfies Omit<
                PublicKeyShareSuccinctProofRecord,
                'publicKeyShareSuccinctProofRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                publicKeyShareSuccinctProofRoot: deriveCanonicalObjectHash(
                    proofRecordWithoutRoot,
                ),
            } satisfies PublicKeyShareSuccinctProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'PublicKeyShareSuccinctProofSet',
        proofFamily: publicKeyShareProofFamily,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        publicKeyCrpRoot: input.publicKeyCrpRoot,
        publicAPolynomialRoot: input.publicAPolynomialRoot,
        publicKeyShareSetRoot: input.publicKeyShares.publicKeyShareSetRoot,
        publicKeyShareProofSetRoot:
            input.publicKeyShareProofs.publicKeyShareProofSetRoot,
        publicKeyShareMaterialSetRoot:
            input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        proofRecords,
    } as const satisfies Omit<
        PublicKeyShareSuccinctProofSet,
        'publicKeyShareSuccinctProofSetRoot'
    >;

    return {
        ...proofSetWithoutRoot,
        publicKeyShareSuccinctProofSetRoot:
            deriveCanonicalObjectHash(proofSetWithoutRoot),
    } satisfies PublicKeyShareSuccinctProofSet;
};
