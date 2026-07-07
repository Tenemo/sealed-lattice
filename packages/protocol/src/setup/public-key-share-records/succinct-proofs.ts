import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { type SameSecretProofSet } from '../same-secret-consistency-records.js';

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
import {
    publicKeyShareRecordsByRosterPosition,
    statementRecordsByRosterPosition,
} from './share-statement-records.js';

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

const sameSecretProofRecordsByRosterPosition = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        | 'setupContext'
        | 'participantCount'
        | 'sameSecretConsistency'
        | 'sameSecretProofs'
    >,
): ReadonlyMap<number, SameSecretProofSet['proofRecords'][number]> => {
    assertContextMatches(
        input.setupContext,
        input.sameSecretProofs,
        'sameSecretProofs',
    );
    if (
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot
    ) {
        throw new Error(
            'sameSecretProofs must bind the accepted same-secret statement set.',
        );
    }
    assertProtocolHash(
        input.sameSecretProofs.sameSecretProofSetRoot,
        'sameSecretProofs.sameSecretProofSetRoot',
    );
    const proofRecords = sortedByRosterPosition(
        input.sameSecretProofs.proofRecords,
    );
    if (proofRecords.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofs.proofRecords must contain one proof per participant.',
        );
    }
    const recordsByRosterPosition = new Map<
        number,
        SameSecretProofSet['proofRecords'][number]
    >();
    proofRecords.forEach((proofRecord, expectedRosterPosition) => {
        if (proofRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretProofs.proofRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            proofRecord.sameSecretProofRoot,
            'sameSecretProofs.proofRecords.sameSecretProofRoot',
        );
        recordsByRosterPosition.set(
            proofRecord.trusteeRosterPosition,
            proofRecord,
        );
    });

    return recordsByRosterPosition;
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
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertContextMatches(
        input.setupContext,
        input.sameSecretProofs,
        'sameSecretProofs',
    );
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
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot ||
        input.publicKeyShareProofs.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot ||
        input.publicKeyShareProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.publicKeyShareMaterial.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot
    ) {
        throw new Error(
            'public-key succinct proofs must bind the accepted public-key share, same-secret, statement, and material roots.',
        );
    }

    const statementsByRosterPosition = statementRecordsByRosterPosition(input);
    const shareRecords = publicKeyShareRecordsByRosterPosition(input);
    const proofStatementRecords =
        publicKeyShareProofRecordsByRosterPosition(input);
    const sameSecretProofRecords =
        sameSecretProofRecordsByRosterPosition(input);
    const materialReferences =
        publicKeyShareMaterialReferencesByRosterPosition(input);
    const proofMaterials = sortedPublicKeyShareSuccinctProofMaterials(input);
    const proofRecords = proofMaterials.map(
        (proofMaterial, expectedRosterPosition) => {
            const statementRecord = statementsByRosterPosition.get(
                expectedRosterPosition,
            );
            const shareRecord = shareRecords.get(expectedRosterPosition);
            const proofStatementRecord = proofStatementRecords.get(
                expectedRosterPosition,
            );
            const sameSecretProofRecord = sameSecretProofRecords.get(
                expectedRosterPosition,
            );
            const materialReference = materialReferences.get(
                expectedRosterPosition,
            );
            if (
                statementRecord === undefined ||
                shareRecord === undefined ||
                proofStatementRecord === undefined ||
                sameSecretProofRecord === undefined ||
                materialReference === undefined
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must match accepted setup records.',
                );
            }
            if (
                proofMaterial.trusteeIdentity !== shareRecord.trusteeIdentity ||
                proofStatementRecord.publicKeyShareRoot !==
                    shareRecord.publicKeyShareRoot ||
                (materialReference.publicKeyShareRoot !== undefined &&
                    materialReference.publicKeyShareRoot !==
                        shareRecord.publicKeyShareRoot) ||
                shareRecord.sameSecretStatementRoot !==
                    statementRecord.sameSecretStatementRoot ||
                proofStatementRecord.sameSecretStatementRoot !==
                    statementRecord.sameSecretStatementRoot ||
                sameSecretProofRecord.sameSecretStatementRoot !==
                    statementRecord.sameSecretStatementRoot ||
                sameSecretProofRecord.trusteeSecretCommitmentRoot !==
                    statementRecord.trusteeSecretCommitmentRoot
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must bind accepted public-key and same-secret records.',
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
                sameSecretStatementRoot:
                    statementRecord.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    statementRecord.trusteeSecretCommitmentRoot,
                sameSecretProofFamilyBindingRoot:
                    sameSecretProofRecord.sameSecretProofFamilyBindingRoot,
                sameSecretProofRoot: sameSecretProofRecord.sameSecretProofRoot,
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
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
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
