import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    type PublicKeyShareMaterialSet,
    type PublicKeyShareMaterialRootReference,
    type PublicKeyShareSuccinctProofByteMaterial,
    type PublicKeyShareSuccinctProofMaterial,
    type PublicKeyShareSuccinctProofRecord,
    type PublicKeyShareSuccinctProofSet,
    type PublicKeyShareSuccinctProofSetInput,
    type SetupPackagePublicKeyShareMaterialSet,
} from './constants-and-types.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    assertContextMatches,
    contextFields,
    sortedByRosterPosition,
    validateCommonInput,
} from './encoding.js';
import { publicKeyShareRecordsByRosterPosition } from './share-statement-records.js';

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
    assertProtocolHash(
        sameSecretBridgeStatementSet.sameSecretBridgeStatementSetRoot,
        'sameSecretBridgeStatementSet.sameSecretBridgeStatementSetRoot',
    );
    if (
        sameSecretBridgeStatementSet.participantCount !== input.participantCount
    ) {
        throw new Error(
            'same-secret bridge statement set must match participantCount.',
        );
    }
    if (
        sameSecretBridgeStatementSet.publicMatrixSeedHash !==
        input.publicMatrixSeedHash
    ) {
        throw new Error(
            'same-secret bridge statement set must match publicMatrixSeedHash.',
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

const hasEmbeddedPublicKeyShareMaterialRecords = (
    materialSet: SetupPackagePublicKeyShareMaterialSet,
): materialSet is PublicKeyShareMaterialSet =>
    Array.isArray(materialSet.shareMaterialRecords);

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
    const materialReferences: readonly PublicKeyShareMaterialProofReference[] =
        hasEmbeddedPublicKeyShareMaterialRecords(input.publicKeyShareMaterial)
            ? sortedByRosterPosition(
                  input.publicKeyShareMaterial.shareMaterialRecords,
              ).map((materialRecord) => ({
                  trusteeIdentity: materialRecord.trusteeIdentity,
                  trusteeRosterPosition: materialRecord.trusteeRosterPosition,
                  publicKeyShareRoot: materialRecord.publicKeyShareRoot,
                  publicKeyShareMaterialRoot:
                      materialRecord.publicKeyShareMaterialRoot,
              }))
            : sortedByRosterPosition(
                  input.publicKeyShareMaterial.publicKeyShareMaterialRoots,
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
    assertProtocolHash(
        material.proofMaterialRoot,
        `${fieldName}.proofMaterialRoot`,
    );
};

const publicKeyShareSuccinctProofByteMaterial = (
    material: PublicKeyShareSuccinctProofMaterial,
): PublicKeyShareSuccinctProofByteMaterial => ({
    proofMaterialRoot: material.proofMaterialRoot,
});

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
        input.publicKeyShares,
        'publicKeyShares',
    );
    assertContextMatches(
        input.setupContext,
        input.publicKeyShareMaterial,
        'publicKeyShareMaterial',
    );
    if (
        input.publicKeyShares.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        input.publicKeyShares.publicKeyCrpRoot !== input.publicKeyCrpRoot ||
        input.publicKeyShares.publicAPolynomialRoot !==
            input.publicAPolynomialRoot ||
        input.publicKeyShareMaterial.publicKeyShareSetRoot !==
            input.publicKeyShares.publicKeyShareSetRoot
    ) {
        throw new Error(
            'public-key succinct proofs must bind the accepted public-key shares and material.',
        );
    }

    const shareRecords = publicKeyShareRecordsByRosterPosition(input);
    const materialReferences =
        publicKeyShareMaterialReferencesByRosterPosition(input);
    const sameSecretBridgeBindings =
        sameSecretBridgeBindingsByRosterPosition(input);
    const proofMaterials = sortedPublicKeyShareSuccinctProofMaterials(input);
    const proofRecords = proofMaterials.map(
        (proofMaterial, expectedRosterPosition) => {
            const shareRecord = shareRecords.get(expectedRosterPosition);
            const materialReference = materialReferences.get(
                expectedRosterPosition,
            );
            const sameSecretBridgeBinding = sameSecretBridgeBindings.get(
                expectedRosterPosition,
            );
            if (
                shareRecord === undefined ||
                materialReference === undefined ||
                sameSecretBridgeBinding === undefined
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must match accepted setup records.',
                );
            }
            if (
                proofMaterial.trusteeIdentity !== shareRecord.trusteeIdentity ||
                materialReference.trusteeIdentity !==
                    shareRecord.trusteeIdentity ||
                sameSecretBridgeBinding.trusteeIdentity !==
                    shareRecord.trusteeIdentity ||
                (materialReference.publicKeyShareRoot !== undefined &&
                    materialReference.publicKeyShareRoot !==
                        shareRecord.publicKeyShareRoot)
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must bind accepted public-key records.',
                );
            }
            return {
                objectType: 'PublicKeyShareSuccinctProof',
                ...contextFields(input.setupContext),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                publicKeyShareMaterialRoot:
                    materialReference.publicKeyShareMaterialRoot,
                sameSecretBridgeStatementRoot:
                    sameSecretBridgeBinding.sameSecretBridgeStatementRoot,
                sameSecretBridgeProofRecordRoot:
                    sameSecretBridgeBinding.sameSecretBridgeProofRecordRoot,
                statementHash: proofMaterial.statementHash,
                proofBytesHash: proofMaterial.proofBytesHash,
                ...publicKeyShareSuccinctProofByteMaterial(proofMaterial),
            } satisfies PublicKeyShareSuccinctProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'PublicKeyShareSuccinctProofSet',
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
