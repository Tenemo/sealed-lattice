import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    type JsonRecord,
    type PublicKeyShareSuccinctProofByteMaterial,
    type PublicKeyShareSuccinctProofMaterial,
    type PublicKeyShareSuccinctProofRecord,
    type PublicKeyShareSuccinctProofSet,
    type PublicKeyShareSuccinctProofSetInput,
} from './constants-and-types.js';
import {
    assertNonEmptyString,
    assertNonNegativeSafeInteger,
    assertProtocolHash,
    assertSetupContextHashMatches,
    deriveCollectiveBgvSetupContextHash,
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
    assertSetupContextHashMatches(
        input.setupContext,
        sameSecretBridgeStatementSet,
        'sameSecretBridgeStatementSet',
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

const publicKeyShareMaterialRootsByRosterPosition = (
    input: Pick<
        PublicKeyShareSuccinctProofSetInput,
        'participantCount' | 'publicKeyShareMaterial'
    >,
): ReadonlyMap<number, ProtocolHash> => {
    assertProtocolHash(
        input.publicKeyShareMaterial.publicKeyShareMaterialSetRoot,
        'publicKeyShareMaterial.publicKeyShareMaterialSetRoot',
    );
    const materialRoots =
        input.publicKeyShareMaterial.publicKeyShareMaterialRoots;
    if (materialRoots.length !== input.participantCount) {
        throw new Error(
            'publicKeyShareMaterial.publicKeyShareMaterialRoots must contain one material root per participant.',
        );
    }
    const rootsByRosterPosition = new Map<number, ProtocolHash>();
    materialRoots.forEach((materialRoot, trusteeRosterPosition) => {
        assertProtocolHash(
            materialRoot,
            'publicKeyShareMaterial.publicKeyShareMaterialRoots',
        );
        rootsByRosterPosition.set(trusteeRosterPosition, materialRoot);
    });

    return rootsByRosterPosition;
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
    const shareRecords = publicKeyShareRecordsByRosterPosition(input);
    const materialRoots = publicKeyShareMaterialRootsByRosterPosition(input);
    const sameSecretBridgeBindings =
        sameSecretBridgeBindingsByRosterPosition(input);
    const proofMaterials = sortedPublicKeyShareSuccinctProofMaterials(input);
    const logicalProofRecords: JsonRecord[] = [];
    const proofRecords = proofMaterials.map(
        (proofMaterial, expectedRosterPosition) => {
            const shareRecord = shareRecords.get(expectedRosterPosition);
            const materialRoot = materialRoots.get(expectedRosterPosition);
            const sameSecretBridgeBinding = sameSecretBridgeBindings.get(
                expectedRosterPosition,
            );
            if (
                shareRecord === undefined ||
                materialRoot === undefined ||
                sameSecretBridgeBinding === undefined
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must match accepted setup records.',
                );
            }
            if (
                proofMaterial.trusteeIdentity !== shareRecord.trusteeIdentity ||
                sameSecretBridgeBinding.trusteeIdentity !==
                    shareRecord.trusteeIdentity
            ) {
                throw new Error(
                    'publicKeyShareSuccinctProofMaterials must bind accepted public-key records.',
                );
            }
            const proofRecord = {
                objectType: 'PublicKeyShareSuccinctProof',
                trusteeRosterPosition: shareRecord.trusteeRosterPosition,
                statementHash: proofMaterial.statementHash,
                proofBytesHash: proofMaterial.proofBytesHash,
                ...publicKeyShareSuccinctProofByteMaterial(proofMaterial),
            } satisfies PublicKeyShareSuccinctProofRecord;
            logicalProofRecords.push({
                objectType: proofRecord.objectType,
                setupContextHash: deriveCollectiveBgvSetupContextHash(
                    input.setupContext,
                ),
                trusteeIdentity: shareRecord.trusteeIdentity,
                trusteeRosterPosition: proofRecord.trusteeRosterPosition,
                publicKeyShareRoot: shareRecord.publicKeyShareRoot,
                publicKeyShareMaterialRoot: materialRoot,
                sameSecretBridgeStatementRoot:
                    sameSecretBridgeBinding.sameSecretBridgeStatementRoot,
                sameSecretBridgeProofRecordRoot:
                    sameSecretBridgeBinding.sameSecretBridgeProofRecordRoot,
                statementHash: proofRecord.statementHash,
                proofBytesHash: proofRecord.proofBytesHash,
                proofMaterialRoot: proofRecord.proofMaterialRoot,
            });

            return proofRecord;
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
        publicKeyShareSuccinctProofSetRoot: deriveCanonicalObjectHash({
            objectType: proofSetWithoutRoot.objectType,
            proofRecords: logicalProofRecords,
        }),
    } satisfies PublicKeyShareSuccinctProofSet;
};
