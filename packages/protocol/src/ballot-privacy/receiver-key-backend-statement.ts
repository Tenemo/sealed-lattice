import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    ProtocolHash,
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
} from '@sealed-lattice/types';

import {
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    receiverEncryptionShortVectorInfinityNormBound,
} from './protocol-parameters.js';

const backendStatementFormat = 'SparseSignedIntegerBackendStatement-v1';
const receiverKeyStatementHashPurpose = 'receiver-key-backend-statement-v1';
const receiverKeyMatrixHashPurpose = 'receiver-key-backend-matrix-v1';
const receiverKeyTargetVectorHashPurpose =
    'receiver-key-backend-target-vector-v1';
const receiverKeyBoundsHashPurpose = 'receiver-key-backend-bounds-v1';
const receiverKeyHashExpandedMatrixHashPurpose =
    'receiver-key-backend-hash-expanded-matrix-v1';
const receiverKeyHashExpandedTargetVectorHashPurpose =
    'receiver-key-backend-hash-expanded-target-vector-v1';
const receiverKeyPublicContextHashPurpose =
    'receiver-key-backend-public-context-v1';
const receiverKeyEquationCoefficientExpansionDomain =
    'sealed.vote/internal/receiver-key-proof/receiver-key-equation/coefficient-expansion-v1';
const receiverKeyEquationTargetExpansionDomain =
    'sealed.vote/internal/receiver-key-proof/receiver-key-equation/target-expansion-v1';
const receiverKeyEquationRowCount =
    receiverEncryptionModuleRank * receiverEncryptionModuleDegree;
const receiverKeyWitnessColumnCount = receiverKeyEquationRowCount * 2;

type ReceiverEncryptionPublicKeyPayload = Omit<
    ReceiverEncryptionPublicKey,
    'receiverPublicKeyHash'
>;

type ReceiverEncryptionPublicKeyMaterial = {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly publicKeyVector: readonly (readonly number[])[];
};

export type ReceiverKeyProofBackendStatementVariableRole =
    | 'ReceiverSecretCoefficient'
    | 'ReceiverErrorCoefficient';

export type ReceiverKeyProofBackendStatementVariableColumn = {
    readonly columnIndex: number;
    readonly variableName: string;
    readonly variableRole: ReceiverKeyProofBackendStatementVariableRole;
    readonly polynomialIndex: number;
    readonly coefficientIndex: number;
};

export type ReceiverKeyProofBackendStatementRowBatch = {
    readonly batchKind: 'HashExpandedRows';
    readonly batchName: 'receiver_key_equation_rows';
    readonly coefficientExpansionDomain: typeof receiverKeyEquationCoefficientExpansionDomain;
    readonly matrixHash: ProtocolHash;
    readonly modulus: string;
    readonly publicInputHashes: {
        readonly keyMaterialHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly receiverEncryptionProfileHash: ProtocolHash;
        readonly receiverKeyContextHash: ProtocolHash;
        readonly receiverPublicKeyHash: ProtocolHash;
    };
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly rowCount: typeof receiverKeyEquationRowCount;
    readonly rowKind: 'ReceiverKeyEquation';
    readonly rowOffset: 0;
    readonly sourceAlgebraicRowName: 'receiver_key_well_formedness';
    readonly targetHash: ProtocolHash;
    readonly targetExpansionDomain: typeof receiverKeyEquationTargetExpansionDomain;
    readonly targetVectorHash: ProtocolHash;
    readonly variableColumnIndices: readonly number[];
};

export type ReceiverKeyProofBackendStatementBound = {
    readonly absoluteMaximum: string;
    readonly boundKind: 'SignedIntegerAbsoluteBound';
    readonly boundName:
        | 'receiver_secret_coefficients_eta_2'
        | 'receiver_error_coefficients_eta_2';
    readonly variableColumnIndices: readonly number[];
    readonly variableNames: readonly string[];
};

export type ReceiverKeyProofBackendStatement = {
    readonly objectType: 'ReceiverKeyProofBackendStatement';
    readonly objectVersion: 1;
    readonly backendStatementHash: ProtocolHash;
    readonly backendStatementFormat: typeof backendStatementFormat;
    readonly relationLabel: 'ReceiverKeyWellFormednessRelation';
    readonly coefficientModulus: string;
    readonly moduleRank: typeof receiverEncryptionModuleRank;
    readonly moduleDegree: typeof receiverEncryptionModuleDegree;
    readonly columnCount: typeof receiverKeyWitnessColumnCount;
    readonly rowCount: typeof receiverKeyEquationRowCount;
    readonly hashExpandedRowCount: typeof receiverKeyEquationRowCount;
    readonly explicitRowCount: 0;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly receiverPublicKeyHash: ProtocolHash;
    readonly keyMaterialHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly receiverKeyContextHash: ProtocolHash;
    readonly variableColumns: readonly ReceiverKeyProofBackendStatementVariableColumn[];
    readonly rowBatches: readonly [ReceiverKeyProofBackendStatementRowBatch];
    readonly bounds: readonly [
        ReceiverKeyProofBackendStatementBound,
        ReceiverKeyProofBackendStatementBound,
    ];
    readonly matrixHash: ProtocolHash;
    readonly targetVectorHash: ProtocolHash;
    readonly boundsHash: ProtocolHash;
};

const deriveReceiverKeyBackendHash = (
    purpose: string,
    payload: unknown,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload,
        purpose,
    });

const deriveReceiverMatrixSeedHash = (input: {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly rosterHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('ReceiverEncryptionProfileHash', {
        purpose: 'receiver-public-matrix-seed',
        ...input,
    });

const deriveReceiverEncryptionPublicKeyHash = (
    publicKey: ReceiverEncryptionPublicKeyPayload,
): ProtocolHash => deriveProtocolHash('PublicKeyHash', publicKey);

const deriveReceiverKeyMaterialHashForBackend = (input: {
    readonly publicKeyVector: readonly (readonly number[])[];
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly receiverEncryptionProfileHash: ProtocolHash;
}): ProtocolHash => deriveProtocolHash('PublicKeyHash', input);

const deriveReceiverKeyProofBackendStatementHash = (
    statementPayload: Omit<
        ReceiverKeyProofBackendStatement,
        'backendStatementHash'
    >,
): ProtocolHash =>
    deriveReceiverKeyBackendHash(
        receiverKeyStatementHashPurpose,
        statementPayload,
    );

const validateReceiverPublicKeyMaterial = (
    publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial,
): void => {
    if (
        publicKeyMaterial.publicKeyVector.length !==
        receiverEncryptionModuleRank
    ) {
        throw new RangeError(
            'Receiver public-key material must use the frozen module rank.',
        );
    }
    for (const polynomial of publicKeyMaterial.publicKeyVector) {
        if (polynomial.length !== receiverEncryptionModuleDegree) {
            throw new RangeError(
                'Receiver public-key polynomials must use the frozen degree.',
            );
        }
        for (const coefficient of polynomial) {
            if (
                !Number.isSafeInteger(coefficient) ||
                coefficient < 0 ||
                coefficient >= receiverEncryptionModulus
            ) {
                throw new RangeError(
                    'Receiver public-key coefficients must be canonical representatives.',
                );
            }
        }
    }
};

const range = (length: number, offset = 0): readonly number[] =>
    Array.from({ length }, (_unusedValue, index) => index + offset);

const receiverSecretVariableName = (
    polynomialIndex: number,
    coefficientIndex: number,
): string =>
    `receiver_secret_polynomial_${polynomialIndex}_coefficient_${coefficientIndex}`;

const receiverErrorVariableName = (
    polynomialIndex: number,
    coefficientIndex: number,
): string =>
    `receiver_error_polynomial_${polynomialIndex}_coefficient_${coefficientIndex}`;

const buildVariableColumns =
    (): readonly ReceiverKeyProofBackendStatementVariableColumn[] => {
        const secretColumns = Array.from(
            { length: receiverKeyEquationRowCount },
            (_unusedValue, linearIndex) => {
                const polynomialIndex = Math.floor(
                    linearIndex / receiverEncryptionModuleDegree,
                );
                const coefficientIndex =
                    linearIndex % receiverEncryptionModuleDegree;

                return {
                    coefficientIndex,
                    columnIndex: linearIndex,
                    polynomialIndex,
                    variableName: receiverSecretVariableName(
                        polynomialIndex,
                        coefficientIndex,
                    ),
                    variableRole:
                        'ReceiverSecretCoefficient' as ReceiverKeyProofBackendStatementVariableRole,
                };
            },
        );
        const errorColumns = Array.from(
            { length: receiverKeyEquationRowCount },
            (_unusedValue, linearIndex) => {
                const polynomialIndex = Math.floor(
                    linearIndex / receiverEncryptionModuleDegree,
                );
                const coefficientIndex =
                    linearIndex % receiverEncryptionModuleDegree;
                const columnIndex = receiverKeyEquationRowCount + linearIndex;

                return {
                    coefficientIndex,
                    columnIndex,
                    polynomialIndex,
                    variableName: receiverErrorVariableName(
                        polynomialIndex,
                        coefficientIndex,
                    ),
                    variableRole:
                        'ReceiverErrorCoefficient' as ReceiverKeyProofBackendStatementVariableRole,
                };
            },
        );

        return [...secretColumns, ...errorColumns];
    };

const buildReceiverKeyBackendBounds = (
    variableColumns: readonly ReceiverKeyProofBackendStatementVariableColumn[],
): readonly [
    ReceiverKeyProofBackendStatementBound,
    ReceiverKeyProofBackendStatementBound,
] => {
    const secretColumns = variableColumns.filter(
        (variableColumn) =>
            variableColumn.variableRole === 'ReceiverSecretCoefficient',
    );
    const errorColumns = variableColumns.filter(
        (variableColumn) =>
            variableColumn.variableRole === 'ReceiverErrorCoefficient',
    );
    const toBound = (
        boundName: ReceiverKeyProofBackendStatementBound['boundName'],
        columns: readonly ReceiverKeyProofBackendStatementVariableColumn[],
    ): ReceiverKeyProofBackendStatementBound => ({
        absoluteMaximum: String(receiverEncryptionShortVectorInfinityNormBound),
        boundKind: 'SignedIntegerAbsoluteBound',
        boundName,
        variableColumnIndices: columns.map(
            (variableColumn) => variableColumn.columnIndex,
        ),
        variableNames: columns.map(
            (variableColumn) => variableColumn.variableName,
        ),
    });

    return [
        toBound('receiver_secret_coefficients_eta_2', secretColumns),
        toBound('receiver_error_coefficients_eta_2', errorColumns),
    ];
};

export const createReceiverKeyProofBackendStatement = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
}): ReceiverKeyProofBackendStatement => {
    validateReceiverPublicKeyMaterial(input.publicKeyMaterial);

    const receiverPublicKeyPayload: ReceiverEncryptionPublicKeyPayload = {
        ceremonyId: input.receiverPublicKey.ceremonyId,
        keyMaterialHash: input.receiverPublicKey.keyMaterialHash,
        manifestHash: input.receiverPublicKey.manifestHash,
        objectType: 'ReceiverEncryptionPublicKey',
        objectVersion: 1,
        receiverEncryptionProfileHash:
            input.receiverPublicKey.receiverEncryptionProfileHash,
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
        rosterHash: input.receiverPublicKey.rosterHash,
    };
    const expectedReceiverPublicKeyHash = deriveReceiverEncryptionPublicKeyHash(
        receiverPublicKeyPayload,
    );
    if (
        input.receiverPublicKey.receiverPublicKeyHash !==
        expectedReceiverPublicKeyHash
    ) {
        throw new RangeError(
            'Receiver public-key hash does not match its canonical payload.',
        );
    }
    if (
        input.receiverPublicKey.receiverEncryptionProfileHash !==
        input.receiverEncryptionProfile.receiverEncryptionProfileHash
    ) {
        throw new RangeError(
            'Receiver public key is not bound to the receiver encryption profile.',
        );
    }

    const expectedPublicMatrixSeedHash = deriveReceiverMatrixSeedHash({
        ceremonyId: input.receiverPublicKey.ceremonyId,
        manifestHash: input.receiverPublicKey.manifestHash,
        receiverEncryptionProfileHash:
            input.receiverEncryptionProfile.receiverEncryptionProfileHash,
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
        rosterHash: input.receiverPublicKey.rosterHash,
    });
    if (
        input.publicKeyMaterial.publicMatrixSeedHash !==
        expectedPublicMatrixSeedHash
    ) {
        throw new RangeError(
            'Receiver key backend statement public matrix seed is not roster-bound.',
        );
    }

    const expectedKeyMaterialHash = deriveReceiverKeyMaterialHashForBackend({
        publicKeyVector: input.publicKeyMaterial.publicKeyVector,
        publicMatrixSeedHash: input.publicKeyMaterial.publicMatrixSeedHash,
        receiverEncryptionProfileHash:
            input.receiverEncryptionProfile.receiverEncryptionProfileHash,
    });
    if (input.receiverPublicKey.keyMaterialHash !== expectedKeyMaterialHash) {
        throw new RangeError(
            'Receiver key backend statement public key material does not match the frozen receiver key.',
        );
    }

    const receiverKeyContextHash = deriveReceiverKeyBackendHash(
        receiverKeyPublicContextHashPurpose,
        {
            ceremonyId: input.receiverPublicKey.ceremonyId,
            manifestHash: input.receiverPublicKey.manifestHash,
            receiverEncryptionProfileHash:
                input.receiverEncryptionProfile.receiverEncryptionProfileHash,
            receiverIdentity: input.receiverPublicKey.receiverIdentity,
            receiverPublicKeyHash:
                input.receiverPublicKey.receiverPublicKeyHash,
            receiverRosterPosition:
                input.receiverPublicKey.receiverRosterPosition,
            recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
            rosterHash: input.receiverPublicKey.rosterHash,
        },
    );
    const variableColumns = buildVariableColumns();
    const variableColumnIndices = range(receiverKeyWitnessColumnCount);
    const rowBatchPayload = {
        coefficientExpansionDomain:
            receiverKeyEquationCoefficientExpansionDomain,
        modulus: String(receiverEncryptionModulus),
        publicInputHashes: {
            keyMaterialHash: input.receiverPublicKey.keyMaterialHash,
            publicMatrixSeedHash: input.publicKeyMaterial.publicMatrixSeedHash,
            receiverEncryptionProfileHash:
                input.receiverEncryptionProfile.receiverEncryptionProfileHash,
            receiverKeyContextHash,
            receiverPublicKeyHash:
                input.receiverPublicKey.receiverPublicKeyHash,
        },
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        rowCount: receiverKeyEquationRowCount,
        rowKind: 'ReceiverKeyEquation',
        sourceAlgebraicRowName: 'receiver_key_well_formedness',
        targetHash: input.receiverPublicKey.keyMaterialHash,
        targetExpansionDomain: receiverKeyEquationTargetExpansionDomain,
        variableColumnIndices,
    } as const;
    const rowBatch: ReceiverKeyProofBackendStatementRowBatch = {
        ...rowBatchPayload,
        batchKind: 'HashExpandedRows',
        batchName: 'receiver_key_equation_rows',
        matrixHash: deriveReceiverKeyBackendHash(
            receiverKeyHashExpandedMatrixHashPurpose,
            rowBatchPayload,
        ),
        rowOffset: 0,
        targetVectorHash: deriveReceiverKeyBackendHash(
            receiverKeyHashExpandedTargetVectorHashPurpose,
            rowBatchPayload,
        ),
    };
    const bounds = buildReceiverKeyBackendBounds(variableColumns);
    const matrixHash = deriveReceiverKeyBackendHash(
        receiverKeyMatrixHashPurpose,
        {
            rowBatches: [
                {
                    batchKind: rowBatch.batchKind,
                    batchName: rowBatch.batchName,
                    matrixHash: rowBatch.matrixHash,
                    rowCount: rowBatch.rowCount,
                    rowKind: rowBatch.rowKind,
                    rowOffset: rowBatch.rowOffset,
                },
            ],
        },
    );
    const targetVectorHash = deriveReceiverKeyBackendHash(
        receiverKeyTargetVectorHashPurpose,
        {
            rowBatches: [
                {
                    batchKind: rowBatch.batchKind,
                    batchName: rowBatch.batchName,
                    rowCount: rowBatch.rowCount,
                    rowKind: rowBatch.rowKind,
                    rowOffset: rowBatch.rowOffset,
                    targetVectorHash: rowBatch.targetVectorHash,
                },
            ],
        },
    );
    const boundsHash = deriveReceiverKeyBackendHash(
        receiverKeyBoundsHashPurpose,
        { bounds },
    );
    const statementPayload: Omit<
        ReceiverKeyProofBackendStatement,
        'backendStatementHash'
    > = {
        backendStatementFormat,
        bounds,
        boundsHash,
        ceremonyId: input.receiverPublicKey.ceremonyId,
        coefficientModulus: String(receiverEncryptionModulus),
        columnCount: receiverKeyWitnessColumnCount,
        hashExpandedRowCount: receiverKeyEquationRowCount,
        explicitRowCount: 0,
        keyMaterialHash: input.receiverPublicKey.keyMaterialHash,
        manifestHash: input.receiverPublicKey.manifestHash,
        matrixHash,
        moduleDegree: receiverEncryptionModuleDegree,
        moduleRank: receiverEncryptionModuleRank,
        objectType: 'ReceiverKeyProofBackendStatement',
        objectVersion: 1,
        publicMatrixSeedHash: input.publicKeyMaterial.publicMatrixSeedHash,
        receiverEncryptionProfileHash:
            input.receiverEncryptionProfile.receiverEncryptionProfileHash,
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverKeyContextHash,
        receiverPublicKeyHash: input.receiverPublicKey.receiverPublicKeyHash,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
        relationLabel: 'ReceiverKeyWellFormednessRelation',
        rosterHash: input.receiverPublicKey.rosterHash,
        rowBatches: [rowBatch],
        rowCount: receiverKeyEquationRowCount,
        targetVectorHash,
        variableColumns,
    };

    return {
        ...statementPayload,
        backendStatementHash:
            deriveReceiverKeyProofBackendStatementHash(statementPayload),
    };
};
