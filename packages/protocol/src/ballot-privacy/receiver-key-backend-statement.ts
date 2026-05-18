import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    ProtocolDigest,
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
} from '@sealed-lattice/types';

const backendStatementFormat = 'SparseSignedIntegerBackendStatement-v1';
const receiverKeyStatementDigestPurpose = 'receiver-key-backend-statement-v1';
const receiverKeyMatrixDigestPurpose = 'receiver-key-backend-matrix-v1';
const receiverKeyTargetVectorDigestPurpose =
    'receiver-key-backend-target-vector-v1';
const receiverKeyBoundsDigestPurpose = 'receiver-key-backend-bounds-v1';
const receiverKeyDigestExpandedMatrixDigestPurpose =
    'receiver-key-backend-digest-expanded-matrix-v1';
const receiverKeyDigestExpandedTargetVectorDigestPurpose =
    'receiver-key-backend-digest-expanded-target-vector-v1';
const receiverKeyPublicContextDigestPurpose =
    'receiver-key-backend-public-context-v1';
const receiverKeyEquationCoefficientExpansionDomain =
    'sealed.vote/internal/receiver-key-proof/receiver-key-equation/coefficient-expansion-v1';
const receiverKeyEquationTargetExpansionDomain =
    'sealed.vote/internal/receiver-key-proof/receiver-key-equation/target-expansion-v1';
const receiverEncryptionModulus = 12_289;
const receiverEncryptionModuleRank = 4;
const receiverEncryptionModuleDegree = 256;
const receiverEncryptionShortVectorInfinityNormBound = 2;
const receiverKeyEquationRowCount =
    receiverEncryptionModuleRank * receiverEncryptionModuleDegree;
const receiverKeyWitnessColumnCount = receiverKeyEquationRowCount * 2;

type ReceiverEncryptionPublicKeyPayload = Omit<
    ReceiverEncryptionPublicKey,
    'receiverPublicKeyDigest'
>;

type ReceiverEncryptionPublicKeyMaterial = {
    readonly publicMatrixSeedDigest: ProtocolDigest;
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
    readonly batchKind: 'DigestExpandedRows';
    readonly batchName: 'receiver_key_equation_rows';
    readonly coefficientExpansionDomain: typeof receiverKeyEquationCoefficientExpansionDomain;
    readonly matrixDigest: ProtocolDigest;
    readonly modulus: string;
    readonly publicInputDigests: {
        readonly keyMaterialDigest: ProtocolDigest;
        readonly publicMatrixSeedDigest: ProtocolDigest;
        readonly receiverEncryptionProfileDigest: ProtocolDigest;
        readonly receiverKeyContextDigest: ProtocolDigest;
        readonly receiverPublicKeyDigest: ProtocolDigest;
    };
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly rowCount: typeof receiverKeyEquationRowCount;
    readonly rowKind: 'ReceiverKeyEquation';
    readonly rowOffset: 0;
    readonly sourceAlgebraicRowName: 'receiver_key_well_formedness';
    readonly targetDigest: ProtocolDigest;
    readonly targetExpansionDomain: typeof receiverKeyEquationTargetExpansionDomain;
    readonly targetVectorDigest: ProtocolDigest;
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
    readonly backendStatementDigest: ProtocolDigest;
    readonly backendStatementFormat: typeof backendStatementFormat;
    readonly relationLabel: 'ReceiverKeyWellFormednessRelation';
    readonly coefficientModulus: string;
    readonly moduleRank: typeof receiverEncryptionModuleRank;
    readonly moduleDegree: typeof receiverEncryptionModuleDegree;
    readonly columnCount: typeof receiverKeyWitnessColumnCount;
    readonly rowCount: typeof receiverKeyEquationRowCount;
    readonly digestExpandedRowCount: typeof receiverKeyEquationRowCount;
    readonly explicitRowCount: 0;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly receiverPublicKeyDigest: ProtocolDigest;
    readonly keyMaterialDigest: ProtocolDigest;
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly receiverKeyContextDigest: ProtocolDigest;
    readonly variableColumns: readonly ReceiverKeyProofBackendStatementVariableColumn[];
    readonly rowBatches: readonly [ReceiverKeyProofBackendStatementRowBatch];
    readonly bounds: readonly [
        ReceiverKeyProofBackendStatementBound,
        ReceiverKeyProofBackendStatementBound,
    ];
    readonly matrixDigest: ProtocolDigest;
    readonly targetVectorDigest: ProtocolDigest;
    readonly boundsDigest: ProtocolDigest;
};

const deriveReceiverKeyBackendDigest = (
    purpose: string,
    payload: unknown,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload,
        purpose,
    });

const deriveReceiverMatrixSeedDigest = (input: {
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly rosterDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('ReceiverEncryptionProfileDigest', {
        purpose: 'receiver-public-matrix-seed',
        ...input,
    });

const deriveReceiverEncryptionPublicKeyDigest = (
    publicKey: ReceiverEncryptionPublicKeyPayload,
): ProtocolDigest => deriveProtocolDigest('PublicKeyDigest', publicKey);

const deriveReceiverKeyMaterialDigestForBackend = (input: {
    readonly publicKeyVector: readonly (readonly number[])[];
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
}): ProtocolDigest => deriveProtocolDigest('PublicKeyDigest', input);

const deriveReceiverKeyProofBackendStatementDigest = (
    statementPayload: Omit<
        ReceiverKeyProofBackendStatement,
        'backendStatementDigest'
    >,
): ProtocolDigest =>
    deriveReceiverKeyBackendDigest(
        receiverKeyStatementDigestPurpose,
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
        keyMaterialDigest: input.receiverPublicKey.keyMaterialDigest,
        manifestDigest: input.receiverPublicKey.manifestDigest,
        objectType: 'ReceiverEncryptionPublicKey',
        objectVersion: 1,
        receiverEncryptionProfileDigest:
            input.receiverPublicKey.receiverEncryptionProfileDigest,
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
        rosterDigest: input.receiverPublicKey.rosterDigest,
    };
    const expectedReceiverPublicKeyDigest =
        deriveReceiverEncryptionPublicKeyDigest(receiverPublicKeyPayload);
    if (
        input.receiverPublicKey.receiverPublicKeyDigest !==
        expectedReceiverPublicKeyDigest
    ) {
        throw new RangeError(
            'Receiver public-key digest does not match its canonical payload.',
        );
    }
    if (
        input.receiverPublicKey.receiverEncryptionProfileDigest !==
        input.receiverEncryptionProfile.receiverEncryptionProfileDigest
    ) {
        throw new RangeError(
            'Receiver public key is not bound to the receiver encryption profile.',
        );
    }

    const expectedPublicMatrixSeedDigest = deriveReceiverMatrixSeedDigest({
        ceremonyId: input.receiverPublicKey.ceremonyId,
        manifestDigest: input.receiverPublicKey.manifestDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
        rosterDigest: input.receiverPublicKey.rosterDigest,
    });
    if (
        input.publicKeyMaterial.publicMatrixSeedDigest !==
        expectedPublicMatrixSeedDigest
    ) {
        throw new RangeError(
            'Receiver key backend statement public matrix seed is not roster-bound.',
        );
    }

    const expectedKeyMaterialDigest = deriveReceiverKeyMaterialDigestForBackend(
        {
            publicKeyVector: input.publicKeyMaterial.publicKeyVector,
            publicMatrixSeedDigest:
                input.publicKeyMaterial.publicMatrixSeedDigest,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        },
    );
    if (
        input.receiverPublicKey.keyMaterialDigest !== expectedKeyMaterialDigest
    ) {
        throw new RangeError(
            'Receiver key backend statement public key material does not match the frozen receiver key.',
        );
    }

    const receiverKeyContextDigest = deriveReceiverKeyBackendDigest(
        receiverKeyPublicContextDigestPurpose,
        {
            ceremonyId: input.receiverPublicKey.ceremonyId,
            manifestDigest: input.receiverPublicKey.manifestDigest,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
            receiverIdentity: input.receiverPublicKey.receiverIdentity,
            receiverPublicKeyDigest:
                input.receiverPublicKey.receiverPublicKeyDigest,
            receiverRosterPosition:
                input.receiverPublicKey.receiverRosterPosition,
            recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
            rosterDigest: input.receiverPublicKey.rosterDigest,
        },
    );
    const variableColumns = buildVariableColumns();
    const variableColumnIndices = range(receiverKeyWitnessColumnCount);
    const rowBatchPayload = {
        coefficientExpansionDomain:
            receiverKeyEquationCoefficientExpansionDomain,
        modulus: String(receiverEncryptionModulus),
        publicInputDigests: {
            keyMaterialDigest: input.receiverPublicKey.keyMaterialDigest,
            publicMatrixSeedDigest:
                input.publicKeyMaterial.publicMatrixSeedDigest,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
            receiverKeyContextDigest,
            receiverPublicKeyDigest:
                input.receiverPublicKey.receiverPublicKeyDigest,
        },
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        rowCount: receiverKeyEquationRowCount,
        rowKind: 'ReceiverKeyEquation',
        sourceAlgebraicRowName: 'receiver_key_well_formedness',
        targetDigest: input.receiverPublicKey.keyMaterialDigest,
        targetExpansionDomain: receiverKeyEquationTargetExpansionDomain,
        variableColumnIndices,
    } as const;
    const rowBatch: ReceiverKeyProofBackendStatementRowBatch = {
        ...rowBatchPayload,
        batchKind: 'DigestExpandedRows',
        batchName: 'receiver_key_equation_rows',
        matrixDigest: deriveReceiverKeyBackendDigest(
            receiverKeyDigestExpandedMatrixDigestPurpose,
            rowBatchPayload,
        ),
        rowOffset: 0,
        targetVectorDigest: deriveReceiverKeyBackendDigest(
            receiverKeyDigestExpandedTargetVectorDigestPurpose,
            rowBatchPayload,
        ),
    };
    const bounds = buildReceiverKeyBackendBounds(variableColumns);
    const matrixDigest = deriveReceiverKeyBackendDigest(
        receiverKeyMatrixDigestPurpose,
        {
            rowBatches: [
                {
                    batchKind: rowBatch.batchKind,
                    batchName: rowBatch.batchName,
                    matrixDigest: rowBatch.matrixDigest,
                    rowCount: rowBatch.rowCount,
                    rowKind: rowBatch.rowKind,
                    rowOffset: rowBatch.rowOffset,
                },
            ],
        },
    );
    const targetVectorDigest = deriveReceiverKeyBackendDigest(
        receiverKeyTargetVectorDigestPurpose,
        {
            rowBatches: [
                {
                    batchKind: rowBatch.batchKind,
                    batchName: rowBatch.batchName,
                    rowCount: rowBatch.rowCount,
                    rowKind: rowBatch.rowKind,
                    rowOffset: rowBatch.rowOffset,
                    targetVectorDigest: rowBatch.targetVectorDigest,
                },
            ],
        },
    );
    const boundsDigest = deriveReceiverKeyBackendDigest(
        receiverKeyBoundsDigestPurpose,
        { bounds },
    );
    const statementPayload: Omit<
        ReceiverKeyProofBackendStatement,
        'backendStatementDigest'
    > = {
        backendStatementFormat,
        bounds,
        boundsDigest,
        ceremonyId: input.receiverPublicKey.ceremonyId,
        coefficientModulus: String(receiverEncryptionModulus),
        columnCount: receiverKeyWitnessColumnCount,
        digestExpandedRowCount: receiverKeyEquationRowCount,
        explicitRowCount: 0,
        keyMaterialDigest: input.receiverPublicKey.keyMaterialDigest,
        manifestDigest: input.receiverPublicKey.manifestDigest,
        matrixDigest,
        moduleDegree: receiverEncryptionModuleDegree,
        moduleRank: receiverEncryptionModuleRank,
        objectType: 'ReceiverKeyProofBackendStatement',
        objectVersion: 1,
        publicMatrixSeedDigest: input.publicKeyMaterial.publicMatrixSeedDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverKeyContextDigest,
        receiverPublicKeyDigest:
            input.receiverPublicKey.receiverPublicKeyDigest,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
        relationLabel: 'ReceiverKeyWellFormednessRelation',
        rosterDigest: input.receiverPublicKey.rosterDigest,
        rowBatches: [rowBatch],
        rowCount: receiverKeyEquationRowCount,
        targetVectorDigest,
        variableColumns,
    };

    return {
        ...statementPayload,
        backendStatementDigest:
            deriveReceiverKeyProofBackendStatementDigest(statementPayload),
    };
};
