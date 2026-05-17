import {
    canonicalJson,
    deriveProtocolDigest,
    hash512,
} from '@sealed-lattice/crypto';
import type {
    ProtocolDigest,
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
} from '@sealed-lattice/types';

const textEncoder = new TextEncoder();
const receiverEncryptionModulus = 12_289;
const receiverEncryptionModuleRank = 4;
const receiverEncryptionModuleDegree = 256;
const receiverEncryptionShortVectorInfinityNormBound = 2;
const receiverKeyStatementRows = receiverEncryptionModuleRank;
const receiverKeyStatementColumns = 8;
const receiverKeyWitnessL2BoundSquared =
    receiverKeyStatementColumns *
    receiverEncryptionModuleDegree *
    receiverEncryptionShortVectorInfinityNormBound *
    receiverEncryptionShortVectorInfinityNormBound;
const unsignedWordModulus = 1n << 64n;
const statementProfileId = 'receiver-key-linear-module-lwe-statement-v1';
const statementDigestPurpose = 'receiver-key-linear-proof-statement-v1';
const statementMatrixDigestPurpose =
    'receiver-key-linear-proof-statement-matrix-v1';
const targetVectorDigestPurpose = 'receiver-key-linear-proof-target-vector-v1';

type ReceiverEncryptionPublicKeyPayload = Omit<
    ReceiverEncryptionPublicKey,
    'receiverPublicKeyDigest'
>;

type ReceiverEncryptionPublicKeyMaterial = {
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly publicKeyVector: readonly (readonly number[])[];
};

type ReceiverEncryptionSecretState = {
    readonly secretVector: readonly (readonly number[])[];
    readonly errorVector: readonly (readonly number[])[];
};

export type ReceiverKeyLinearProofStatement = {
    readonly objectType: 'ReceiverKeyLinearProofStatement';
    readonly objectVersion: 1;
    readonly statementProfileId: typeof statementProfileId;
    readonly statementDigest: ProtocolDigest;
    readonly statementMatrixDigest: ProtocolDigest;
    readonly targetVectorDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly receiverPublicKeyDigest: ProtocolDigest;
    readonly keyMaterialDigest: ProtocolDigest;
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly relation: 'A*w + t = 0';
    readonly sourceRing: 'Z_q[X]/(X^256 + 1)';
    readonly coefficientModulus: '12289';
    readonly ringDegree: 256;
    readonly statementRows: 4;
    readonly statementColumns: 8;
    readonly witnessVectorLayout: readonly [
        'receiver secret polynomial 0',
        'receiver secret polynomial 1',
        'receiver secret polynomial 2',
        'receiver secret polynomial 3',
        'receiver error polynomial 0',
        'receiver error polynomial 1',
        'receiver error polynomial 2',
        'receiver error polynomial 3',
    ];
    readonly witnessInfinityNormBound: 2;
    readonly witnessL2BoundSquared: string;
    readonly statementMatrixCoefficients: readonly (readonly (readonly number[])[])[];
    readonly targetCoefficientRepresentation: 'centeredSignedSourceModulus';
    readonly targetVectorCoefficients: readonly (readonly number[])[];
};

type ReceiverKeyLinearWitnessCheck = {
    readonly ok: true;
    readonly statementDigest: ProtocolDigest;
    readonly witnessL2Squared: number;
};

const canonicalBytes = (value: unknown): Uint8Array =>
    textEncoder.encode(canonicalJson(value));

const deriveBytes = (
    domain: string,
    payload: unknown,
    byteLength: number,
): Uint8Array => {
    const output = new Uint8Array(byteLength);
    let outputOffset = 0;
    let blockCounter = 0;
    while (outputOffset < byteLength) {
        const block = hash512(domain, [
            canonicalBytes({
                blockCounter,
                payload,
            }),
        ]);
        const bytesToCopy = Math.min(block.length, byteLength - outputOffset);
        output.set(block.subarray(0, bytesToCopy), outputOffset);
        outputOffset += bytesToCopy;
        blockCounter += 1;
    }

    return output;
};

const readLittleEndianWord = (
    bytes: Uint8Array,
    byteOffset: number,
): bigint => {
    let value = 0n;
    for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
        value |=
            BigInt(bytes[byteOffset + byteIndex] ?? 0) << BigInt(8 * byteIndex);
    }

    return value;
};

const deriveUniformBigInt = (
    domain: string,
    payload: unknown,
    modulus: bigint,
): bigint => {
    const rejectionLimit =
        unsignedWordModulus - (unsignedWordModulus % modulus);
    let blockCounter = 0;
    for (;;) {
        const block = deriveBytes(domain, { blockCounter, payload }, 64);
        for (
            let byteOffset = 0;
            byteOffset + 8 <= block.length;
            byteOffset += 8
        ) {
            const candidate = readLittleEndianWord(block, byteOffset);
            if (candidate < rejectionLimit) {
                return candidate % modulus;
            }
        }
        blockCounter += 1;
    }
};

const deriveUniformNumber = (
    domain: string,
    payload: unknown,
    modulus: number,
): number => Number(deriveUniformBigInt(domain, payload, BigInt(modulus)));

const deriveNumberPolynomial = (
    domain: string,
    payload: unknown,
    degree: number,
    modulus: number,
): readonly number[] =>
    Array.from({ length: degree }, (_unusedValue, coefficientIndex) =>
        deriveUniformNumber(domain, { coefficientIndex, payload }, modulus),
    );

const deriveReceiverPublicMatrix = (
    receiverEncryptionProfileDigest: ProtocolDigest,
    publicMatrixSeedDigest: ProtocolDigest,
): readonly (readonly (readonly number[])[])[] =>
    Array.from(
        { length: receiverEncryptionModuleRank },
        (_unusedRow, rowIndex) =>
            Array.from(
                { length: receiverEncryptionModuleRank },
                (_unusedColumn, columnIndex) =>
                    deriveNumberPolynomial(
                        'sealed.vote/internal/receiver-encryption/public-matrix-v1',
                        {
                            columnIndex,
                            publicMatrixSeedDigest,
                            receiverEncryptionProfileDigest,
                            rowIndex,
                        },
                        receiverEncryptionModuleDegree,
                        receiverEncryptionModulus,
                    ),
            ),
    );

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

const deriveReceiverKeyMaterialDigest = (input: {
    readonly publicKeyVector: readonly (readonly number[])[];
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
}): ProtocolDigest => deriveProtocolDigest('PublicKeyDigest', input);

const deriveReceiverKeyLinearDigest = (
    purpose: string,
    payload: unknown,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload,
        purpose,
    });

const validateCanonicalReceiverPolynomialVector = (
    vector: readonly (readonly number[])[],
    label: string,
): void => {
    if (vector.length !== receiverEncryptionModuleRank) {
        throw new RangeError(`${label} must use the frozen module rank.`);
    }
    for (const polynomial of vector) {
        if (polynomial.length !== receiverEncryptionModuleDegree) {
            throw new RangeError(
                `${label} polynomials must use the frozen degree.`,
            );
        }
        for (const coefficient of polynomial) {
            if (
                !Number.isSafeInteger(coefficient) ||
                coefficient < 0 ||
                coefficient >= receiverEncryptionModulus
            ) {
                throw new RangeError(
                    `${label} coefficients must be canonical representatives.`,
                );
            }
        }
    }
};

const validateShortReceiverPolynomialVector = (
    vector: readonly (readonly number[])[],
    label: string,
): void => {
    if (vector.length !== receiverEncryptionModuleRank) {
        throw new RangeError(`${label} must use the frozen module rank.`);
    }
    for (const polynomial of vector) {
        if (polynomial.length !== receiverEncryptionModuleDegree) {
            throw new RangeError(
                `${label} polynomials must use the frozen degree.`,
            );
        }
        for (const coefficient of polynomial) {
            if (
                !Number.isSafeInteger(coefficient) ||
                Math.abs(coefficient) >
                    receiverEncryptionShortVectorInfinityNormBound
            ) {
                throw new RangeError(
                    `${label} coefficients must satisfy the frozen infinity-norm bound.`,
                );
            }
        }
    }
};

const modNumber = (value: number, modulus: number): number =>
    ((value % modulus) + modulus) % modulus;

const zeroPolynomial = (): number[] =>
    Array.from({ length: receiverEncryptionModuleDegree }, () => 0);

const identityPolynomial = (
    rowIndex: number,
    columnIndex: number,
): readonly number[] => {
    const polynomial = zeroPolynomial();
    if (rowIndex === columnIndex) {
        polynomial[0] = 1;
    }

    return polynomial;
};

const addNumberPolynomials = (
    leftPolynomial: readonly number[],
    rightPolynomial: readonly number[],
    modulus: number,
): readonly number[] =>
    leftPolynomial.map((coefficient, coefficientIndex) =>
        modNumber(
            coefficient + (rightPolynomial[coefficientIndex] ?? 0),
            modulus,
        ),
    );

const multiplyNumberPolynomials = (
    leftPolynomial: readonly number[],
    rightPolynomial: readonly number[],
    modulus: number,
): readonly number[] => {
    const output = zeroPolynomial();
    for (
        let leftCoefficientIndex = 0;
        leftCoefficientIndex < receiverEncryptionModuleDegree;
        leftCoefficientIndex += 1
    ) {
        for (
            let rightCoefficientIndex = 0;
            rightCoefficientIndex < receiverEncryptionModuleDegree;
            rightCoefficientIndex += 1
        ) {
            const rawIndex = leftCoefficientIndex + rightCoefficientIndex;
            const outputIndex = rawIndex % receiverEncryptionModuleDegree;
            const sign = rawIndex >= receiverEncryptionModuleDegree ? -1 : 1;
            output[outputIndex] = modNumber(
                output[outputIndex] +
                    sign *
                        leftPolynomial[leftCoefficientIndex] *
                        rightPolynomial[rightCoefficientIndex],
                modulus,
            );
        }
    }

    return output;
};

const multiplyStatementMatrixByWitness = (input: {
    readonly matrix: readonly (readonly (readonly number[])[])[];
    readonly witnessVector: readonly (readonly number[])[];
}): readonly (readonly number[])[] =>
    input.matrix.map((matrixRow) => {
        let accumulatedPolynomial = zeroPolynomial();
        for (
            let columnIndex = 0;
            columnIndex < matrixRow.length;
            columnIndex += 1
        ) {
            accumulatedPolynomial = [
                ...addNumberPolynomials(
                    accumulatedPolynomial,
                    multiplyNumberPolynomials(
                        matrixRow[columnIndex] ?? zeroPolynomial(),
                        input.witnessVector[columnIndex] ?? zeroPolynomial(),
                        receiverEncryptionModulus,
                    ),
                    receiverEncryptionModulus,
                ),
            ];
        }

        return accumulatedPolynomial;
    });

const validateReceiverPublicKeyBinding = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
}): void => {
    validateCanonicalReceiverPolynomialVector(
        input.publicKeyMaterial.publicKeyVector,
        'Receiver public-key material',
    );
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
    const expectedPublicKeyDigest = deriveReceiverEncryptionPublicKeyDigest(
        receiverPublicKeyPayload,
    );
    if (
        input.receiverPublicKey.receiverPublicKeyDigest !==
        expectedPublicKeyDigest
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
            'Receiver-key linear statement public matrix seed is not roster-bound.',
        );
    }
    const expectedKeyMaterialDigest = deriveReceiverKeyMaterialDigest({
        publicKeyVector: input.publicKeyMaterial.publicKeyVector,
        publicMatrixSeedDigest: input.publicKeyMaterial.publicMatrixSeedDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
    });
    if (
        input.receiverPublicKey.keyMaterialDigest !== expectedKeyMaterialDigest
    ) {
        throw new RangeError(
            'Receiver-key linear statement public key material does not match the frozen receiver key.',
        );
    }
};

export const createReceiverKeyLinearProofStatement = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
}): ReceiverKeyLinearProofStatement => {
    validateReceiverPublicKeyBinding(input);

    const publicMatrix = deriveReceiverPublicMatrix(
        input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        input.publicKeyMaterial.publicMatrixSeedDigest,
    );
    const statementMatrixCoefficients = publicMatrix.map(
        (matrixRow, rowIndex) => [
            ...matrixRow,
            ...Array.from(
                { length: receiverEncryptionModuleRank },
                (_unusedValue, identityColumnIndex) =>
                    identityPolynomial(rowIndex, identityColumnIndex),
            ),
        ],
    );
    const targetVectorCoefficients =
        input.publicKeyMaterial.publicKeyVector.map((polynomial) =>
            polynomial.map((coefficient) =>
                modNumber(-coefficient, receiverEncryptionModulus),
            ),
        );
    const statementMatrixDigest = deriveReceiverKeyLinearDigest(
        statementMatrixDigestPurpose,
        statementMatrixCoefficients,
    );
    const targetVectorDigest = deriveReceiverKeyLinearDigest(
        targetVectorDigestPurpose,
        targetVectorCoefficients,
    );
    const statementPayload: Omit<
        ReceiverKeyLinearProofStatement,
        'statementDigest'
    > = {
        ceremonyId: input.receiverPublicKey.ceremonyId,
        coefficientModulus: String(receiverEncryptionModulus) as '12289',
        keyMaterialDigest: input.receiverPublicKey.keyMaterialDigest,
        manifestDigest: input.receiverPublicKey.manifestDigest,
        objectType: 'ReceiverKeyLinearProofStatement',
        objectVersion: 1,
        publicMatrixSeedDigest: input.publicKeyMaterial.publicMatrixSeedDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverPublicKeyDigest:
            input.receiverPublicKey.receiverPublicKeyDigest,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
        relation: 'A*w + t = 0',
        ringDegree: receiverEncryptionModuleDegree,
        rosterDigest: input.receiverPublicKey.rosterDigest,
        sourceRing: 'Z_q[X]/(X^256 + 1)',
        statementColumns: receiverKeyStatementColumns,
        statementMatrixCoefficients,
        statementMatrixDigest,
        statementProfileId,
        statementRows: receiverKeyStatementRows,
        targetCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetVectorCoefficients,
        targetVectorDigest,
        witnessInfinityNormBound:
            receiverEncryptionShortVectorInfinityNormBound,
        witnessL2BoundSquared: String(receiverKeyWitnessL2BoundSquared),
        witnessVectorLayout: [
            'receiver secret polynomial 0',
            'receiver secret polynomial 1',
            'receiver secret polynomial 2',
            'receiver secret polynomial 3',
            'receiver error polynomial 0',
            'receiver error polynomial 1',
            'receiver error polynomial 2',
            'receiver error polynomial 3',
        ],
    };

    return {
        ...statementPayload,
        statementDigest: deriveReceiverKeyLinearDigest(
            statementDigestPurpose,
            statementPayload,
        ),
    };
};

export const verifyReceiverKeyLinearWitness = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
    readonly secretState: ReceiverEncryptionSecretState;
}): ReceiverKeyLinearWitnessCheck => {
    validateShortReceiverPolynomialVector(
        input.secretState.secretVector,
        'Receiver secret vector',
    );
    validateShortReceiverPolynomialVector(
        input.secretState.errorVector,
        'Receiver error vector',
    );
    const statement = createReceiverKeyLinearProofStatement(input);
    const witnessVector = [
        ...input.secretState.secretVector,
        ...input.secretState.errorVector,
    ];
    let witnessL2Squared = 0;
    for (const polynomial of witnessVector) {
        for (const coefficient of polynomial) {
            witnessL2Squared += coefficient * coefficient;
        }
    }
    if (witnessL2Squared > receiverKeyWitnessL2BoundSquared) {
        throw new RangeError(
            'Receiver-key linear statement witness exceeds the frozen l2 bound.',
        );
    }

    const matrixProduct = multiplyStatementMatrixByWitness({
        matrix: statement.statementMatrixCoefficients,
        witnessVector,
    });
    const relationOutput = matrixProduct.map((polynomial, rowIndex) =>
        addNumberPolynomials(
            polynomial,
            statement.targetVectorCoefficients[rowIndex] ?? zeroPolynomial(),
            receiverEncryptionModulus,
        ),
    );
    if (
        relationOutput.some((polynomial) =>
            polynomial.some((coefficient) => coefficient !== 0),
        )
    ) {
        throw new RangeError(
            'Receiver-key linear statement witness does not satisfy A*w + t = 0.',
        );
    }

    return {
        ok: true,
        statementDigest: statement.statementDigest,
        witnessL2Squared,
    };
};
