import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    ProtocolDigest,
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
    ShareCommitmentProfile,
} from '@sealed-lattice/types';

import { createReceiverEncryptionPublicKeyShell } from '../objects.js';

import type {
    BallotPrivacyRandomnessSource,
    ReceiverEncryptionPublicKeyMaterial,
    ReceiverEncryptionSecretState,
    ReceiverEncryptionState,
    ReceiverPayloadPlaintextWitness,
} from './primitive-contracts.js';
import {
    addNumberPolynomials,
    deriveReceiverPublicMatrix,
    multiplyMatrixByVector,
    receiverEncryptionCenteredBinomialEta,
    receiverEncryptionMessageScale,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    receiverOpeningRandomnessBitLength,
    sampleCenteredBinomialVector,
    validateReceiverShareVector,
} from './primitive-contracts.js';
import { validateShareCommitmentOpening } from './share-commitments.js';

const encodePayloadPlaintextBits = (
    plaintext: ReceiverPayloadPlaintextWitness,
    shareCommitmentProfile: ShareCommitmentProfile,
): readonly number[] => {
    validateReceiverShareVector(
        plaintext.receiverShareVector,
        shareCommitmentProfile,
    );
    validateShareCommitmentOpening(
        plaintext.shareCommitmentOpening,
        shareCommitmentProfile,
    );
    const bits: number[] = [];
    const pushUnsignedBits = (value: number, bitLength: number): void => {
        if (
            !Number.isSafeInteger(value) ||
            value < 0 ||
            value >= 2 ** bitLength
        ) {
            throw new RangeError(
                'Payload plaintext integer does not fit its bit width.',
            );
        }
        for (let bitIndex = 0; bitIndex < bitLength; bitIndex += 1) {
            bits.push((value >> bitIndex) & 1);
        }
    };

    for (const shareRepresentative of plaintext.receiverShareVector) {
        pushUnsignedBits(shareRepresentative, 17);
    }
    for (const openingCoordinate of plaintext.shareCommitmentOpening
        .openingRandomness) {
        pushUnsignedBits(
            openingCoordinate +
                shareCommitmentProfile.openingRandomnessInfinityNormBound,
            receiverOpeningRandomnessBitLength,
        );
    }

    return bits;
};

const encodePlaintextChunkPolynomial = (
    plaintextBits: readonly number[],
    chunkIndex: number,
): readonly number[] =>
    Array.from(
        { length: receiverEncryptionModuleDegree },
        (_unusedValue, coefficientIndex) => {
            const plaintextBit =
                plaintextBits[
                    chunkIndex * receiverEncryptionModuleDegree +
                        coefficientIndex
                ] ?? 0;

            return plaintextBit === 0 ? 0 : receiverEncryptionMessageScale;
        },
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

const deriveReceiverKeyMaterialDigest = (input: {
    readonly publicKeyVector: readonly (readonly number[])[];
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
}): ProtocolDigest => deriveProtocolDigest('PublicKeyDigest', input);

export const generateReceiverState = (input: {
    readonly ceremonyId: string;
    readonly manifestDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly randomnessSource?: BallotPrivacyRandomnessSource;
}): ReceiverEncryptionState => {
    const randomnessSource = input.randomnessSource ?? { kind: 'production' };
    const publicMatrixSeedDigest = deriveReceiverMatrixSeedDigest({
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        recoveryEpoch: input.recoveryEpoch,
        rosterDigest: input.rosterDigest,
    });
    const secretVector = sampleCenteredBinomialVector(
        randomnessSource,
        'sealed.vote/internal/receiver-encryption/secret-vector-v1',
        {
            publicMatrixSeedDigest,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
        receiverEncryptionModuleRank,
        receiverEncryptionModuleDegree,
    );
    const errorVector = sampleCenteredBinomialVector(
        randomnessSource,
        'sealed.vote/internal/receiver-encryption/key-error-vector-v1',
        {
            publicMatrixSeedDigest,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
        receiverEncryptionModuleRank,
        receiverEncryptionModuleDegree,
    );
    const publicMatrix = deriveReceiverPublicMatrix(
        input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        publicMatrixSeedDigest,
    );
    const publicKeyVector = multiplyMatrixByVector(
        publicMatrix,
        secretVector,
        receiverEncryptionModulus,
    ).map((polynomial, vectorIndex) =>
        addNumberPolynomials(
            polynomial,
            errorVector[vectorIndex] ?? [],
            receiverEncryptionModulus,
        ),
    );
    const keyMaterialDigest = deriveReceiverKeyMaterialDigest({
        publicKeyVector,
        publicMatrixSeedDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
    });
    const receiverPublicKey = createReceiverEncryptionPublicKeyShell({
        ceremonyId: input.ceremonyId,
        manifestDigest: input.manifestDigest,
        rosterDigest: input.rosterDigest,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        recoveryEpoch: input.recoveryEpoch,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        keyMaterialDigest,
    });

    return {
        publicKeyMaterial: {
            publicKeyVector,
            publicMatrixSeedDigest,
        },
        receiverPublicKey,
        secretState: {
            errorVector,
            secretVector,
        },
    };
};

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

const validateReceiverSecretState = (
    secretState: ReceiverEncryptionSecretState,
): void => {
    const validateShortVector = (
        vector: readonly (readonly number[])[],
        vectorLabel: string,
    ): void => {
        if (vector.length !== receiverEncryptionModuleRank) {
            throw new RangeError(
                `${vectorLabel} must use the frozen module rank.`,
            );
        }
        for (const polynomial of vector) {
            if (polynomial.length !== receiverEncryptionModuleDegree) {
                throw new RangeError(
                    `${vectorLabel} polynomials must use the frozen degree.`,
                );
            }
            for (const coefficient of polynomial) {
                if (
                    !Number.isSafeInteger(coefficient) ||
                    Math.abs(coefficient) >
                        receiverEncryptionCenteredBinomialEta
                ) {
                    throw new RangeError(
                        `${vectorLabel} coefficients must satisfy the frozen centered-binomial norm bound.`,
                    );
                }
            }
        }
    };

    validateShortVector(secretState.secretVector, 'Receiver secret vector');
    validateShortVector(secretState.errorVector, 'Receiver error vector');
};

const deriveExpectedReceiverPublicKeyMaterial = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly secretState: ReceiverEncryptionSecretState;
}): ReceiverEncryptionPublicKeyMaterial => {
    const publicMatrix = deriveReceiverPublicMatrix(
        input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        input.publicMatrixSeedDigest,
    );
    const publicKeyVector = multiplyMatrixByVector(
        publicMatrix,
        input.secretState.secretVector,
        receiverEncryptionModulus,
    ).map((polynomial, vectorIndex) =>
        addNumberPolynomials(
            polynomial,
            input.secretState.errorVector[vectorIndex] ?? [],
            receiverEncryptionModulus,
        ),
    );

    return {
        publicKeyVector,
        publicMatrixSeedDigest: input.publicMatrixSeedDigest,
    };
};

const deriveReceiverKeyProofRoot = (input: {
    readonly backendStatementDigest: ProtocolDigest;
    readonly linearStatementDigest: ProtocolDigest;
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
}): ProtocolDigest =>
    deriveProtocolDigest('ReceiverKeyProofRoot', {
        backendStatementDigest: input.backendStatementDigest,
        coefficientModulus: receiverEncryptionModulus,
        errorInfinityNormBound: receiverEncryptionCenteredBinomialEta,
        keyMaterialDigest: input.receiverPublicKey.keyMaterialDigest,
        linearStatementDigest: input.linearStatementDigest,
        moduleDegree: receiverEncryptionModuleDegree,
        moduleRank: receiverEncryptionModuleRank,
        proofRelation:
            'receiver_public_key_vector = public_matrix * secret_vector + error_vector mod q_receiver',
        proofRootKind: 'ReceiverKeyRelationLinearStatementAndBackendStatement',
        publicMatrixSeedDigest: input.publicKeyMaterial.publicMatrixSeedDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        receiverPublicKeyDigest:
            input.receiverPublicKey.receiverPublicKeyDigest,
        secretInfinityNormBound: receiverEncryptionCenteredBinomialEta,
    });

const deriveReceiverKeyProofBytesRoot = (input: {
    readonly linearStatementDigest: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofEncodingProfileDigest: ProtocolDigest;
    readonly proofParameterSetDigest: ProtocolDigest;
    readonly publicRandomnessDigest: ProtocolDigest;
}): ProtocolDigest =>
    deriveProtocolDigest('ReceiverKeyProofRoot', {
        linearStatementDigest: input.linearStatementDigest,
        proofBytesDigest: input.proofBytesDigest,
        proofEncodingProfileDigest: input.proofEncodingProfileDigest,
        proofParameterSetDigest: input.proofParameterSetDigest,
        publicRandomnessDigest: input.publicRandomnessDigest,
        purpose: 'receiver-key-linear-proof-record-root-v1',
    });

export {
    encodePayloadPlaintextBits,
    encodePlaintextChunkPolynomial,
    deriveReceiverMatrixSeedDigest,
    deriveReceiverKeyMaterialDigest,
    validateReceiverPublicKeyMaterial,
    validateReceiverSecretState,
    deriveExpectedReceiverPublicKeyMaterial,
    deriveReceiverKeyProofRoot,
    deriveReceiverKeyProofBytesRoot,
};
