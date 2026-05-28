import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    ProtocolHash,
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

const deriveReceiverKeyMaterialHash = (input: {
    readonly publicKeyVector: readonly (readonly number[])[];
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly receiverEncryptionProfileHash: ProtocolHash;
}): ProtocolHash => deriveProtocolHash('PublicKeyHash', input);

export const generateReceiverState = (input: {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly recoveryEpoch: number;
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly randomnessSource?: BallotPrivacyRandomnessSource;
}): ReceiverEncryptionState => {
    const randomnessSource = input.randomnessSource ?? { kind: 'production' };
    const publicMatrixSeedHash = deriveReceiverMatrixSeedHash({
        ceremonyId: input.ceremonyId,
        manifestHash: input.manifestHash,
        receiverEncryptionProfileHash:
            input.receiverEncryptionProfile.receiverEncryptionProfileHash,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        recoveryEpoch: input.recoveryEpoch,
        rosterHash: input.rosterHash,
    });
    const secretVector = sampleCenteredBinomialVector(
        randomnessSource,
        'sealed.vote/internal/receiver-encryption/secret-vector-v1',
        {
            publicMatrixSeedHash,
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
            publicMatrixSeedHash,
            receiverIdentity: input.receiverIdentity,
            receiverRosterPosition: input.receiverRosterPosition,
        },
        receiverEncryptionModuleRank,
        receiverEncryptionModuleDegree,
    );
    const publicMatrix = deriveReceiverPublicMatrix(
        input.receiverEncryptionProfile.receiverEncryptionProfileHash,
        publicMatrixSeedHash,
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
    const keyMaterialHash = deriveReceiverKeyMaterialHash({
        publicKeyVector,
        publicMatrixSeedHash,
        receiverEncryptionProfileHash:
            input.receiverEncryptionProfile.receiverEncryptionProfileHash,
    });
    const receiverPublicKey = createReceiverEncryptionPublicKeyShell({
        ceremonyId: input.ceremonyId,
        manifestHash: input.manifestHash,
        rosterHash: input.rosterHash,
        receiverIdentity: input.receiverIdentity,
        receiverRosterPosition: input.receiverRosterPosition,
        recoveryEpoch: input.recoveryEpoch,
        receiverEncryptionProfileHash:
            input.receiverEncryptionProfile.receiverEncryptionProfileHash,
        keyMaterialHash,
    });

    return {
        publicKeyMaterial: {
            publicKeyVector,
            publicMatrixSeedHash,
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
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly secretState: ReceiverEncryptionSecretState;
}): ReceiverEncryptionPublicKeyMaterial => {
    const publicMatrix = deriveReceiverPublicMatrix(
        input.receiverEncryptionProfile.receiverEncryptionProfileHash,
        input.publicMatrixSeedHash,
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
        publicMatrixSeedHash: input.publicMatrixSeedHash,
    };
};

const deriveReceiverKeyProofRoot = (input: {
    readonly backendStatementHash: ProtocolHash;
    readonly linearStatementHash: ProtocolHash;
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
}): ProtocolHash =>
    deriveProtocolHash('ReceiverKeyProofRoot', {
        backendStatementHash: input.backendStatementHash,
        coefficientModulus: receiverEncryptionModulus,
        errorInfinityNormBound: receiverEncryptionCenteredBinomialEta,
        keyMaterialHash: input.receiverPublicKey.keyMaterialHash,
        linearStatementHash: input.linearStatementHash,
        moduleDegree: receiverEncryptionModuleDegree,
        moduleRank: receiverEncryptionModuleRank,
        proofRelation:
            'receiver_public_key_vector = public_matrix * secret_vector + error_vector mod q_receiver',
        proofRootKind: 'ReceiverKeyRelationLinearStatementAndBackendStatement',
        publicMatrixSeedHash: input.publicKeyMaterial.publicMatrixSeedHash,
        receiverEncryptionProfileHash:
            input.receiverEncryptionProfile.receiverEncryptionProfileHash,
        receiverPublicKeyHash: input.receiverPublicKey.receiverPublicKeyHash,
        secretInfinityNormBound: receiverEncryptionCenteredBinomialEta,
    });

const deriveReceiverKeyProofBytesRoot = (input: {
    readonly linearStatementHash: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofEncodingProfileHash: ProtocolHash;
    readonly proofParameterSetHash: ProtocolHash;
    readonly publicRandomnessHash: ProtocolHash;
}): ProtocolHash =>
    deriveProtocolHash('ReceiverKeyProofRoot', {
        linearStatementHash: input.linearStatementHash,
        proofBytesHash: input.proofBytesHash,
        proofEncodingProfileHash: input.proofEncodingProfileHash,
        proofParameterSetHash: input.proofParameterSetHash,
        publicRandomnessHash: input.publicRandomnessHash,
        purpose: 'receiver-key-linear-proof-record-root-v1',
    });

export {
    encodePayloadPlaintextBits,
    encodePlaintextChunkPolynomial,
    deriveReceiverMatrixSeedHash,
    deriveReceiverKeyMaterialHash,
    validateReceiverPublicKeyMaterial,
    validateReceiverSecretState,
    deriveExpectedReceiverPublicKeyMaterial,
    deriveReceiverKeyProofRoot,
    deriveReceiverKeyProofBytesRoot,
};
