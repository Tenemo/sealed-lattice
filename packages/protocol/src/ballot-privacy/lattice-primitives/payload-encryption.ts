import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
    ReceiverPayload,
    RefusalRecord,
    ShareCommitmentProfile,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';
import { createReceiverPayloadShell } from '../objects.js';

import type {
    BallotPrivacyRandomnessSource,
    ReceiverEncryptionChunkWitness,
    ReceiverEncryptionPublicKeyMaterial,
    ReceiverEncryptionWitness,
    ReceiverPayloadCiphertextChunk,
    ReceiverPayloadEncryptionResult,
    ReceiverPayloadPlaintextWitness,
} from './primitive-contracts.js';
import {
    addNumberPolynomials,
    canonicalEqual,
    deriveReceiverPublicMatrix,
    dotNumberPolynomialVectors,
    multiplyTransposeMatrixByVector,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    sampleCenteredBinomialVector,
} from './primitive-contracts.js';
import {
    deriveReceiverKeyMaterialDigest,
    encodePayloadPlaintextBits,
    encodePlaintextChunkPolynomial,
    validateReceiverPublicKeyMaterial,
} from './receiver-keys.js';

const sampleReceiverEncryptionChunkWitness = (
    randomnessSource: BallotPrivacyRandomnessSource,
    payload: unknown,
    chunkIndex: number,
): ReceiverEncryptionChunkWitness => ({
    chunkIndex,
    encryptionRandomnessVector: sampleCenteredBinomialVector(
        randomnessSource,
        'sealed.vote/internal/receiver-encryption/randomness-vector-v1',
        { chunkIndex, payload },
        receiverEncryptionModuleRank,
        receiverEncryptionModuleDegree,
    ),
    firstNoiseVector: sampleCenteredBinomialVector(
        randomnessSource,
        'sealed.vote/internal/receiver-encryption/first-noise-vector-v1',
        { chunkIndex, payload },
        receiverEncryptionModuleRank,
        receiverEncryptionModuleDegree,
    ),
    secondNoisePolynomial:
        sampleCenteredBinomialVector(
            randomnessSource,
            'sealed.vote/internal/receiver-encryption/second-noise-polynomial-v1',
            { chunkIndex, payload },
            1,
            receiverEncryptionModuleDegree,
        )[0] ?? [],
});

const sampleReceiverEncryptionWitness = (
    randomnessSource: BallotPrivacyRandomnessSource,
    payload: unknown,
    chunkCount: number,
): ReceiverEncryptionWitness => ({
    chunkWitnesses: Array.from(
        { length: chunkCount },
        (_unusedValue, chunkIndex) =>
            sampleReceiverEncryptionChunkWitness(
                randomnessSource,
                payload,
                chunkIndex,
            ),
    ),
});

export const encryptReceiverPayload = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
    readonly plaintext: ReceiverPayloadPlaintextWitness;
    readonly randomnessSource?: BallotPrivacyRandomnessSource;
    readonly witness?: ReceiverEncryptionWitness;
}): ReceiverPayloadEncryptionResult => {
    validateReceiverPublicKeyMaterial(input.publicKeyMaterial);
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
            'Receiver public-key material does not match the public key digest.',
        );
    }
    if (
        input.plaintext.receiverIdentity !==
            input.receiverPublicKey.receiverIdentity ||
        input.plaintext.receiverRosterPosition !==
            input.receiverPublicKey.receiverRosterPosition
    ) {
        throw new RangeError(
            'Receiver payload plaintext must target the frozen receiver key.',
        );
    }

    const plaintextBits = encodePayloadPlaintextBits(
        input.plaintext,
        input.shareCommitmentProfile,
    );
    const chunkCount = Math.ceil(
        plaintextBits.length / receiverEncryptionModuleDegree,
    );
    const randomnessSource = input.randomnessSource ?? { kind: 'production' };
    const witness =
        input.witness ??
        sampleReceiverEncryptionWitness(
            randomnessSource,
            {
                ballotPackageContextDigest:
                    input.plaintext.ballotPackageContextDigest,
                receiverIdentity: input.plaintext.receiverIdentity,
                receiverRosterPosition: input.plaintext.receiverRosterPosition,
                receiverPublicKeyDigest:
                    input.receiverPublicKey.receiverPublicKeyDigest,
            },
            chunkCount,
        );
    if (witness.chunkWitnesses.length !== chunkCount) {
        throw new RangeError(
            'Receiver encryption witness must contain one chunk witness per plaintext chunk.',
        );
    }
    const publicMatrix = deriveReceiverPublicMatrix(
        input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        input.publicKeyMaterial.publicMatrixSeedDigest,
    );
    const ciphertextChunks = Array.from(
        { length: chunkCount },
        (_unusedValue, chunkIndex) => {
            const chunkWitness = witness.chunkWitnesses[chunkIndex];
            if (chunkWitness?.chunkIndex !== chunkIndex) {
                throw new RangeError(
                    'Receiver encryption chunk witnesses must be in canonical chunk order.',
                );
            }
            const firstCiphertextBaseVector = multiplyTransposeMatrixByVector(
                publicMatrix,
                chunkWitness.encryptionRandomnessVector,
                receiverEncryptionModulus,
            ).map((polynomial, vectorIndex) =>
                addNumberPolynomials(
                    polynomial,
                    chunkWitness.firstNoiseVector[vectorIndex] ?? [],
                    receiverEncryptionModulus,
                ),
            );
            const secondCiphertextBasePolynomial = dotNumberPolynomialVectors(
                input.publicKeyMaterial.publicKeyVector,
                chunkWitness.encryptionRandomnessVector,
                receiverEncryptionModulus,
            );
            const encodedPlaintextPolynomial = encodePlaintextChunkPolynomial(
                plaintextBits,
                chunkIndex,
            );
            const secondCiphertextPolynomial = addNumberPolynomials(
                addNumberPolynomials(
                    secondCiphertextBasePolynomial,
                    chunkWitness.secondNoisePolynomial,
                    receiverEncryptionModulus,
                ),
                encodedPlaintextPolynomial,
                receiverEncryptionModulus,
            );

            return {
                chunkIndex,
                firstCiphertextVector: firstCiphertextBaseVector,
                secondCiphertextPolynomial,
            };
        },
    );
    const ciphertextBodyDigest = deriveProtocolDigest(
        'ReceiverPayloadCiphertextRoot',
        {
            ciphertextChunks,
            plaintextBitLength: plaintextBits.length,
            receiverEncryptionProfileDigest:
                input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        },
    );
    const payloadContextDigest = deriveProtocolDigest('ReceiverPayloadDigest', {
        ballotPackageContextDigest: input.plaintext.ballotPackageContextDigest,
        ceremonyId: input.plaintext.ceremonyId,
        manifestDigest: input.plaintext.manifestDigest,
        pollSpecDigest: input.plaintext.pollSpecDigest,
        receiverIdentity: input.plaintext.receiverIdentity,
        receiverRosterPosition: input.plaintext.receiverRosterPosition,
        rosterDigest: input.plaintext.rosterDigest,
        voterIdentityDigest: input.plaintext.voterIdentityDigest,
    });
    const receiverPayload = createReceiverPayloadShell({
        ceremonyId: input.plaintext.ceremonyId,
        manifestDigest: input.plaintext.manifestDigest,
        rosterDigest: input.plaintext.rosterDigest,
        pollSpecDigest: input.plaintext.pollSpecDigest,
        voterIdentityDigest: input.plaintext.voterIdentityDigest,
        receiverIdentity: input.plaintext.receiverIdentity,
        receiverRosterPosition: input.plaintext.receiverRosterPosition,
        receiverPublicKeyDigest:
            input.receiverPublicKey.receiverPublicKeyDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
        payloadContextDigest,
        ciphertextBodyDigest,
    });

    return {
        ciphertextChunks,
        plaintextBitLength: plaintextBits.length,
        receiverPayload,
        witness,
    };
};

export const verifyReceiverPayloadWitness = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly shareCommitmentProfile: ShareCommitmentProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
    readonly plaintext: ReceiverPayloadPlaintextWitness;
    readonly witness: ReceiverEncryptionWitness;
    readonly expectedReceiverPayload: ReceiverPayload;
    readonly expectedCiphertextChunks?: readonly ReceiverPayloadCiphertextChunk[];
}): readonly RefusalRecord[] => {
    const recomputedPayload = encryptReceiverPayload({
        plaintext: input.plaintext,
        publicKeyMaterial: input.publicKeyMaterial,
        receiverEncryptionProfile: input.receiverEncryptionProfile,
        receiverPublicKey: input.receiverPublicKey,
        shareCommitmentProfile: input.shareCommitmentProfile,
        witness: input.witness,
    });
    const refusedObjects: RefusalRecord[] = [];

    if (
        recomputedPayload.receiverPayload.receiverPayloadDigest !==
        input.expectedReceiverPayload.receiverPayloadDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver payload witness does not reproduce the expected encrypted payload digest.',
                input.expectedReceiverPayload.receiverPayloadDigest,
            ),
        );
    }
    if (
        input.expectedCiphertextChunks !== undefined &&
        !canonicalEqual(
            recomputedPayload.ciphertextChunks,
            input.expectedCiphertextChunks,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver payload witness does not reproduce the expected ciphertext chunks.',
                input.expectedReceiverPayload.receiverPayloadDigest,
            ),
        );
    }

    return refusedObjects;
};
