import type {
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
    ReceiverKeyProof,
    RefusalRecord,
} from '@sealed-lattice/types';

import {
    createReceiverKeyProofShell,
    deriveProofBytesHash,
    deriveReceiverKeyProofEncodingProfileHash,
    deriveReceiverKeyProofParameterSetHash,
    deriveReceiverKeyProofPublicRandomnessHash,
} from '../objects.js';
import { createReceiverKeyProofBackendStatement } from '../receiver-key-backend-statement.js';
import {
    createReceiverKeyLinearProofStatement,
    verifyReceiverKeyLinearWitness,
} from '../receiver-key-linear-statement.js';
import {
    createReceiverKeyLinearProofEncoding,
    createReceiverKeyLinearProofParameterSet,
    type ReceiverKeyProofMaterial,
} from '../receiver-key-proof-parameters.js';
import { createRefusal } from '../verification-helpers.js';

import type {
    ReceiverEncryptionPublicKeyMaterial,
    ReceiverEncryptionSecretState,
} from './primitive-contracts.js';
import { canonicalEqual } from './primitive-contracts.js';
import {
    deriveExpectedReceiverPublicKeyMaterial,
    deriveReceiverKeyMaterialHash,
    deriveReceiverKeyProofBytesRoot,
    deriveReceiverKeyProofRoot,
    deriveReceiverMatrixSeedHash,
    validateReceiverPublicKeyMaterial,
    validateReceiverSecretState,
} from './receiver-keys.js';

const validateReceiverKeyProofMaterialContracts = (
    proofMaterial: ReceiverKeyProofMaterial,
): number => {
    const proofBytesHash = deriveProofBytesHash({
        proofBytesHex: proofMaterial.proofBytesHex,
    });
    void proofBytesHash;
    deriveReceiverKeyProofPublicRandomnessHash({
        publicRandomnessHex: proofMaterial.publicRandomnessHex,
    });
    const proofSizeBytes = proofMaterial.proofBytesHex.length / 2;
    const expectedProofEncoding = createReceiverKeyLinearProofEncoding({
        expectedProofSizeBytes: proofSizeBytes,
    });
    const expectedProofParameterSet = createReceiverKeyLinearProofParameterSet({
        expectedProofSizeBytes: proofSizeBytes,
    });

    if (!canonicalEqual(proofMaterial.proofEncoding, expectedProofEncoding)) {
        throw new RangeError(
            'Receiver-key proof material must use the frozen proof encoding contract for its proof length.',
        );
    }
    if (
        !canonicalEqual(
            proofMaterial.proofParameterSet,
            expectedProofParameterSet,
        )
    ) {
        throw new RangeError(
            'Receiver-key proof material must use the frozen proof parameter contract for its proof length.',
        );
    }

    return proofSizeBytes;
};

export const verifyReceiverKeyWitness = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
    readonly secretState: ReceiverEncryptionSecretState;
}): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];

    try {
        validateReceiverPublicKeyMaterial(input.publicKeyMaterial);
        validateReceiverSecretState(input.secretState);
    } catch (error) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                error instanceof Error
                    ? error.message
                    : 'Receiver key witness is malformed.',
                input.receiverPublicKey.receiverPublicKeyHash,
            ),
        );

        return refusedObjects;
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
    const expectedPublicKeyMaterial = deriveExpectedReceiverPublicKeyMaterial({
        publicMatrixSeedHash: input.publicKeyMaterial.publicMatrixSeedHash,
        receiverEncryptionProfile: input.receiverEncryptionProfile,
        secretState: input.secretState,
    });
    const expectedKeyMaterialHash = deriveReceiverKeyMaterialHash({
        publicKeyVector: input.publicKeyMaterial.publicKeyVector,
        publicMatrixSeedHash: input.publicKeyMaterial.publicMatrixSeedHash,
        receiverEncryptionProfileHash:
            input.receiverEncryptionProfile.receiverEncryptionProfileHash,
    });

    if (
        input.receiverPublicKey.receiverEncryptionProfileHash !==
        input.receiverEncryptionProfile.receiverEncryptionProfileHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key witness is not bound to the receiver encryption profile.',
                input.receiverPublicKey.receiverPublicKeyHash,
            ),
        );
    }
    if (
        input.publicKeyMaterial.publicMatrixSeedHash !==
        expectedPublicMatrixSeedHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key witness public matrix seed is not roster-bound.',
                input.receiverPublicKey.receiverPublicKeyHash,
            ),
        );
    }
    if (input.receiverPublicKey.keyMaterialHash !== expectedKeyMaterialHash) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key witness public key material does not match the frozen receiver key.',
                input.receiverPublicKey.receiverPublicKeyHash,
            ),
        );
    }
    if (
        !canonicalEqual(
            input.publicKeyMaterial.publicKeyVector,
            expectedPublicKeyMaterial.publicKeyVector,
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key witness does not satisfy the frozen receiver-key equation.',
                input.receiverPublicKey.receiverPublicKeyHash,
            ),
        );
    }

    return refusedObjects;
};

export const createReceiverKeyProof = (input: {
    readonly receiverEncryptionProfile: ReceiverEncryptionProfile;
    readonly receiverPublicKey: ReceiverEncryptionPublicKey;
    readonly publicKeyMaterial: ReceiverEncryptionPublicKeyMaterial;
    readonly secretState: ReceiverEncryptionSecretState;
    readonly proofMaterial?: ReceiverKeyProofMaterial;
}): ReceiverKeyProof => {
    const refusedObjects = verifyReceiverKeyWitness(input);
    if (refusedObjects.length > 0) {
        throw new RangeError(
            refusedObjects.map((refusal) => refusal.message).join(' '),
        );
    }
    const backendStatement = createReceiverKeyProofBackendStatement({
        publicKeyMaterial: input.publicKeyMaterial,
        receiverEncryptionProfile: input.receiverEncryptionProfile,
        receiverPublicKey: input.receiverPublicKey,
    });
    const linearStatement = createReceiverKeyLinearProofStatement({
        publicKeyMaterial: input.publicKeyMaterial,
        receiverEncryptionProfile: input.receiverEncryptionProfile,
        receiverPublicKey: input.receiverPublicKey,
    });
    verifyReceiverKeyLinearWitness({
        publicKeyMaterial: input.publicKeyMaterial,
        receiverEncryptionProfile: input.receiverEncryptionProfile,
        receiverPublicKey: input.receiverPublicKey,
        secretState: input.secretState,
    });
    const proofMaterialFields =
        input.proofMaterial === undefined
            ? undefined
            : (() => {
                  const proofSizeBytes =
                      validateReceiverKeyProofMaterialContracts(
                          input.proofMaterial,
                      );
                  const proofBytesHash = deriveProofBytesHash({
                      proofBytesHex: input.proofMaterial.proofBytesHex,
                  });
                  const proofEncodingProfileHash =
                      deriveReceiverKeyProofEncodingProfileHash({
                          proofEncoding: input.proofMaterial.proofEncoding,
                      });
                  const proofParameterSetHash =
                      deriveReceiverKeyProofParameterSetHash({
                          parameterSet: input.proofMaterial.proofParameterSet,
                      });
                  const publicRandomnessHash =
                      deriveReceiverKeyProofPublicRandomnessHash({
                          publicRandomnessHex:
                              input.proofMaterial.publicRandomnessHex,
                      });

                  return {
                      backendStatementHash:
                          backendStatement.backendStatementHash,
                      linearStatementHash: linearStatement.statementHash,
                      proofBytesHash,
                      proofEncodingProfileHash,
                      proofParameterSetHash,
                      proofRoot: deriveReceiverKeyProofBytesRoot({
                          linearStatementHash: linearStatement.statementHash,
                          proofBytesHash,
                          proofEncodingProfileHash,
                          proofParameterSetHash,
                          publicRandomnessHash,
                      }),
                      proofSizeBytes,
                      publicRandomnessHash,
                  };
              })();

    return createReceiverKeyProofShell({
        ceremonyId: input.receiverPublicKey.ceremonyId,
        manifestHash: input.receiverPublicKey.manifestHash,
        proofBackend: 'LocalLinearLatticeRelation',
        proofRoot:
            proofMaterialFields?.proofRoot ??
            deriveReceiverKeyProofRoot({
                ...input,
                backendStatementHash: backendStatement.backendStatementHash,
                linearStatementHash: linearStatement.statementHash,
            }),
        ...(proofMaterialFields === undefined
            ? {}
            : {
                  backendStatementHash:
                      proofMaterialFields.backendStatementHash,
                  linearStatementHash: proofMaterialFields.linearStatementHash,
                  proofBytesHash: proofMaterialFields.proofBytesHash,
                  proofEncodingProfileHash:
                      proofMaterialFields.proofEncodingProfileHash,
                  proofParameterSetHash:
                      proofMaterialFields.proofParameterSetHash,
                  proofSizeBytes: proofMaterialFields.proofSizeBytes,
                  publicRandomnessHash:
                      proofMaterialFields.publicRandomnessHash,
              }),
        receiverEncryptionProfileHash:
            input.receiverPublicKey.receiverEncryptionProfileHash,
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverPublicKeyHash: input.receiverPublicKey.receiverPublicKeyHash,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
        rosterHash: input.receiverPublicKey.rosterHash,
    });
};
