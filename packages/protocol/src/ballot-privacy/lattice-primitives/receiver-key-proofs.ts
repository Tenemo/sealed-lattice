import type {
    ReceiverEncryptionProfile,
    ReceiverEncryptionPublicKey,
    ReceiverKeyProof,
    RefusalRecord,
} from '@sealed-lattice/types';

import { createRefusal } from '../../common/verification-helpers.js';
import {
    createReceiverKeyProofShell,
    deriveProofBytesDigest,
    deriveReceiverKeyProofEncodingProfileDigest,
    deriveReceiverKeyProofParameterSetDigest,
    deriveReceiverKeyProofPublicRandomnessDigest,
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

import type {
    ReceiverEncryptionPublicKeyMaterial,
    ReceiverEncryptionSecretState,
} from './primitive-contracts.js';
import { canonicalEqual } from './primitive-contracts.js';
import {
    deriveExpectedReceiverPublicKeyMaterial,
    deriveReceiverKeyMaterialDigest,
    deriveReceiverKeyProofBytesRoot,
    deriveReceiverKeyProofRoot,
    deriveReceiverMatrixSeedDigest,
    validateReceiverPublicKeyMaterial,
    validateReceiverSecretState,
} from './receiver-keys.js';

const validateReceiverKeyProofMaterialContracts = (
    proofMaterial: ReceiverKeyProofMaterial,
): number => {
    const proofBytesDigest = deriveProofBytesDigest({
        proofBytesHex: proofMaterial.proofBytesHex,
    });
    void proofBytesDigest;
    deriveReceiverKeyProofPublicRandomnessDigest({
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
                input.receiverPublicKey.receiverPublicKeyDigest,
            ),
        );

        return refusedObjects;
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
    const expectedPublicKeyMaterial = deriveExpectedReceiverPublicKeyMaterial({
        publicMatrixSeedDigest: input.publicKeyMaterial.publicMatrixSeedDigest,
        receiverEncryptionProfile: input.receiverEncryptionProfile,
        secretState: input.secretState,
    });
    const expectedKeyMaterialDigest = deriveReceiverKeyMaterialDigest({
        publicKeyVector: input.publicKeyMaterial.publicKeyVector,
        publicMatrixSeedDigest: input.publicKeyMaterial.publicMatrixSeedDigest,
        receiverEncryptionProfileDigest:
            input.receiverEncryptionProfile.receiverEncryptionProfileDigest,
    });

    if (
        input.receiverPublicKey.receiverEncryptionProfileDigest !==
        input.receiverEncryptionProfile.receiverEncryptionProfileDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key witness is not bound to the receiver encryption profile.',
                input.receiverPublicKey.receiverPublicKeyDigest,
            ),
        );
    }
    if (
        input.publicKeyMaterial.publicMatrixSeedDigest !==
        expectedPublicMatrixSeedDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key witness public matrix seed is not roster-bound.',
                input.receiverPublicKey.receiverPublicKeyDigest,
            ),
        );
    }
    if (
        input.receiverPublicKey.keyMaterialDigest !== expectedKeyMaterialDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPackageInvalid',
                'Receiver key witness public key material does not match the frozen receiver key.',
                input.receiverPublicKey.receiverPublicKeyDigest,
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
                input.receiverPublicKey.receiverPublicKeyDigest,
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
                  const proofBytesDigest = deriveProofBytesDigest({
                      proofBytesHex: input.proofMaterial.proofBytesHex,
                  });
                  const proofEncodingProfileDigest =
                      deriveReceiverKeyProofEncodingProfileDigest({
                          proofEncoding: input.proofMaterial.proofEncoding,
                      });
                  const proofParameterSetDigest =
                      deriveReceiverKeyProofParameterSetDigest({
                          parameterSet: input.proofMaterial.proofParameterSet,
                      });
                  const publicRandomnessDigest =
                      deriveReceiverKeyProofPublicRandomnessDigest({
                          publicRandomnessHex:
                              input.proofMaterial.publicRandomnessHex,
                      });

                  return {
                      backendStatementDigest:
                          backendStatement.backendStatementDigest,
                      linearStatementDigest: linearStatement.statementDigest,
                      proofBytesDigest,
                      proofEncodingProfileDigest,
                      proofParameterSetDigest,
                      proofRoot: deriveReceiverKeyProofBytesRoot({
                          linearStatementDigest:
                              linearStatement.statementDigest,
                          proofBytesDigest,
                          proofEncodingProfileDigest,
                          proofParameterSetDigest,
                          publicRandomnessDigest,
                      }),
                      proofSizeBytes,
                      publicRandomnessDigest,
                  };
              })();

    return createReceiverKeyProofShell({
        ceremonyId: input.receiverPublicKey.ceremonyId,
        manifestDigest: input.receiverPublicKey.manifestDigest,
        proofBackend: 'LocalLinearLatticeRelation',
        proofRoot:
            proofMaterialFields?.proofRoot ??
            deriveReceiverKeyProofRoot({
                ...input,
                backendStatementDigest: backendStatement.backendStatementDigest,
                linearStatementDigest: linearStatement.statementDigest,
            }),
        ...(proofMaterialFields === undefined
            ? {}
            : {
                  backendStatementDigest:
                      proofMaterialFields.backendStatementDigest,
                  linearStatementDigest:
                      proofMaterialFields.linearStatementDigest,
                  proofBytesDigest: proofMaterialFields.proofBytesDigest,
                  proofEncodingProfileDigest:
                      proofMaterialFields.proofEncodingProfileDigest,
                  proofParameterSetDigest:
                      proofMaterialFields.proofParameterSetDigest,
                  proofSizeBytes: proofMaterialFields.proofSizeBytes,
                  publicRandomnessDigest:
                      proofMaterialFields.publicRandomnessDigest,
              }),
        receiverEncryptionProfileDigest:
            input.receiverPublicKey.receiverEncryptionProfileDigest,
        receiverIdentity: input.receiverPublicKey.receiverIdentity,
        receiverPublicKeyDigest:
            input.receiverPublicKey.receiverPublicKeyDigest,
        receiverRosterPosition: input.receiverPublicKey.receiverRosterPosition,
        recoveryEpoch: input.receiverPublicKey.recoveryEpoch,
        rosterDigest: input.receiverPublicKey.rosterDigest,
    });
};
