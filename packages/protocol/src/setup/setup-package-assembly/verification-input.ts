import {
    assertObjectRecord,
    assertProtocolHash,
} from './constants-and-assertions.js';
import type {
    JsonRecord,
    SetupPackageVerificationInput,
    SetupPackageVerificationInputSource,
} from './types.js';

const descriptorBackedMaterialReferenceForVerificationInput = (
    materialValue: unknown,
    materialPath: string,
): JsonRecord => {
    const material = assertObjectRecord(materialValue, materialPath);
    const { descriptorBytes: omittedDescriptorBytes, ...materialReference } =
        material;
    void omittedDescriptorBytes;

    return materialReference;
};

const descriptorBackedMaterialSetForVerificationInput = (
    materialSetValue: unknown,
    materialSetPath: string,
    materialArrayFieldName: string,
): JsonRecord | undefined => {
    if (materialSetValue === undefined) {
        return undefined;
    }
    const materialSet = assertObjectRecord(materialSetValue, materialSetPath);
    const materials = materialSet[materialArrayFieldName];
    if (!Array.isArray(materials)) {
        throw new TypeError(
            `${materialSetPath}.${materialArrayFieldName} must be an array.`,
        );
    }

    return {
        ...materialSet,
        [materialArrayFieldName]: materials.map(
            (materialValue, materialIndex) =>
                descriptorBackedMaterialReferenceForVerificationInput(
                    materialValue,
                    `${materialSetPath}.${materialArrayFieldName}.${String(materialIndex)}`,
                ),
        ),
    };
};

export const createSetupPackageVerificationInput = (
    input: SetupPackageVerificationInputSource,
): SetupPackageVerificationInput => {
    assertProtocolHash(input.expectedManifestHash, 'expectedManifestHash');
    assertProtocolHash(input.expectedRosterHash, 'expectedRosterHash');

    const transportedPublicKeyShareProofMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedPublicKeyShareProofMaterial,
            'transportedPublicKeyShareProofMaterial',
            'proofMaterials',
        );
    const transportedEvaluationKeyShareProofMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedEvaluationKeyShareProofMaterial,
            'transportedEvaluationKeyShareProofMaterial',
            'proofMaterials',
        );
    const transportedVssShareLinkageProofMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedVssShareLinkageProofMaterial,
            'transportedVssShareLinkageProofMaterial',
            'proofMaterials',
        );
    const transportedSameSecretBridgeProofMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedSameSecretBridgeProofMaterial,
            'transportedSameSecretBridgeProofMaterial',
            'proofMaterials',
        );
    const transportedPublicKeyShareMaterial =
        input.transportedPublicKeyShareMaterial === undefined
            ? undefined
            : descriptorBackedMaterialReferenceForVerificationInput(
                  input.transportedPublicKeyShareMaterial,
                  'transportedPublicKeyShareMaterial',
              );
    const transportedEvaluationKeyShareComponentMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedEvaluationKeyShareComponentMaterial,
            'transportedEvaluationKeyShareComponentMaterial',
            'componentMaterials',
        );
    const transportedPublicEvaluationKeyMaterial =
        descriptorBackedMaterialSetForVerificationInput(
            input.transportedPublicEvaluationKeyMaterial,
            'transportedPublicEvaluationKeyMaterial',
            'publicEvaluationKeyMaterials',
        );

    return {
        setupPackage: input.setupPackage,
        expectedManifestHash: input.expectedManifestHash,
        expectedRosterHash: input.expectedRosterHash,
        ...(transportedPublicKeyShareMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareMaterial:
                      transportedPublicKeyShareMaterial,
              }),
        ...(transportedPublicKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedPublicKeyShareProofMaterial:
                      transportedPublicKeyShareProofMaterial,
              }),
        ...(transportedEvaluationKeyShareProofMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareProofMaterial:
                      transportedEvaluationKeyShareProofMaterial,
              }),
        ...(transportedVssShareLinkageProofMaterial === undefined
            ? {}
            : {
                  transportedVssShareLinkageProofMaterial:
                      transportedVssShareLinkageProofMaterial,
              }),
        ...(transportedSameSecretBridgeProofMaterial === undefined
            ? {}
            : {
                  transportedSameSecretBridgeProofMaterial:
                      transportedSameSecretBridgeProofMaterial,
              }),
        ...(transportedEvaluationKeyShareComponentMaterial === undefined
            ? {}
            : {
                  transportedEvaluationKeyShareComponentMaterial:
                      transportedEvaluationKeyShareComponentMaterial,
              }),
        ...(transportedPublicEvaluationKeyMaterial === undefined
            ? {}
            : {
                  transportedPublicEvaluationKeyMaterial:
                      transportedPublicEvaluationKeyMaterial,
              }),
    };
};
