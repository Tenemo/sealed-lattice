import { canonicalStreamTransportAccountingFromDescriptor } from '../canonical-stream-descriptor.js';
import type { SetupCertificateTransportedObjectInput } from '../setup-certificates.js';

import { assertObjectRecord, hashField } from './constants-and-assertions.js';
import type { SetupPackageInput } from './types.js';

const descriptorBackedTransportedMaterialObjects = (
    materialSetValue: unknown,
    materialSetFieldName: string,
    materialArrayFieldName: string,
    rootFieldName: string,
    objectName: string,
    objectRole: string,
): readonly SetupCertificateTransportedObjectInput[] => {
    if (materialSetValue === undefined) {
        return [];
    }
    const materialSet = assertObjectRecord(
        materialSetValue,
        materialSetFieldName,
    );
    const materials = materialSet[materialArrayFieldName];
    if (!Array.isArray(materials)) {
        throw new TypeError(
            `${materialSetFieldName}.${materialArrayFieldName} must be an array.`,
        );
    }

    return materials.map((materialValue, materialIndex) => {
        const objectPath = `${materialSetFieldName}.${materialArrayFieldName}.${String(materialIndex)}`;
        const material = assertObjectRecord(materialValue, objectPath);
        const accounting = canonicalStreamTransportAccountingFromDescriptor(
            material.descriptorBytes,
            `${objectPath}.descriptorBytes`,
        );

        return {
            objectName,
            objectRole,
            objectRoot: hashField(material, rootFieldName, objectPath),
            byteLength: accounting.totalByteLength,
            fullObjectHash: accounting.fullObjectHash,
            chunkRoot: accounting.chunkRoot,
            chunkHashes: accounting.chunkHashes,
        };
    });
};

const descriptorBackedTransportedMaterialObject = (
    materialValue: unknown,
    materialFieldName: string,
    rootFieldName: string,
    objectName: string,
    objectRole: string,
): readonly SetupCertificateTransportedObjectInput[] => {
    if (materialValue === undefined) {
        return [];
    }
    const material = assertObjectRecord(materialValue, materialFieldName);
    const accounting = canonicalStreamTransportAccountingFromDescriptor(
        material.descriptorBytes,
        `${materialFieldName}.descriptorBytes`,
    );

    return [
        {
            objectName,
            objectRole,
            objectRoot: hashField(material, rootFieldName, materialFieldName),
            byteLength: accounting.totalByteLength,
            fullObjectHash: accounting.fullObjectHash,
            chunkRoot: accounting.chunkRoot,
            chunkHashes: accounting.chunkHashes,
        },
    ];
};

export const setupCertificateTransportedObjectsFromPackageInput = (
    input: SetupPackageInput,
): readonly SetupCertificateTransportedObjectInput[] => [
    ...descriptorBackedTransportedMaterialObject(
        input.transportedPublicKeyShareMaterial,
        'transportedPublicKeyShareMaterial',
        'publicKeyShareMaterialSetRoot',
        'publicKeyShareMaterial',
        'public-key-share-material',
    ),
    ...descriptorBackedTransportedMaterialObjects(
        input.transportedPublicKeyShareProofMaterial,
        'transportedPublicKeyShareProofMaterial',
        'proofMaterials',
        'proofMaterialRoot',
        'publicKeyShareProofMaterial',
        'public-key-share-proof-material',
    ),
    ...descriptorBackedTransportedMaterialObjects(
        input.transportedVssShareLinkageProofMaterial,
        'transportedVssShareLinkageProofMaterial',
        'proofMaterials',
        'proofMaterialRoot',
        'vssShareLinkageProofMaterial',
        'vss-share-linkage-proof-material',
    ),
    ...descriptorBackedTransportedMaterialObjects(
        input.transportedSameSecretBridgeProofMaterial,
        'transportedSameSecretBridgeProofMaterial',
        'proofMaterials',
        'proofMaterialRoot',
        'sameSecretBridgeProofMaterial',
        'same-secret-bridge-proof-material',
    ),
    ...descriptorBackedTransportedMaterialObjects(
        input.transportedEvaluationKeyShareProofMaterial,
        'transportedEvaluationKeyShareProofMaterial',
        'proofMaterials',
        'proofMaterialRoot',
        'evaluationKeyShareProofMaterial',
        'evaluation-key-share-proof-material',
    ),
    ...descriptorBackedTransportedMaterialObjects(
        input.transportedEvaluationKeyShareComponentMaterial,
        'transportedEvaluationKeyShareComponentMaterial',
        'componentMaterials',
        'keySwitchComponentMaterialRoot',
        'evaluationKeyShareComponentMaterial',
        'evaluation-key-share-component-material',
    ),
    ...descriptorBackedTransportedMaterialObjects(
        input.transportedPublicEvaluationKeyMaterial,
        'transportedPublicEvaluationKeyMaterial',
        'publicEvaluationKeyMaterials',
        'publicEvaluationKeyMaterialRoot',
        'publicEvaluationKeyMaterial',
        'public-evaluation-key-runtime-material',
    ),
];
