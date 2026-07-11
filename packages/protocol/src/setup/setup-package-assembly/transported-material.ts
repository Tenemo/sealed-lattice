import type { ProtocolHash } from '@sealed-lattice/types';

import type { SetupCertificateTransportedObjectInput } from '../setup-certificates.js';
import {
    vssCoefficientCommitmentMaterialTransportEncoding,
    type VssCoefficientCommitmentMaterialBinaryReference,
} from '../vss-coefficient-commitments.js';

import {
    assertObjectRecord,
    assertProtocolHash,
    hashField,
} from './constants-and-assertions.js';
import type { SetupPackageInput } from './types.js';

const nonNegativeSafeIntegerField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (
        typeof fieldValue !== 'number' ||
        !Number.isSafeInteger(fieldValue) ||
        fieldValue < 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a non-negative safe integer.`,
        );
    }

    return fieldValue;
};

const positiveSafeIntegerField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (
        typeof fieldValue !== 'number' ||
        !Number.isSafeInteger(fieldValue) ||
        fieldValue <= 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a positive safe integer.`,
        );
    }

    return fieldValue;
};

const protocolHashArrayField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): readonly ProtocolHash[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(`${objectPath}.${fieldName} must be an array.`);
    }

    return fieldValue.map((item, itemIndex) => {
        if (typeof item !== 'string') {
            throw new TypeError(
                `${objectPath}.${fieldName}.${String(itemIndex)} must be a string.`,
            );
        }
        assertProtocolHash(
            item,
            `${objectPath}.${fieldName}.${String(itemIndex)}`,
        );

        return item;
    });
};

const transportedMaterialObject = (
    material: Readonly<Record<string, unknown>>,
    objectPath: string,
    rootFieldName: string,
    objectName: string,
    objectRole: string,
): SetupCertificateTransportedObjectInput => ({
    objectName,
    objectRole,
    objectRoot: hashField(material, rootFieldName, objectPath),
    byteLength: positiveSafeIntegerField(
        material,
        'totalByteLength',
        objectPath,
    ),
    fullObjectHash: hashField(material, 'fullObjectHash', objectPath),
    chunkRoot: hashField(material, 'chunkRoot', objectPath),
    chunkHashes: protocolHashArrayField(material, 'chunkHashes', objectPath),
});

type TransportedProofMaterialFieldNames = Readonly<{
    readonly byteLength: string;
    readonly fullObjectHash: string;
    readonly chunkRoot: string;
    readonly chunkHashes: string;
}>;

const plainTransportedProofMaterialFields: TransportedProofMaterialFieldNames =
    {
        byteLength: 'totalByteLength',
        fullObjectHash: 'fullObjectHash',
        chunkRoot: 'chunkRoot',
        chunkHashes: 'chunkHashes',
    };

const proofPrefixedTransportedProofMaterialFields: TransportedProofMaterialFieldNames =
    {
        byteLength: 'proofTotalByteLength',
        fullObjectHash: 'proofFullObjectHash',
        chunkRoot: 'proofChunkRoot',
        chunkHashes: 'proofChunkHashes',
    };

const transportedProofMaterialObjects = (
    materialSetValue: unknown,
    materialSetFieldName: string,
    objectName: string,
    objectRole: string,
    fieldNames: TransportedProofMaterialFieldNames,
): readonly SetupCertificateTransportedObjectInput[] => {
    if (materialSetValue === undefined) {
        return [];
    }
    const materialSet = assertObjectRecord(
        materialSetValue,
        materialSetFieldName,
    );
    const proofMaterials = materialSet.proofMaterials;
    if (!Array.isArray(proofMaterials)) {
        throw new TypeError(
            `${materialSetFieldName}.proofMaterials must be an array.`,
        );
    }

    return proofMaterials.map((proofMaterialValue, proofMaterialIndex) => {
        const objectPath = `${materialSetFieldName}.proofMaterials.${String(proofMaterialIndex)}`;
        const proofMaterial = assertObjectRecord(
            proofMaterialValue,
            objectPath,
        );

        return {
            objectName,
            objectRole,
            objectRoot: hashField(
                proofMaterial,
                'proofMaterialRoot',
                objectPath,
            ),
            byteLength: positiveSafeIntegerField(
                proofMaterial,
                fieldNames.byteLength,
                objectPath,
            ),
            fullObjectHash: hashField(
                proofMaterial,
                fieldNames.fullObjectHash,
                objectPath,
            ),
            chunkRoot: hashField(
                proofMaterial,
                fieldNames.chunkRoot,
                objectPath,
            ),
            chunkHashes: protocolHashArrayField(
                proofMaterial,
                fieldNames.chunkHashes,
                objectPath,
            ),
        };
    });
};

const transportedMaterialObjects = (
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

    return materials.map((materialValue, materialIndex) =>
        transportedMaterialObject(
            assertObjectRecord(
                materialValue,
                `${materialSetFieldName}.${materialArrayFieldName}.${String(materialIndex)}`,
            ),
            `${materialSetFieldName}.${materialArrayFieldName}.${String(materialIndex)}`,
            rootFieldName,
            objectName,
            objectRole,
        ),
    );
};

const transportedPublicKeyShareMaterialObject = (
    input: SetupPackageInput,
): readonly SetupCertificateTransportedObjectInput[] => {
    if (input.transportedPublicKeyShareMaterial === undefined) {
        return [];
    }
    const transportedMaterial = assertObjectRecord(
        input.transportedPublicKeyShareMaterial,
        'transportedPublicKeyShareMaterial',
    );
    const packageMaterialRoot = hashField(
        input.publicKeyShareMaterial,
        'publicKeyShareMaterialSetRoot',
        'publicKeyShareMaterial',
    );

    return [
        {
            objectName: 'publicKeyShareMaterial',
            objectRole: 'public-key-share-material',
            objectRoot: packageMaterialRoot,
            byteLength: positiveSafeIntegerField(
                transportedMaterial,
                'totalByteLength',
                'transportedPublicKeyShareMaterial',
            ),
            fullObjectHash: hashField(
                transportedMaterial,
                'fullObjectHash',
                'transportedPublicKeyShareMaterial',
            ),
            chunkRoot: hashField(
                transportedMaterial,
                'chunkRoot',
                'transportedPublicKeyShareMaterial',
            ),
            chunkHashes: protocolHashArrayField(
                transportedMaterial,
                'chunkHashes',
                'transportedPublicKeyShareMaterial',
            ),
        },
    ];
};

const transportedVssCoefficientCommitmentMaterialObject = (
    input: SetupPackageInput,
): readonly SetupCertificateTransportedObjectInput[] => {
    const material = assertObjectRecord(
        input.vssCoefficientCommitmentMaterial,
        'vssCoefficientCommitmentMaterial',
    );
    if (
        material.materialEncoding !==
        vssCoefficientCommitmentMaterialTransportEncoding
    ) {
        return [];
    }

    return [
        transportedMaterialObject(
            material,
            'vssCoefficientCommitmentMaterial',
            'vssCoefficientCommitmentMaterialRoot',
            'vssCoefficientCommitmentMaterial',
            'public-vss-coefficient-commitment-material',
        ),
    ];
};

export const vssCoefficientCommitmentMaterialReferenceFromCertificate = (
    input: SetupPackageInput,
    setupTransportCertificate: Readonly<Record<string, unknown>>,
): VssCoefficientCommitmentMaterialBinaryReference => {
    const material = assertObjectRecord(
        input.vssCoefficientCommitmentMaterial,
        'vssCoefficientCommitmentMaterial',
    );
    const transportedObjects = setupTransportCertificate.transportedObjects;
    if (!Array.isArray(transportedObjects)) {
        throw new TypeError(
            'setupTransportCertificate.transportedObjects must be an array.',
        );
    }
    const matchingTransportedObjects = transportedObjects.filter(
        (transportedObjectValue) => {
            const transportedObject = assertObjectRecord(
                transportedObjectValue,
                'setupTransportCertificate.transportedObjects',
            );

            return (
                transportedObject.objectName ===
                'vssCoefficientCommitmentMaterial'
            );
        },
    );
    if (matchingTransportedObjects.length !== 1) {
        throw new Error(
            'setupTransportCertificate must bind exactly one vssCoefficientCommitmentMaterial object.',
        );
    }
    const transportedObject = assertObjectRecord(
        matchingTransportedObjects[0],
        'setupTransportCertificate.transportedObjects.vssCoefficientCommitmentMaterial',
    );
    if (
        transportedObject.objectRole !==
            'public-vss-coefficient-commitment-material' ||
        transportedObject.encoding !== 'binary'
    ) {
        throw new Error(
            'setupTransportCertificate vssCoefficientCommitmentMaterial must use the canonical role and binary encoding.',
        );
    }
    const materialRoot = hashField(
        material,
        'vssCoefficientCommitmentMaterialRoot',
        'vssCoefficientCommitmentMaterial',
    );
    if (
        hashField(
            transportedObject,
            'objectRoot',
            'setupTransportCertificate.transportedObjects.vssCoefficientCommitmentMaterial',
        ) !== materialRoot
    ) {
        throw new Error(
            'setupTransportCertificate vssCoefficientCommitmentMaterial root must match the pre-finalization material root.',
        );
    }
    const chunkCount = positiveSafeIntegerField(
        transportedObject,
        'chunkCount',
        'setupTransportCertificate.transportedObjects.vssCoefficientCommitmentMaterial',
    );
    const chunkHashes = protocolHashArrayField(
        transportedObject,
        'chunkHashes',
        'setupTransportCertificate.transportedObjects.vssCoefficientCommitmentMaterial',
    );
    if (chunkHashes.length !== chunkCount) {
        throw new Error(
            'setupTransportCertificate vssCoefficientCommitmentMaterial chunk count must match its chunk hashes.',
        );
    }

    return {
        objectType: 'VssCoefficientCommitmentMaterialSet',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: hashField(
            material,
            'publicMatrixSeedHash',
            'vssCoefficientCommitmentMaterial',
        ),
        vssCoefficientCommitmentRoot: hashField(
            material,
            'vssCoefficientCommitmentRoot',
            'vssCoefficientCommitmentMaterial',
        ),
        materialEncoding: vssCoefficientCommitmentMaterialTransportEncoding,
        participantCount: positiveSafeIntegerField(
            material,
            'participantCount',
            'vssCoefficientCommitmentMaterial',
        ),
        thresholdDegree: positiveSafeIntegerField(
            material,
            'thresholdDegree',
            'vssCoefficientCommitmentMaterial',
        ),
        rnsLimbCount: positiveSafeIntegerField(
            material,
            'rnsLimbCount',
            'vssCoefficientCommitmentMaterial',
        ),
        ringDegree: positiveSafeIntegerField(
            material,
            'ringDegree',
            'vssCoefficientCommitmentMaterial',
        ),
        materialRecordCount: nonNegativeSafeIntegerField(
            material,
            'materialRecordCount',
            'vssCoefficientCommitmentMaterial',
        ),
        vssCoefficientCommitmentMaterialRoot: materialRoot,
        chunkCount,
        totalByteLength: positiveSafeIntegerField(
            transportedObject,
            'byteLength',
            'setupTransportCertificate.transportedObjects.vssCoefficientCommitmentMaterial',
        ),
        fullObjectHash: hashField(
            transportedObject,
            'fullObjectHash',
            'setupTransportCertificate.transportedObjects.vssCoefficientCommitmentMaterial',
        ),
        chunkRoot: hashField(
            transportedObject,
            'chunkRoot',
            'setupTransportCertificate.transportedObjects.vssCoefficientCommitmentMaterial',
        ),
        chunkHashes,
    };
};

export const setupCertificateTransportedObjectsFromPackageInput = (
    input: SetupPackageInput,
): readonly SetupCertificateTransportedObjectInput[] => [
    ...transportedVssCoefficientCommitmentMaterialObject(input),
    ...transportedPublicKeyShareMaterialObject(input),
    ...transportedProofMaterialObjects(
        input.transportedPublicKeyShareProofMaterial,
        'transportedPublicKeyShareProofMaterial',
        'publicKeyShareProofMaterial',
        'public-key-share-proof-material',
        plainTransportedProofMaterialFields,
    ),
    ...transportedProofMaterialObjects(
        input.transportedEvaluationKeyShareProofMaterial,
        'transportedEvaluationKeyShareProofMaterial',
        'evaluationKeyShareProofMaterial',
        'evaluation-key-share-proof-material',
        proofPrefixedTransportedProofMaterialFields,
    ),
    ...transportedMaterialObjects(
        input.transportedEvaluationKeyShareComponentMaterial,
        'transportedEvaluationKeyShareComponentMaterial',
        'componentMaterials',
        'keySwitchComponentMaterialRoot',
        'evaluationKeyShareComponentMaterial',
        'evaluation-key-share-component-material',
    ),
    ...transportedMaterialObjects(
        input.transportedPublicEvaluationKeyMaterial,
        'transportedPublicEvaluationKeyMaterial',
        'publicEvaluationKeyMaterials',
        'publicEvaluationKeyMaterialRoot',
        'publicEvaluationKeyMaterial',
        'public-evaluation-key-runtime-material',
    ),
];
