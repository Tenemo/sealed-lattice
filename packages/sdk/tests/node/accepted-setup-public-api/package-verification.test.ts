import { describe, expect, it } from 'vitest';

import { hash512Hex, publicSetupApi } from './support.js';

type JsonRecord = Record<string, unknown>;

type SetupProofMaterialTransportFieldName =
    | 'transportedSameSecretProofMaterial'
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial';

type SetupProofMaterialTransportCase = Readonly<{
    readonly fieldName: SetupProofMaterialTransportFieldName;
    readonly materialSetObjectType:
        | 'SetupTransportedSameSecretProofMaterialSet'
        | 'SetupTransportedPublicKeyShareProofMaterialSet'
        | 'SetupTransportedEvaluationKeyShareProofMaterialSet';
    readonly materialObjectType:
        | 'SetupTransportedSameSecretProofMaterial'
        | 'SetupTransportedPublicKeyShareProofMaterial'
        | 'SetupTransportedEvaluationKeyShareProofMaterial';
    readonly proofFamily:
        | 'same-secret-linkage-anchor'
        | 'public-key-share'
        | 'trustee-evaluation-key';
}>;

const setupProofProfileId = 'SealedLattice-SetupProof-v1';

const setupProofMaterialTransportCases = [
    {
        fieldName: 'transportedSameSecretProofMaterial',
        materialSetObjectType: 'SetupTransportedSameSecretProofMaterialSet',
        materialObjectType: 'SetupTransportedSameSecretProofMaterial',
        proofFamily: 'same-secret-linkage-anchor',
    },
    {
        fieldName: 'transportedPublicKeyShareProofMaterial',
        materialSetObjectType: 'SetupTransportedPublicKeyShareProofMaterialSet',
        materialObjectType: 'SetupTransportedPublicKeyShareProofMaterial',
        proofFamily: 'public-key-share',
    },
    {
        fieldName: 'transportedEvaluationKeyShareProofMaterial',
        materialSetObjectType:
            'SetupTransportedEvaluationKeyShareProofMaterialSet',
        materialObjectType: 'SetupTransportedEvaluationKeyShareProofMaterial',
        proofFamily: 'trustee-evaluation-key',
    },
] as const satisfies readonly SetupProofMaterialTransportCase[];

const setupProofMaterialRoot = (
    transportCase: SetupProofMaterialTransportCase,
): string =>
    hash512Hex('sealed-lattice/test/setup-proof-material-root', [
        new TextEncoder().encode(transportCase.proofFamily),
    ]);

const transportedSetupProofMaterialSet = (
    transportCase: SetupProofMaterialTransportCase,
): JsonRecord => {
    const proofMaterialRoot = setupProofMaterialRoot(transportCase);

    return {
        objectType: transportCase.materialSetObjectType,
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: transportCase.proofFamily,
        proofMaterials: [
            {
                objectType: transportCase.materialObjectType,
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot,
                chunkSizeBytes: 1_048_576,
                chunkCount: 1,
                totalByteLength: 4,
                fullObjectHash: proofMaterialRoot,
                chunkHashes: [proofMaterialRoot],
                chunkRoot: proofMaterialRoot,
                chunks: [
                    {
                        chunkIndex: 0,
                        bytesHex: '01020304',
                    },
                ],
            },
        ],
    };
};

const verifiedSetupProofMaterials = (
    proofMaterialRootForCase: (
        transportCase: SetupProofMaterialTransportCase,
    ) => string = setupProofMaterialRoot,
): JsonRecord => ({
    objectType: 'VerifiedSetupProofMaterialSet',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    setupProofProfileId,
    proofMaterials: setupProofMaterialTransportCases.map((transportCase) => {
        const proofMaterialRoot = proofMaterialRootForCase(transportCase);

        return {
            objectType: 'VerifiedSetupProofMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            verificationId: `sdk-public-${transportCase.proofFamily}`,
            proofFamily: transportCase.proofFamily,
            proofMaterialRoot,
            proofBytesEncoding: 'binary-chunked-proof-bytes',
            proofChunkSizeBytes: 1_048_576,
            proofChunkCount: 1,
            proofTotalByteLength: 4,
            proofFullObjectHash: proofMaterialRoot,
            proofChunkRoot: proofMaterialRoot,
            proofChunkHashes: [proofMaterialRoot],
        };
    }),
});

const transportedPublicCompanions = (): Readonly<{
    readonly transportedPublicKeyShareMaterial: JsonRecord;
    readonly transportedEvaluationKeyShareComponentMaterial: JsonRecord;
    readonly transportedPublicEvaluationKeyMaterial: JsonRecord;
}> => {
    const publicKeyShareMaterialRoot = hash512Hex(
        'sealed-lattice/test/public-key-share-material-root',
        [new Uint8Array([13, 14, 15, 16])],
    );
    const evaluationKeyComponentRoot = hash512Hex(
        'sealed-lattice/test/evaluation-key-component-root',
        [new Uint8Array([17, 18, 19, 20])],
    );
    const publicEvaluationKeyMaterialRoot = hash512Hex(
        'sealed-lattice/test/public-evaluation-key-material-root',
        [new Uint8Array([21, 22, 23, 24])],
    );

    return {
        transportedPublicKeyShareMaterial: {
            objectType: 'SetupTransportedPublicKeyShareMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            publicKeyShareMaterials: [
                {
                    objectType: 'SetupTransportedPublicKeyShareMaterial',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    publicKeyShareMaterialRoot,
                    chunkSizeBytes: 1_048_576,
                    chunkCount: 1,
                    totalByteLength: 4,
                    fullObjectHash: publicKeyShareMaterialRoot,
                    chunkRoot: publicKeyShareMaterialRoot,
                    chunkHashes: [publicKeyShareMaterialRoot],
                },
            ],
        },
        transportedEvaluationKeyShareComponentMaterial: {
            objectType:
                'SetupTransportedEvaluationKeyShareComponentMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            componentMaterials: [
                {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterial',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    keySwitchComponentMaterialRoot: evaluationKeyComponentRoot,
                    chunkSizeBytes: 1_048_576,
                    chunkCount: 1,
                    totalByteLength: 4,
                    fullObjectHash: evaluationKeyComponentRoot,
                    chunkRoot: evaluationKeyComponentRoot,
                    chunkHashes: [evaluationKeyComponentRoot],
                },
            ],
        },
        transportedPublicEvaluationKeyMaterial: {
            objectType: 'SetupTransportedPublicEvaluationKeyMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            materialEncoding:
                'sealed-lattice-public-evaluation-key-material-binary-v1',
            publicEvaluationKeyMaterials: [
                {
                    objectType: 'SetupTransportedPublicEvaluationKeyMaterial',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    publicEvaluationKeyMaterialRoot,
                    chunkSizeBytes: 1_048_576,
                    chunkCount: 1,
                    totalByteLength: 4,
                    fullObjectHash: publicEvaluationKeyMaterialRoot,
                    chunkRoot: publicEvaluationKeyMaterialRoot,
                    chunkHashes: [publicEvaluationKeyMaterialRoot],
                },
            ],
            componentMaterials: [],
        },
    };
};

describe('accepted setup public package API in Node', () => {
    it('exposes setup package verification without accepting passive setup packages', async () => {
        const transportHash = hash512Hex(
            'sealed-lattice/test/setup-verification-vss-transport',
            [new Uint8Array([1, 2, 3, 4])],
        );
        const chunkHash = hash512Hex(
            'sealed-lattice/test/setup-verification-vss-chunk',
            [new Uint8Array([1, 2, 3, 4])],
        );
        const vssMaterialReference = {
            objectType: 'SetupTransportedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            binaryFormat:
                'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
            chunkSizeBytes: 1_048_576,
            chunkCount: 1,
            totalByteLength: 4,
            fullObjectHash: transportHash,
            chunkHashes: [chunkHash],
            chunkRoot: chunkHash,
        };
        const transportedVssCoefficientCommitmentMaterial = {
            ...vssMaterialReference,
            chunks: [
                {
                    chunkIndex: 0,
                    bytesHex: '01020304',
                },
            ],
        };
        const verifiedVssCoefficientCommitmentMaterial = {
            objectType: 'VerifiedVssCoefficientCommitmentMaterial',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            verificationId: 'sdk-public-verification-input-test',
            materialBinaryFormat:
                'sealed-lattice-vss-coefficient-commitment-material-binary-v1',
            publicMatrixSeedHash: transportHash,
            vssCoefficientCommitmentRoot: transportHash,
            vssCoefficientCommitmentMaterialRoot: transportHash,
            thresholdShareCommitmentRoot: transportHash,
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
            transportChunkSizeBytes: 1_048_576,
            transportChunkCount: 1,
            transportTotalByteLength: 4,
            transportFullObjectHash: transportHash,
            transportChunkRoot: chunkHash,
        };
        const setupPackage = {
            objectType: 'SetupPackage',
            objectVersion: 1,
            setupPackageHash: transportHash,
        };

        const verificationInput =
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                transportedVssCoefficientCommitmentMaterial,
                verifiedVssCoefficientCommitmentMaterial,
            });

        expect(verificationInput.setupPackage).toBe(setupPackage);
        expect(verificationInput.verifiedVssCoefficientCommitmentMaterial).toBe(
            verifiedVssCoefficientCommitmentMaterial,
        );
        expect(
            verificationInput.transportedVssCoefficientCommitmentMaterial,
        ).toEqual(vssMaterialReference);
        expect(
            verificationInput.transportedVssCoefficientCommitmentMaterial,
        ).not.toHaveProperty('chunks');

        const verification = await publicSetupApi.verifySetupPackage({
            setupPackage: {
                objectType: 'BgvPassiveSetupPackage',
                objectVersion: 1,
            },
        });

        expect(verification).toMatchObject({
            ok: false,
            operation: 'verifyCollectiveBgvSetupPackage',
            verifierStatus: 'outsideProfile',
        });
        expect(verification.acceptedSetupHandoff).toBeUndefined();
    });

    it('keeps setup proof chunks in public verification input', () => {
        const setupPackage = {
            objectType: 'SetupPackage',
            objectVersion: 1,
            setupPackageHash: hash512Hex(
                'sealed-lattice/test/setup-package-hash',
                [new Uint8Array([5, 6, 7, 8])],
            ),
        };
        const publicCompanions = transportedPublicCompanions();
        const verificationInput =
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                transportedSameSecretProofMaterial:
                    transportedSetupProofMaterialSet(
                        setupProofMaterialTransportCases[0],
                    ),
                transportedPublicKeyShareProofMaterial:
                    transportedSetupProofMaterialSet(
                        setupProofMaterialTransportCases[1],
                    ),
                transportedEvaluationKeyShareProofMaterial:
                    transportedSetupProofMaterialSet(
                        setupProofMaterialTransportCases[2],
                    ),
                ...publicCompanions,
            });

        expect(verificationInput.setupPackage).toBe(setupPackage);
        expect(verificationInput.transportedPublicKeyShareMaterial).toBe(
            publicCompanions.transportedPublicKeyShareMaterial,
        );
        expect(
            verificationInput.transportedEvaluationKeyShareComponentMaterial,
        ).toBe(publicCompanions.transportedEvaluationKeyShareComponentMaterial);
        expect(verificationInput.transportedPublicEvaluationKeyMaterial).toBe(
            publicCompanions.transportedPublicEvaluationKeyMaterial,
        );
        for (const transportCase of setupProofMaterialTransportCases) {
            const materialSet = verificationInput[transportCase.fieldName] as
                | Readonly<{
                      readonly proofMaterials: readonly JsonRecord[];
                  }>
                | undefined;
            expect(materialSet?.proofMaterials[0]).toMatchObject({
                objectType: transportCase.materialObjectType,
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot: setupProofMaterialRoot(transportCase),
            });
            expect(materialSet?.proofMaterials[0]).toHaveProperty('chunks');
        }
    });

    it('ignores caller-supplied setup proof handles in public verification input', () => {
        const setupPackage = {
            objectType: 'SetupPackage',
            objectVersion: 1,
            setupPackageHash: hash512Hex(
                'sealed-lattice/test/setup-package-hash-with-unverified-proof-material',
                [new Uint8Array([9, 10, 11, 12])],
            ),
        };
        const inputWithCallerProofHandles: Record<string, unknown> = {
            setupPackage,
            transportedSameSecretProofMaterial:
                transportedSetupProofMaterialSet(
                    setupProofMaterialTransportCases[0],
                ),
            transportedPublicKeyShareProofMaterial:
                transportedSetupProofMaterialSet(
                    setupProofMaterialTransportCases[1],
                ),
            transportedEvaluationKeyShareProofMaterial:
                transportedSetupProofMaterialSet(
                    setupProofMaterialTransportCases[2],
                ),
            verifiedSetupProofMaterials: verifiedSetupProofMaterials(
                (transportCase) =>
                    hash512Hex(
                        'sealed-lattice/test/foreign-setup-proof-material-root',
                        [new TextEncoder().encode(transportCase.proofFamily)],
                    ),
            ),
        };
        const verificationInput =
            publicSetupApi.createSetupPackageVerificationInput(
                inputWithCallerProofHandles,
            );

        for (const transportCase of setupProofMaterialTransportCases) {
            const materialSet = verificationInput[transportCase.fieldName] as
                | Readonly<{
                      readonly proofMaterials: readonly JsonRecord[];
                  }>
                | undefined;
            expect(materialSet?.proofMaterials[0]).toMatchObject({
                objectType: transportCase.materialObjectType,
                proofFamily: transportCase.proofFamily,
                proofMaterialRoot: setupProofMaterialRoot(transportCase),
            });
            expect(materialSet?.proofMaterials[0]).toHaveProperty('chunks');
        }
        expect(verificationInput).not.toHaveProperty(
            'verifiedSetupProofMaterials',
        );
    });
});
