import { describe, expect, it } from 'vitest';

import { hash512Hex, publicSetupApi } from './support.js';

type JsonRecord = Record<string, unknown>;
const expectedManifestHash = '1'.repeat(128);
const expectedRosterHash = '2'.repeat(128);
const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
} as const;

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
        proofFamily: transportCase.proofFamily,
        proofMaterials: [
            {
                objectType: transportCase.materialObjectType,
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
    proofMaterials: setupProofMaterialTransportCases.map((transportCase) => {
        const proofMaterialRoot = proofMaterialRootForCase(transportCase);

        return {
            objectType: 'VerifiedSetupProofMaterial',
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
            publicKeyShareMaterials: [
                {
                    objectType: 'SetupTransportedPublicKeyShareMaterial',
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
            componentMaterials: [
                {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterial',
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
            materialEncoding:
                'sealed-lattice-public-evaluation-key-material-binary-v1',
            publicEvaluationKeyMaterials: [
                {
                    objectType: 'SetupTransportedPublicEvaluationKeyMaterial',
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
        const verification = await publicSetupApi.verifySetupPackage({
            setupPackage: {
                objectType: 'BgvPassiveSetupPackage',
            },
            ...setupVerificationBindings,
        });

        expect(verification).toMatchObject({
            isValid: false,
            operation: 'verifyCollectiveBgvSetupPackage',
        });
        expect(verification.acceptedSetupHandoff).toBeUndefined();
    });

    it('creates setup verification input for every verified proof material family', () => {
        const setupPackage = {
            objectType: 'SetupPackage',
            setupPackageHash: hash512Hex(
                'sealed-lattice/test/setup-package-hash',
                [new Uint8Array([5, 6, 7, 8])],
            ),
        };
        const publicCompanions = transportedPublicCompanions();
        const verificationInput =
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                ...setupVerificationBindings,
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
                verifiedSetupProofMaterials: verifiedSetupProofMaterials(),
            });

        expect(verificationInput.setupPackage).toBe(setupPackage);
        expect(verificationInput.expectedManifestHash).toBe(
            expectedManifestHash,
        );
        expect(verificationInput.expectedRosterHash).toBe(expectedRosterHash);
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
        }
    });

    it('keeps setup proof chunks when no verified handle binds that proof root', () => {
        const setupPackage = {
            objectType: 'SetupPackage',
            setupPackageHash: hash512Hex(
                'sealed-lattice/test/setup-package-hash-with-unverified-proof-material',
                [new Uint8Array([9, 10, 11, 12])],
            ),
        };
        const verificationInput =
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                ...setupVerificationBindings,
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
                            [
                                new TextEncoder().encode(
                                    transportCase.proofFamily,
                                ),
                            ],
                        ),
                ),
            });

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

    it('requires expected manifest and roster hashes for public setup verification input construction', () => {
        const setupPackage = {
            objectType: 'SetupPackage',
            setupPackageHash: hash512Hex(
                'sealed-lattice/test/setup-package-hash-missing-bindings',
                [new Uint8Array([13, 14, 15, 16])],
            ),
        };

        expect(() =>
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                expectedManifestHash,
            }),
        ).toThrow(/expectedRosterHash/u);
        expect(() =>
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                expectedManifestHash: 'not-a-protocol-hash',
                expectedRosterHash,
            }),
        ).toThrow(/expectedManifestHash/u);
    });
});
