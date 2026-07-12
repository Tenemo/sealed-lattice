import { describe, expect, it } from 'vitest';

import { hash512Hex, publicSetupApi } from './support.js';

import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';

type JsonRecord = Record<string, unknown>;
const expectedManifestHash = '1'.repeat(128);
const expectedRosterHash = '2'.repeat(128);
const setupVerificationBindings = {
    expectedManifestHash,
    expectedRosterHash,
} as const;
const canonicalDescriptorBytes = canonicalStreamDescriptorFixture(4);
type SetupProofMaterialTransportFieldName =
    | 'transportedPublicKeyShareProofMaterial'
    | 'transportedEvaluationKeyShareProofMaterial'
    | 'transportedVssShareLinkageProofMaterial'
    | 'transportedSameSecretBridgeProofMaterial';

type SetupProofMaterialTransportCase = Readonly<{
    readonly fieldName: SetupProofMaterialTransportFieldName;
    readonly materialSetObjectType:
        | 'SetupTransportedPublicKeyShareProofMaterialSet'
        | 'SetupTransportedEvaluationKeyShareProofMaterialSet'
        | 'SetupTransportedVssShareLinkageProofMaterialSet'
        | 'SetupTransportedSameSecretBridgeProofMaterialSet';
    readonly materialObjectType:
        | 'SetupTransportedPublicKeyShareProofMaterial'
        | 'SetupTransportedEvaluationKeyShareProofMaterial'
        | 'SetupTransportedVssShareLinkageProofMaterial'
        | 'SetupTransportedSameSecretBridgeProofMaterial';
    readonly proofFamily:
        | 'public-key-share'
        | 'trustee-evaluation-key'
        | 'vss-share-linkage'
        | 'same-secret-bridge';
}>;

const setupProofMaterialTransportCases = [
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
    {
        fieldName: 'transportedVssShareLinkageProofMaterial',
        materialSetObjectType:
            'SetupTransportedVssShareLinkageProofMaterialSet',
        materialObjectType: 'SetupTransportedVssShareLinkageProofMaterial',
        proofFamily: 'vss-share-linkage',
    },
    {
        fieldName: 'transportedSameSecretBridgeProofMaterial',
        materialSetObjectType:
            'SetupTransportedSameSecretBridgeProofMaterialSet',
        materialObjectType: 'SetupTransportedSameSecretBridgeProofMaterial',
        proofFamily: 'same-secret-bridge',
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
                descriptorBytes: canonicalDescriptorBytes.slice(),
            },
        ],
    };
};

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
            objectType: 'SetupTransportedPublicKeyShareMaterial',
            publicKeyShareMaterialSetRoot: publicKeyShareMaterialRoot,
            descriptorBytes: canonicalDescriptorBytes.slice(),
        },
        transportedEvaluationKeyShareComponentMaterial: {
            objectType:
                'SetupTransportedEvaluationKeyShareComponentMaterialSet',
            componentMaterials: [
                {
                    objectType:
                        'SetupTransportedEvaluationKeyShareComponentMaterial',
                    keySwitchComponentMaterialRoot: evaluationKeyComponentRoot,
                    descriptorBytes: canonicalDescriptorBytes.slice(),
                },
            ],
        },
        transportedPublicEvaluationKeyMaterial: {
            objectType: 'SetupTransportedPublicEvaluationKeyMaterialSet',
            materialEncoding:
                'sealed-lattice-public-evaluation-key-material-binary',
            publicEvaluationKeyMaterials: [
                {
                    objectType: 'SetupTransportedPublicEvaluationKeyMaterial',
                    publicEvaluationKeyMaterialRoot,
                    descriptorBytes: canonicalDescriptorBytes.slice(),
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
        });
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
        const transportedPublicKeyShareProofMaterial =
            transportedSetupProofMaterialSet(
                setupProofMaterialTransportCases[0],
            );
        const transportedEvaluationKeyShareProofMaterial =
            transportedSetupProofMaterialSet(
                setupProofMaterialTransportCases[1],
            );
        const transportedVssShareLinkageProofMaterial =
            transportedSetupProofMaterialSet(
                setupProofMaterialTransportCases[2],
            );
        const transportedSameSecretBridgeProofMaterial =
            transportedSetupProofMaterialSet(
                setupProofMaterialTransportCases[3],
            );
        const publicKeyShareMaterialChunkSource = {
            publicKeyShareMaterialSetRoot:
                publicCompanions.transportedPublicKeyShareMaterial
                    .publicKeyShareMaterialSetRoot,
            pullChunk: (): Promise<ArrayBuffer> =>
                Promise.resolve(new ArrayBuffer(0)),
        };
        const verificationInput =
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                ...setupVerificationBindings,
                transportedPublicKeyShareProofMaterial,
                transportedEvaluationKeyShareProofMaterial,
                transportedVssShareLinkageProofMaterial,
                transportedSameSecretBridgeProofMaterial,
                publicKeyShareMaterialChunkSource,
                ...publicCompanions,
            });

        expect(verificationInput.setupPackage).toBe(setupPackage);
        expect(verificationInput.expectedManifestHash).toBe(
            expectedManifestHash,
        );
        expect(verificationInput.expectedRosterHash).toBe(expectedRosterHash);
        expect(verificationInput.transportedPublicKeyShareMaterial).toBe(
            publicCompanions.transportedPublicKeyShareMaterial,
        );
        expect(verificationInput.publicKeyShareMaterialChunkSource).toBe(
            publicKeyShareMaterialChunkSource,
        );
        expect(verificationInput.transportedPublicKeyShareProofMaterial).toBe(
            transportedPublicKeyShareProofMaterial,
        );
        expect(
            verificationInput.transportedEvaluationKeyShareProofMaterial,
        ).toBe(transportedEvaluationKeyShareProofMaterial);
        expect(verificationInput.transportedVssShareLinkageProofMaterial).toBe(
            transportedVssShareLinkageProofMaterial,
        );
        expect(verificationInput.transportedSameSecretBridgeProofMaterial).toBe(
            transportedSameSecretBridgeProofMaterial,
        );
        expect(
            verificationInput.transportedEvaluationKeyShareComponentMaterial,
        ).toBe(publicCompanions.transportedEvaluationKeyShareComponentMaterial);
        expect(verificationInput.transportedPublicEvaluationKeyMaterial).toBe(
            publicCompanions.transportedPublicEvaluationKeyMaterial,
        );
    });

    it('rejects malformed canonical descriptors during verification-input construction', () => {
        const setupPackage = {
            objectType: 'SetupPackage',
            setupPackageHash: hash512Hex(
                'sealed-lattice/test/setup-package-hash-with-malformed-proof-material',
                [new Uint8Array([9, 10, 11, 12])],
            ),
        };
        const malformedProofMaterial = transportedSetupProofMaterialSet(
            setupProofMaterialTransportCases[0],
        );
        const proofMaterials =
            malformedProofMaterial.proofMaterials as JsonRecord[];
        proofMaterials[0].descriptorBytes = canonicalDescriptorBytes.subarray(
            0,
            canonicalDescriptorBytes.byteLength - 1,
        );

        expect(() =>
            publicSetupApi.createSetupPackageVerificationInput({
                setupPackage,
                ...setupVerificationBindings,
                transportedPublicKeyShareProofMaterial: malformedProofMaterial,
            }),
        ).toThrow(
            'transportedPublicKeyShareProofMaterial.proofMaterials.0.descriptorBytes.fullObjectHash is truncated',
        );
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
