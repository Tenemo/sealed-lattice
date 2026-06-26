import {
    deriveProtocolHash,
    hash512Hex,
    setupProofMaterialFullObjectHashHex,
} from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    compactVssCommitmentBinaryFormat,
    compactVssCommitmentProfileId,
    verifyCompactVssCoefficientCommitmentSet,
    type CompactVssCoefficientCommitmentSet,
} from './compact-vss-commitments.js';
import {
    setupProofChunkManifestRoot,
    setupProofMaterialChunkHash,
    setupProofTransportChunkSizeBytes,
    type TransportedSetupProofMaterialSet,
} from './setup-proof-material-transport.js';
import {
    setupCommitmentProfileId,
    type SetupPackageVssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentRecord,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeCoefficientCommitmentRecord,
} from './vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

export const setupProofProfileId = 'SealedLattice-SetupProof-v1';
export const sameSecretProofFamily = 'same-secret-linkage-anchor';
const sameSecretAnchorProofBytesHashDomain =
    'sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1';
export const sameSecretRelation =
    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs';
export const sameSecretAnchorArgument =
    'one keyless succinct linkage proof per trustee; secret-dependent families bind the anchor root and open the same commitment values';
export const sameSecretBoundProofFamilies = [
    'vss-constant-relation',
    'public-key-share',
    'relinearization-key-share',
    'galois-key-share',
] as const;

export const compactVssSameSecretBridgeRelation =
    'target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof';
export const compactVssSameSecretBridgeProofFamily =
    'compact-same-secret-bridge';
const compactVssSameSecretBridgeProofBytesHashDomain =
    'sealed-lattice/setup/compact-same-secret-bridge/proof-bytes-v1';
export const compactVssSameSecretBridgeIntegerSupport =
    'the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb';
export const compactVssSameSecretBridgeSignedRepresentativeConvention =
    'coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime';
export const compactVssSameSecretBridgeTargetBasisLimbOrder =
    'target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime';

export type SameSecretConstantCoefficientCommitmentRoot = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: 0;
    readonly commitmentRoot: ProtocolHash;
}>;

export type TrusteeSecretCommitmentRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly trusteeSecretCommitmentRoot: ProtocolHash;
}>;

export type SameSecretConsistencyStatementRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretConsistencyStatement';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly vssSourceTrusteeCommitmentRoot: ProtocolHash;
        readonly constantCoefficientCommitmentRoots: readonly SameSecretConstantCoefficientCommitmentRoot[];
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly boundSecretDependentProofFamilies: typeof sameSecretBoundProofFamilies;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly sameSecretRelation: typeof sameSecretRelation;
        readonly sameSecretStatementRoot: ProtocolHash;
    }
>;

export type SameSecretConsistencyStatementSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretConsistencyStatementSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly vssCoefficientCommitmentRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoots: readonly TrusteeSecretCommitmentRootReference[];
        readonly statementRecords: readonly SameSecretConsistencyStatementRecord[];
        readonly sameSecretConsistencyRoot: ProtocolHash;
    }
>;

export type SameSecretEmbeddedProofBytes = Readonly<{
    readonly proofBytesHex: string;
}>;

export type SameSecretTransportedProofBytes = Readonly<{
    readonly proofBytesEncoding: 'binary-chunked-proof-bytes';
    readonly proofMaterialRoot: ProtocolHash;
    readonly proofChunkSizeBytes: number;
    readonly proofChunkCount: number;
    readonly proofTotalByteLength: number;
    readonly proofFullObjectHash: ProtocolHash;
    readonly proofChunkRoot: ProtocolHash;
    readonly proofChunkHashes: readonly ProtocolHash[];
}>;

export type SameSecretProofByteMaterial =
    | SameSecretEmbeddedProofBytes
    | SameSecretTransportedProofBytes;

export type SameSecretProofMaterial = Readonly<
    SameSecretProofByteMaterial & {
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly statementHash: ProtocolHash;
        readonly proofSizeBytes: number;
        readonly proofBytesHash: ProtocolHash;
    }
>;

export type SameSecretProofRecord = Readonly<
    JsonRecord &
        SameSecretProofByteMaterial & {
            readonly objectType: 'SameSecretProof';
            readonly objectVersion: 1;
            readonly setupProfileId: 'CollectiveBgvSetup-v1';
            readonly commitmentProfileId: typeof setupCommitmentProfileId;
            readonly setupProofProfileId: typeof setupProofProfileId;
            readonly proofFamily: typeof sameSecretProofFamily;
            readonly trusteeIdentity: string;
            readonly trusteeRosterPosition: number;
            readonly ringDegree: number;
            readonly sameSecretStatementRoot: ProtocolHash;
            readonly trusteeSecretCommitmentRoot: ProtocolHash;
            readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
            readonly statementHash: ProtocolHash;
            readonly proofSizeBytes: number;
            readonly proofBytesHash: ProtocolHash;
            readonly sameSecretProofRoot: ProtocolHash;
        }
>;

export type SameSecretProofRootReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly sameSecretProofRoot: ProtocolHash;
}>;

export type SameSecretProofSet = Readonly<
    JsonRecord & {
        readonly objectType: 'SameSecretProofSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly proofAccountingHash: ProtocolHash;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly vssCoefficientCommitmentMaterialRoot: ProtocolHash;
        readonly sameSecretProofRoots: readonly SameSecretProofRootReference[];
        readonly proofRecords: readonly SameSecretProofRecord[];
        readonly sameSecretProofSetRoot: ProtocolHash;
    }
>;

export type CompactVssSameSecretBridgeTargetConstantCommitmentRoot = Readonly<{
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: 0;
    readonly coefficientCommitmentRoot: ProtocolHash;
}>;

export type CompactVssSameSecretBridgeStatementRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSameSecretBridgeStatement';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly compactCommitmentProfileId: typeof compactVssCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly targetBasisHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
        readonly sameSecretStatementRoot: ProtocolHash;
        readonly sameSecretProofRoot: ProtocolHash;
        readonly trusteeSecretCommitmentRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly dataBasisRelation: typeof sameSecretRelation;
        readonly integerSupport: typeof compactVssSameSecretBridgeIntegerSupport;
        readonly signedRepresentativeConvention: typeof compactVssSameSecretBridgeSignedRepresentativeConvention;
        readonly compactCommitmentEncoding: typeof compactVssCommitmentBinaryFormat;
        readonly targetBasisLimbOrder: typeof compactVssSameSecretBridgeTargetBasisLimbOrder;
        readonly targetConstantCoefficientCommitmentRoots: readonly CompactVssSameSecretBridgeTargetConstantCommitmentRoot[];
        readonly relation: typeof compactVssSameSecretBridgeRelation;
        readonly compactSameSecretBridgeStatementRoot: ProtocolHash;
    }
>;

export type CompactVssSameSecretBridgeStatementSet = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSameSecretBridgeStatementSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly compactCommitmentProfileId: typeof compactVssCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof sameSecretProofFamily;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly targetBasisHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly participantCount: number;
        readonly targetRnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly compactCoefficientCommitmentRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly integerSupport: typeof compactVssSameSecretBridgeIntegerSupport;
        readonly signedRepresentativeConvention: typeof compactVssSameSecretBridgeSignedRepresentativeConvention;
        readonly compactCommitmentEncoding: typeof compactVssCommitmentBinaryFormat;
        readonly targetBasisLimbOrder: typeof compactVssSameSecretBridgeTargetBasisLimbOrder;
        readonly statementRecords: readonly CompactVssSameSecretBridgeStatementRecord[];
        readonly compactSameSecretBridgeStatementSetRoot: ProtocolHash;
    }
>;

export type CompactVssSameSecretBridgeProofRecordInput = Readonly<{
    readonly compactSameSecretBridgeStatementRoot: ProtocolHash;
    readonly proofStatementHash: ProtocolHash;
    readonly proofStatement: Readonly<
        JsonRecord & {
            readonly proofStatementHash: ProtocolHash;
        }
    >;
    readonly proofBytesHex: string;
}>;

export type CompactVssSameSecretBridgeProofRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSameSecretBridgeProofRecord';
        readonly objectVersion: 1;
        readonly proofFamily: typeof compactVssSameSecretBridgeProofFamily;
        readonly compactSameSecretBridgeStatementRoot: ProtocolHash;
        readonly proofStatementHash: ProtocolHash;
        readonly proofByteLength: number;
        readonly proofBytesHash: ProtocolHash;
        readonly proofBytesHex: string;
        readonly proofRecordRoot: ProtocolHash;
    }
>;

export type CompactVssSameSecretBridgeProofMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSameSecretBridgeProofMaterialSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly compactCommitmentProfileId: typeof compactVssCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof compactVssSameSecretBridgeProofFamily;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly targetBasisHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly participantCount: number;
        readonly targetRnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly compactCoefficientCommitmentRoot: ProtocolHash;
        readonly sameSecretConsistencyRoot: ProtocolHash;
        readonly sameSecretProofSetRoot: ProtocolHash;
        readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
        readonly compactSameSecretBridgeStatementSetRoot: ProtocolHash;
        readonly proofRecords: readonly CompactVssSameSecretBridgeProofRecord[];
        readonly proofStatements: readonly Readonly<
            JsonRecord & {
                readonly proofStatementHash: ProtocolHash;
            }
        >[];
        readonly proofMaterialSetRoot: ProtocolHash;
    }
>;

export type SameSecretConsistencyStatementSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly thresholdDegree: number;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
};

export type SameSecretProofSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly qSharePrimes: readonly number[];
    readonly participantCount: number;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly vssCoefficientCommitmentMaterial: SetupPackageVssCoefficientCommitmentMaterialSet;
    readonly proofAccountingHash: ProtocolHash;
    readonly proofMaterials: readonly SameSecretProofMaterial[];
};

export type CompactVssSameSecretBridgeStatementSetInput = {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly targetBasisHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly compactCoefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
};

export type TransportedSameSecretProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedSameSecretProofMaterialSet';
        readonly proofFamily: typeof sameSecretProofFamily;
    }
>;

export type BinaryChunkedSameSecretProofMaterialTransport = Readonly<{
    readonly proofMaterials: readonly SameSecretProofMaterial[];
    readonly transportedSameSecretProofMaterial: TransportedSameSecretProofMaterialSet;
}>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const lowercaseHexPattern = /^(?:[0-9a-f]{2})*$/u;
const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertLowercaseHexBytes = (value: string, fieldName: string): void => {
    if (!lowercaseHexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const assertExactString = (
    value: string,
    fieldName: string,
    expectedValue: string,
): void => {
    if (value !== expectedValue) {
        throw new TypeError(`${fieldName} is not supported.`);
    }
};

const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    assertLowercaseHexBytes(hex, fieldName);
    const bytes = new Uint8Array(hex.length / 2);
    for (let offset = 0; offset < hex.length; offset += 2) {
        bytes[offset / 2] = Number.parseInt(hex.slice(offset, offset + 2), 16);
    }

    return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const hasSameSecretTransportReference = (record: JsonRecord): boolean =>
    [
        'proofMaterialRoot',
        'proofChunkSizeBytes',
        'proofChunkCount',
        'proofTotalByteLength',
        'proofFullObjectHash',
        'proofChunkRoot',
        'proofChunkHashes',
    ].some((fieldName) => record[fieldName] !== undefined);

type SameSecretProofTransportBinding = Readonly<{
    fullObjectHash: ProtocolHash;
    chunkHashes: readonly ProtocolHash[];
    chunkRoot: ProtocolHash;
    totalByteLength: number;
    proofBytesHash: ProtocolHash;
}>;

const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<
    CollectiveBgvSetupContext,
    (typeof setupContextFieldNames)[number]
> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    valueName: string,
): void => {
    for (const fieldName of setupContextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${valueName}.${fieldName} must match setupContext.`,
            );
        }
    }
};

const validateInput = (input: SameSecretConsistencyStatementSetInput): void => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertContextMatches(
        input.setupContext,
        input.vssCoefficientCommitments,
        'vssCoefficientCommitments',
    );
    assertProtocolHash(
        input.vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        'vssCoefficientCommitments.vssCoefficientCommitmentRoot',
    );
};

const validateSameSecretProofMaterial = (
    material: SameSecretProofMaterial,
    fieldName: string,
): void => {
    if (material.setupProofProfileId !== setupProofProfileId) {
        throw new Error(
            `${fieldName}.setupProofProfileId must match setup proof profile.`,
        );
    }
    if (material.proofFamily !== sameSecretProofFamily) {
        throw new Error(
            `${fieldName}.proofFamily must be the same-secret linkage anchor family.`,
        );
    }
    assertNonEmptyString(
        material.trusteeIdentity,
        `${fieldName}.trusteeIdentity`,
    );
    assertNonNegativeSafeInteger(
        material.trusteeRosterPosition,
        `${fieldName}.trusteeRosterPosition`,
    );
    assertProtocolHash(material.statementHash, `${fieldName}.statementHash`);
    assertPositiveSafeInteger(
        material.proofSizeBytes,
        `${fieldName}.proofSizeBytes`,
    );
    assertProtocolHash(material.proofBytesHash, `${fieldName}.proofBytesHash`);
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        const materialRecord = material as JsonRecord;
        if (
            materialRecord.proofBytesEncoding !== undefined ||
            hasSameSecretTransportReference(materialRecord)
        ) {
            throw new Error(
                `${fieldName} must not mix proofBytesHex with transported proof material.`,
            );
        }
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(`${fieldName}.proofBytesHex must be a string.`);
        }
        assertLowercaseHexBytes(proofBytesHex, `${fieldName}.proofBytesHex`);
        if (proofBytesHex.length / 2 !== material.proofSizeBytes) {
            throw new Error(
                `${fieldName}.proofBytesHex must match proofSizeBytes.`,
            );
        }
        const proofBytes = Buffer.from(proofBytesHex, 'hex');
        const expectedProofBytesHash = hash512Hex(
            sameSecretAnchorProofBytesHashDomain,
            [proofBytes],
        );
        if (material.proofBytesHash !== expectedProofBytesHash) {
            throw new Error(
                `${fieldName}.proofBytesHash must match proofBytesHex.`,
            );
        }
    } else {
        const transportedMaterial = material as SameSecretTransportedProofBytes;
        if (
            transportedMaterial.proofBytesEncoding !==
            'binary-chunked-proof-bytes'
        ) {
            throw new TypeError(
                `${fieldName}.proofBytesEncoding must be binary-chunked-proof-bytes.`,
            );
        }
        assertProtocolHash(
            transportedMaterial.proofMaterialRoot,
            `${fieldName}.proofMaterialRoot`,
        );
        assertPositiveSafeInteger(
            transportedMaterial.proofChunkSizeBytes,
            `${fieldName}.proofChunkSizeBytes`,
        );
        assertPositiveSafeInteger(
            transportedMaterial.proofChunkCount,
            `${fieldName}.proofChunkCount`,
        );
        assertPositiveSafeInteger(
            transportedMaterial.proofTotalByteLength,
            `${fieldName}.proofTotalByteLength`,
        );
        if (
            transportedMaterial.proofTotalByteLength !== material.proofSizeBytes
        ) {
            throw new Error(
                `${fieldName}.proofTotalByteLength must match proofSizeBytes.`,
            );
        }
        assertProtocolHash(
            transportedMaterial.proofFullObjectHash,
            `${fieldName}.proofFullObjectHash`,
        );
        assertProtocolHash(
            transportedMaterial.proofChunkRoot,
            `${fieldName}.proofChunkRoot`,
        );
        transportedMaterial.proofChunkHashes.forEach(
            (proofChunkHash, chunkIndex) =>
                assertProtocolHash(
                    proofChunkHash,
                    `${fieldName}.proofChunkHashes.${String(chunkIndex)}`,
                ),
        );
        if (
            transportedMaterial.proofChunkHashes.length !==
            transportedMaterial.proofChunkCount
        ) {
            throw new Error(
                `${fieldName}.proofChunkHashes must match proofChunkCount.`,
            );
        }
    }
};

const assertTransportedSameSecretProofMaterialSetHeader = (
    materialSet: TransportedSameSecretProofMaterialSet,
): void => {
    assertExactString(
        materialSet.objectType,
        'transportedSameSecretProofMaterial.objectType',
        'SetupTransportedSameSecretProofMaterialSet',
    );
    if (materialSet.objectVersion !== 1) {
        throw new TypeError(
            'transportedSameSecretProofMaterial.objectVersion is not supported.',
        );
    }
    assertExactString(
        materialSet.setupProfileId,
        'transportedSameSecretProofMaterial.setupProfileId',
        'CollectiveBgvSetup-v1',
    );
    assertExactString(
        materialSet.setupProofProfileId,
        'transportedSameSecretProofMaterial.setupProofProfileId',
        setupProofProfileId,
    );
    assertExactString(
        materialSet.proofFamily,
        'transportedSameSecretProofMaterial.proofFamily',
        sameSecretProofFamily,
    );
    if (!Array.isArray(materialSet.proofMaterials)) {
        throw new TypeError(
            'transportedSameSecretProofMaterial.proofMaterials must be an array.',
        );
    }
};

const transportedSameSecretProofChunks = (
    material: JsonRecord,
    materialIndex: number,
): Uint8Array[] => {
    if (material.chunkSizeBytes !== setupProofTransportChunkSizeBytes) {
        throw new Error(
            'transported same-secret proof material chunkSizeBytes must match the setup proof transport profile.',
        );
    }
    assertPositiveSafeInteger(
        material.chunkCount as number,
        `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.chunkCount`,
    );
    const chunkRecords = material.chunks;
    if (!Array.isArray(chunkRecords)) {
        throw new TypeError(
            `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.chunks must be an array.`,
        );
    }
    if (chunkRecords.length !== material.chunkCount) {
        throw new Error(
            'transported same-secret proof material chunks must match chunkCount.',
        );
    }

    return chunkRecords.map((chunkRecord, expectedChunkIndex) => {
        if (
            typeof chunkRecord !== 'object' ||
            chunkRecord === null ||
            Array.isArray(chunkRecord)
        ) {
            throw new TypeError(
                `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.chunks.${String(expectedChunkIndex)} must be an object.`,
            );
        }
        const chunk = chunkRecord as JsonRecord;
        if (chunk.chunkIndex !== expectedChunkIndex) {
            throw new Error(
                'transported same-secret proof material chunks must be supplied in ascending chunk-index order.',
            );
        }
        if (typeof chunk.bytesHex !== 'string') {
            throw new TypeError(
                `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.chunks.${String(expectedChunkIndex)}.bytesHex must be a string.`,
            );
        }
        const chunkBytes = bytesFromHex(
            chunk.bytesHex,
            `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.chunks.${String(expectedChunkIndex)}.bytesHex`,
        );
        if (
            chunkBytes.byteLength === 0 ||
            chunkBytes.byteLength > setupProofTransportChunkSizeBytes ||
            (expectedChunkIndex + 1 < chunkRecords.length &&
                chunkBytes.byteLength !== setupProofTransportChunkSizeBytes)
        ) {
            throw new Error(
                'transported same-secret proof material chunks must match the setup proof transport profile.',
            );
        }

        return chunkBytes;
    });
};

const assertTransportedSameSecretProofMaterialHashes = (
    material: JsonRecord,
    binding: SameSecretProofTransportBinding,
    materialIndex: number,
): void => {
    if (material.totalByteLength !== binding.totalByteLength) {
        throw new Error(
            'transported same-secret proof material totalByteLength must match supplied chunks.',
        );
    }
    if (material.fullObjectHash !== binding.fullObjectHash) {
        throw new Error(
            'transported same-secret proof material fullObjectHash must match supplied chunks.',
        );
    }
    if (material.chunkRoot !== binding.chunkRoot) {
        throw new Error(
            'transported same-secret proof material chunkRoot must match supplied chunks.',
        );
    }
    const chunkHashes = material.chunkHashes;
    if (!Array.isArray(chunkHashes)) {
        throw new TypeError(
            `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.chunkHashes must be an array.`,
        );
    }
    if (chunkHashes.length !== binding.chunkHashes.length) {
        throw new Error(
            'transported same-secret proof material chunkHashes must match supplied chunks.',
        );
    }
    chunkHashes.forEach((chunkHash, chunkIndex) => {
        assertProtocolHash(
            chunkHash as string,
            `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.chunkHashes.${String(chunkIndex)}`,
        );
        if (chunkHash !== binding.chunkHashes[chunkIndex]) {
            throw new Error(
                'transported same-secret proof material chunkHashes must match supplied chunks.',
            );
        }
    });
};

const sameSecretAnchorProofMaterialRoot = (
    proofRecord: SameSecretProofRecord,
    binding: SameSecretProofTransportBinding,
): ProtocolHash =>
    deriveProtocolHash('SameSecretLinkageAnchorProofMaterialRoot', {
        objectType: 'SameSecretLinkageAnchorProofMaterialReference',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        trusteeIdentity: proofRecord.trusteeIdentity,
        trusteeRosterPosition: proofRecord.trusteeRosterPosition,
        statementHash: proofRecord.statementHash,
        proofSizeBytes: proofRecord.proofSizeBytes,
        proofBytesHash: proofRecord.proofBytesHash,
        chunkSizeBytes: setupProofTransportChunkSizeBytes,
        chunkCount: binding.chunkHashes.length,
        totalByteLength: binding.totalByteLength,
        fullObjectHash: binding.fullObjectHash,
        chunkRoot: binding.chunkRoot,
        chunkHashes: binding.chunkHashes,
    });

const transportedSameSecretProofMaterialBinding = (
    proofRecord: SameSecretProofRecord,
    transportedMaterialSet: TransportedSameSecretProofMaterialSet | undefined,
): SameSecretProofTransportBinding => {
    const transportedProofRecord = proofRecord as SameSecretProofRecord &
        SameSecretTransportedProofBytes;
    if (transportedMaterialSet === undefined) {
        throw new Error(
            'transportedSameSecretProofMaterial is required by transported same-secret proof records.',
        );
    }
    assertTransportedSameSecretProofMaterialSetHeader(transportedMaterialSet);
    const matchingMaterials = transportedMaterialSet.proofMaterials.filter(
        (material) =>
            material.proofMaterialRoot ===
            transportedProofRecord.proofMaterialRoot,
    );
    if (matchingMaterials.length !== 1) {
        throw new Error(
            'transportedSameSecretProofMaterial must contain exactly one proofMaterialRoot entry for each transported proof record.',
        );
    }
    const material = matchingMaterials[0] as JsonRecord | undefined;
    if (material === undefined) {
        throw new Error(
            'transportedSameSecretProofMaterial is missing the requested proofMaterialRoot.',
        );
    }
    const materialIndex =
        transportedMaterialSet.proofMaterials.indexOf(material);
    assertExactString(
        material.objectType as string,
        `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.objectType`,
        'SetupTransportedSameSecretProofMaterial',
    );
    if (material.objectVersion !== 1) {
        throw new TypeError(
            `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.objectVersion is not supported.`,
        );
    }
    assertExactString(
        material.setupProfileId as string,
        `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.setupProfileId`,
        'CollectiveBgvSetup-v1',
    );
    assertExactString(
        material.setupProofProfileId as string,
        `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.setupProofProfileId`,
        setupProofProfileId,
    );
    assertExactString(
        material.proofFamily as string,
        `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.proofFamily`,
        sameSecretProofFamily,
    );
    assertProtocolHash(
        material.proofMaterialRoot as string,
        `transportedSameSecretProofMaterial.proofMaterials.${String(materialIndex)}.proofMaterialRoot`,
    );

    const chunks = transportedSameSecretProofChunks(material, materialIndex);
    const totalByteLength = chunks.reduce(
        (byteLength, chunk) => byteLength + chunk.byteLength,
        0,
    );
    const fullObjectHash = setupProofMaterialFullObjectHashHex(
        sameSecretProofFamily,
        totalByteLength,
        chunks,
    );
    const chunkHashes = chunks.map((chunk, chunkIndex) =>
        setupProofMaterialChunkHash(
            sameSecretProofFamily,
            fullObjectHash,
            chunkIndex,
            chunk,
        ),
    );
    const binding = {
        fullObjectHash,
        chunkHashes,
        chunkRoot: setupProofChunkManifestRoot(
            sameSecretProofFamily,
            chunkHashes,
            fullObjectHash,
            totalByteLength,
        ),
        totalByteLength,
        proofBytesHash: hash512Hex(
            sameSecretAnchorProofBytesHashDomain,
            chunks,
        ),
    } satisfies SameSecretProofTransportBinding;
    assertTransportedSameSecretProofMaterialHashes(
        material,
        binding,
        materialIndex,
    );

    return binding;
};

const assertSameSecretProofRecordMatchesTransport = (
    proofRecord: SameSecretProofRecord,
    transportedMaterialSet: TransportedSameSecretProofMaterialSet | undefined,
): void => {
    const transportedProofRecord = proofRecord as SameSecretProofRecord &
        SameSecretTransportedProofBytes;
    const binding = transportedSameSecretProofMaterialBinding(
        proofRecord,
        transportedMaterialSet,
    );
    if (proofRecord.proofSizeBytes !== binding.totalByteLength) {
        throw new Error(
            'same-secret proof record proofSizeBytes must match transported proof byte length.',
        );
    }
    if (
        transportedProofRecord.proofTotalByteLength !== binding.totalByteLength
    ) {
        throw new Error(
            'same-secret proof record proofTotalByteLength must match transported proof byte length.',
        );
    }
    if (proofRecord.proofBytesHash !== binding.proofBytesHash) {
        throw new Error(
            'same-secret proof record proofBytesHash must match transported proof bytes.',
        );
    }
    if (
        transportedProofRecord.proofChunkSizeBytes !==
            setupProofTransportChunkSizeBytes ||
        transportedProofRecord.proofChunkCount !== binding.chunkHashes.length ||
        transportedProofRecord.proofFullObjectHash !== binding.fullObjectHash ||
        transportedProofRecord.proofChunkRoot !== binding.chunkRoot ||
        transportedProofRecord.proofChunkHashes.length !==
            binding.chunkHashes.length ||
        transportedProofRecord.proofChunkHashes.some(
            (chunkHash, chunkIndex) =>
                chunkHash !== binding.chunkHashes[chunkIndex],
        )
    ) {
        throw new Error(
            'same-secret proof transport reference must match transported proof material.',
        );
    }
    if (
        transportedProofRecord.proofMaterialRoot !==
        sameSecretAnchorProofMaterialRoot(proofRecord, binding)
    ) {
        throw new Error(
            'same-secret proof record proofMaterialRoot must match the canonical transported proof material reference.',
        );
    }
};

const validateProofSetInput = (input: SameSecretProofSetInput): void => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    if (input.qSharePrimes.length === 0) {
        throw new Error('qSharePrimes must contain at least one RNS prime.');
    }
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        );
    });
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertProtocolHash(
        input.sameSecretConsistency.sameSecretConsistencyRoot,
        'sameSecretConsistency.sameSecretConsistencyRoot',
    );
    assertProtocolHash(
        input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        'sameSecretConsistency.sameSecretProofFamilyBindingRoot',
    );
    assertProtocolHash(
        input.vssCoefficientCommitmentMaterial
            .vssCoefficientCommitmentMaterialRoot,
        'vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot',
    );
    if (
        input.vssCoefficientCommitmentMaterial.participantCount !==
            input.participantCount ||
        input.vssCoefficientCommitmentMaterial.rnsLimbCount !==
            input.qSharePrimes.length ||
        input.vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot !==
            input.sameSecretConsistency.vssCoefficientCommitmentRoot
    ) {
        throw new Error(
            'vssCoefficientCommitmentMaterial must match the same-secret statement set.',
        );
    }
    assertProtocolHash(input.proofAccountingHash, 'proofAccountingHash');
};

const sortedSourceTrusteeRecords = (
    input: SameSecretConsistencyStatementSetInput,
): VssSourceTrusteeCoefficientCommitmentRecord[] => {
    const sourceTrusteeRecords = [
        ...input.vssCoefficientCommitments.sourceTrusteeRecords,
    ].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );
    if (sourceTrusteeRecords.length !== input.participantCount) {
        throw new Error(
            'vssCoefficientCommitments.sourceTrusteeRecords must cover every participant.',
        );
    }
    sourceTrusteeRecords.forEach(
        (sourceTrusteeRecord, expectedRosterPosition) => {
            assertNonEmptyString(
                sourceTrusteeRecord.sourceTrusteeIdentity,
                'sourceTrusteeIdentity',
            );
            assertNonNegativeSafeInteger(
                sourceTrusteeRecord.sourceTrusteeRosterPosition,
                'sourceTrusteeRosterPosition',
            );
            if (
                sourceTrusteeRecord.sourceTrusteeRosterPosition !==
                expectedRosterPosition
            ) {
                throw new Error(
                    'vssCoefficientCommitments.sourceTrusteeRecords roster positions must be contiguous from zero.',
                );
            }
            assertContextMatches(
                input.setupContext,
                sourceTrusteeRecord,
                'sourceTrusteeRecord',
            );
            assertProtocolHash(
                sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
                'sourceTrusteeRecord.sourceTrusteeCommitmentRoot',
            );
        },
    );

    return sourceTrusteeRecords;
};

const constantCoefficientCommitmentRoots = (
    sourceTrusteeRecord: VssSourceTrusteeCoefficientCommitmentRecord,
    qSharePrimes: readonly number[],
): SameSecretConstantCoefficientCommitmentRoot[] =>
    qSharePrimes.map((rnsPrime, rnsLimbIndex) => {
        const coefficientRecord =
            sourceTrusteeRecord.coefficientCommitments.find(
                (candidateRecord: VssCoefficientCommitmentRecord) =>
                    candidateRecord.rnsLimbIndex === rnsLimbIndex &&
                    candidateRecord.rnsPrime === rnsPrime &&
                    candidateRecord.shamirCoefficientIndex === 0,
            );
        if (coefficientRecord === undefined) {
            throw new Error(
                'sourceTrusteeRecord.coefficientCommitments must include every constant coefficient commitment.',
            );
        }
        assertProtocolHash(
            coefficientRecord.commitmentRoot,
            'coefficientRecord.commitmentRoot',
        );

        return {
            rnsLimbIndex,
            rnsPrime,
            shamirCoefficientIndex: 0,
            commitmentRoot: coefficientRecord.commitmentRoot,
        };
    });

const trusteeSecretCommitmentPayload = (
    setupContext: CollectiveBgvSetupContext,
    sourceTrusteeRecord: VssSourceTrusteeCoefficientCommitmentRecord,
    constantRoots: readonly SameSecretConstantCoefficientCommitmentRoot[],
): JsonRecord => ({
    objectType: 'TrusteeSecretCommitment',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    commitmentProfileId: setupCommitmentProfileId,
    setupProofProfileId,
    ...contextFields(setupContext),
    trusteeIdentity: sourceTrusteeRecord.sourceTrusteeIdentity,
    trusteeRosterPosition: sourceTrusteeRecord.sourceTrusteeRosterPosition,
    vssSourceTrusteeCommitmentRoot:
        sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
    constantCoefficientCommitmentRoots: constantRoots,
});

const sameSecretProofFamilyBindingPayload = (): JsonRecord => ({
    objectType: 'SameSecretProofFamilyBinding',
    objectVersion: 1,
    setupProfileId: 'CollectiveBgvSetup-v1',
    setupProofProfileId,
    proofFamily: sameSecretProofFamily,
    sameSecretRelation,
    anchorArgument: sameSecretAnchorArgument,
    boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
});

const sameSecretProofFamilyBindingRoot = (): ProtocolHash =>
    deriveProtocolHash(
        'SameSecretProofFamilyBindingRoot',
        sameSecretProofFamilyBindingPayload(),
    );

const createStatementRecord = (
    setupContext: CollectiveBgvSetupContext,
    sourceTrusteeRecord: VssSourceTrusteeCoefficientCommitmentRecord,
    constantRoots: readonly SameSecretConstantCoefficientCommitmentRoot[],
): {
    readonly statementRecord: SameSecretConsistencyStatementRecord;
    readonly trusteeSecretCommitmentRootReference: TrusteeSecretCommitmentRootReference;
} => {
    const trusteeSecretCommitmentRoot = deriveProtocolHash(
        'TrusteeSecretCommitmentRoot',
        trusteeSecretCommitmentPayload(
            setupContext,
            sourceTrusteeRecord,
            constantRoots,
        ),
    );
    const proofFamilyBindingRoot = sameSecretProofFamilyBindingRoot();
    const statementRecordWithoutRoot = {
        objectType: 'SameSecretConsistencyStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: setupCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        ...contextFields(setupContext),
        trusteeIdentity: sourceTrusteeRecord.sourceTrusteeIdentity,
        trusteeRosterPosition: sourceTrusteeRecord.sourceTrusteeRosterPosition,
        vssSourceTrusteeCommitmentRoot:
            sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
        constantCoefficientCommitmentRoots: constantRoots,
        trusteeSecretCommitmentRoot,
        boundSecretDependentProofFamilies: sameSecretBoundProofFamilies,
        sameSecretProofFamilyBindingRoot: proofFamilyBindingRoot,
        sameSecretRelation,
    } as const satisfies Omit<
        SameSecretConsistencyStatementRecord,
        'sameSecretStatementRoot'
    >;
    const statementRecord = {
        ...statementRecordWithoutRoot,
        sameSecretStatementRoot: deriveProtocolHash(
            'SameSecretConsistencyRoot',
            statementRecordWithoutRoot,
        ),
    } satisfies SameSecretConsistencyStatementRecord;

    return {
        statementRecord,
        trusteeSecretCommitmentRootReference: {
            trusteeIdentity: sourceTrusteeRecord.sourceTrusteeIdentity,
            trusteeRosterPosition:
                sourceTrusteeRecord.sourceTrusteeRosterPosition,
            trusteeSecretCommitmentRoot,
        },
    };
};

export const createSameSecretConsistencyStatementSet = (
    input: SameSecretConsistencyStatementSetInput,
): SameSecretConsistencyStatementSet => {
    validateInput(input);
    const proofFamilyBindingRoot = sameSecretProofFamilyBindingRoot();
    const statementOutputs = sortedSourceTrusteeRecords(input).map(
        (sourceTrusteeRecord) =>
            createStatementRecord(
                input.setupContext,
                sourceTrusteeRecord,
                constantCoefficientCommitmentRoots(
                    sourceTrusteeRecord,
                    input.qSharePrimes,
                ),
            ),
    );
    const statementSetWithoutRoot = {
        objectType: 'SameSecretConsistencyStatementSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: setupCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        thresholdDegree: input.thresholdDegree,
        vssCoefficientCommitmentRoot:
            input.vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        sameSecretProofFamilyBindingRoot: proofFamilyBindingRoot,
        trusteeSecretCommitmentRoots: statementOutputs.map(
            (output) => output.trusteeSecretCommitmentRootReference,
        ),
        statementRecords: statementOutputs.map(
            (output) => output.statementRecord,
        ),
    } as const satisfies Omit<
        SameSecretConsistencyStatementSet,
        'sameSecretConsistencyRoot'
    >;

    return {
        ...statementSetWithoutRoot,
        sameSecretConsistencyRoot: deriveProtocolHash(
            'SameSecretConsistencyRoot',
            statementSetWithoutRoot,
        ),
    } satisfies SameSecretConsistencyStatementSet;
};

const sortedStatementRecordsForProofs = (
    input: Pick<
        SameSecretProofSetInput,
        'participantCount' | 'sameSecretConsistency'
    >,
): SameSecretConsistencyStatementRecord[] => {
    const statementRecords = [
        ...input.sameSecretConsistency.statementRecords,
    ].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (statementRecords.length !== input.participantCount) {
        throw new Error(
            'sameSecretConsistency.statementRecords must contain one statement per participant.',
        );
    }
    statementRecords.forEach((statementRecord, expectedRosterPosition) => {
        assertNonEmptyString(
            statementRecord.trusteeIdentity,
            'sameSecretConsistency.statementRecords.trusteeIdentity',
        );
        if (statementRecord.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretConsistency.statementRecords roster positions must be contiguous from zero.',
            );
        }
        assertProtocolHash(
            statementRecord.sameSecretStatementRoot,
            'sameSecretConsistency.statementRecords.sameSecretStatementRoot',
        );
        assertProtocolHash(
            statementRecord.trusteeSecretCommitmentRoot,
            'sameSecretConsistency.statementRecords.trusteeSecretCommitmentRoot',
        );
        assertProtocolHash(
            statementRecord.sameSecretProofFamilyBindingRoot,
            'sameSecretConsistency.statementRecords.sameSecretProofFamilyBindingRoot',
        );
    });

    return statementRecords;
};

const sortedSameSecretProofMaterials = (
    input: Pick<SameSecretProofSetInput, 'participantCount' | 'proofMaterials'>,
): SameSecretProofMaterial[] => {
    const proofMaterials = [...input.proofMaterials].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    if (proofMaterials.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofMaterials must contain one proof per participant.',
        );
    }
    proofMaterials.forEach((proofMaterial, expectedRosterPosition) => {
        validateSameSecretProofMaterial(
            proofMaterial,
            `sameSecretProofMaterials.${String(expectedRosterPosition)}`,
        );
        if (proofMaterial.trusteeRosterPosition !== expectedRosterPosition) {
            throw new Error(
                'sameSecretProofMaterials roster positions must be contiguous from zero.',
            );
        }
    });

    return proofMaterials;
};

const sameSecretProofByteMaterial = (
    material: SameSecretProofMaterial,
): SameSecretProofByteMaterial => {
    const proofBytesHex = (material as JsonRecord).proofBytesHex;
    if (proofBytesHex !== undefined) {
        if (typeof proofBytesHex !== 'string') {
            throw new TypeError(
                'sameSecretProofMaterial.proofBytesHex must be a string.',
            );
        }
        return {
            proofBytesHex,
        };
    }

    const transportedMaterial = material as SameSecretTransportedProofBytes;

    return {
        proofBytesEncoding: transportedMaterial.proofBytesEncoding,
        proofMaterialRoot: transportedMaterial.proofMaterialRoot,
        proofChunkSizeBytes: transportedMaterial.proofChunkSizeBytes,
        proofChunkCount: transportedMaterial.proofChunkCount,
        proofTotalByteLength: transportedMaterial.proofTotalByteLength,
        proofFullObjectHash: transportedMaterial.proofFullObjectHash,
        proofChunkRoot: transportedMaterial.proofChunkRoot,
        proofChunkHashes: transportedMaterial.proofChunkHashes,
    };
};

export const createSameSecretProofSet = (
    input: SameSecretProofSetInput,
): SameSecretProofSet => {
    validateProofSetInput(input);
    const statementRecords = sortedStatementRecordsForProofs(input);
    const proofMaterials = sortedSameSecretProofMaterials(input);
    const proofRecords = proofMaterials.map(
        (proofMaterial, expectedRosterPosition) => {
            const statementRecord = statementRecords[expectedRosterPosition];
            if (statementRecord === undefined) {
                throw new Error(
                    'sameSecretProofMaterials must match same-secret statement order.',
                );
            }
            if (
                proofMaterial.trusteeIdentity !==
                    statementRecord.trusteeIdentity ||
                proofMaterial.trusteeRosterPosition !==
                    statementRecord.trusteeRosterPosition
            ) {
                throw new Error(
                    'sameSecretProofMaterials must bind the derived same-secret statements.',
                );
            }
            const proofRecordWithoutRoot = {
                objectType: 'SameSecretProof',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                commitmentProfileId: setupCommitmentProfileId,
                setupProofProfileId,
                proofFamily: sameSecretProofFamily,
                ...contextFields(input.setupContext),
                trusteeIdentity: statementRecord.trusteeIdentity,
                trusteeRosterPosition: statementRecord.trusteeRosterPosition,
                ringDegree: input.vssCoefficientCommitmentMaterial.ringDegree,
                sameSecretStatementRoot:
                    statementRecord.sameSecretStatementRoot,
                trusteeSecretCommitmentRoot:
                    statementRecord.trusteeSecretCommitmentRoot,
                sameSecretProofFamilyBindingRoot:
                    statementRecord.sameSecretProofFamilyBindingRoot,
                statementHash: proofMaterial.statementHash,
                proofSizeBytes: proofMaterial.proofSizeBytes,
                proofBytesHash: proofMaterial.proofBytesHash,
                ...sameSecretProofByteMaterial(proofMaterial),
            } as const satisfies Omit<
                SameSecretProofRecord,
                'sameSecretProofRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                sameSecretProofRoot: deriveProtocolHash(
                    'SameSecretProofRoot',
                    proofRecordWithoutRoot,
                ),
            } satisfies SameSecretProofRecord;
        },
    );
    const proofSetWithoutRoot = {
        objectType: 'SameSecretProofSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: setupCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        proofAccountingHash: input.proofAccountingHash,
        ...contextFields(input.setupContext),
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        vssCoefficientCommitmentMaterialRoot:
            input.vssCoefficientCommitmentMaterial
                .vssCoefficientCommitmentMaterialRoot,
        sameSecretProofRoots: proofRecords.map((proofRecord) => ({
            trusteeIdentity: proofRecord.trusteeIdentity,
            trusteeRosterPosition: proofRecord.trusteeRosterPosition,
            sameSecretProofRoot: proofRecord.sameSecretProofRoot,
        })),
        proofRecords,
    } as const satisfies Omit<SameSecretProofSet, 'sameSecretProofSetRoot'>;

    return {
        ...proofSetWithoutRoot,
        sameSecretProofSetRoot: deriveProtocolHash(
            'SameSecretProofRoot',
            proofSetWithoutRoot,
        ),
    } satisfies SameSecretProofSet;
};

type CompactVssSourceCoefficientRecord =
    CompactVssCoefficientCommitmentSet['sourceTrusteeRecords'][number];

const sortedCompactCoefficientSourceRecordsForBridge = (
    compactCoefficientCommitmentSet: CompactVssCoefficientCommitmentSet,
): CompactVssSourceCoefficientRecord[] => {
    const sourceTrusteeRecords = [
        ...compactCoefficientCommitmentSet.sourceTrusteeRecords,
    ].sort(
        (leftRecord, rightRecord) =>
            leftRecord.sourceTrusteeRosterPosition -
            rightRecord.sourceTrusteeRosterPosition,
    );
    if (
        sourceTrusteeRecords.length !==
        compactCoefficientCommitmentSet.participantCount
    ) {
        throw new Error(
            'compact coefficient commitments must contain one source record per participant.',
        );
    }
    sourceTrusteeRecords.forEach((sourceTrusteeRecord, expectedPosition) => {
        if (
            sourceTrusteeRecord.sourceTrusteeRosterPosition !== expectedPosition
        ) {
            throw new Error(
                'compact coefficient source records must be contiguous from zero.',
            );
        }
    });

    return sourceTrusteeRecords;
};

const sortedSameSecretProofRecordsForBridge = (
    input: Pick<
        CompactVssSameSecretBridgeStatementSetInput,
        'sameSecretProofs'
    > & {
        readonly participantCount: number;
    },
): SameSecretProofRecord[] => {
    const proofRecords = [...input.sameSecretProofs.proofRecords].sort(
        (leftRecord, rightRecord) =>
            leftRecord.trusteeRosterPosition -
            rightRecord.trusteeRosterPosition,
    );
    if (proofRecords.length !== input.participantCount) {
        throw new Error(
            'sameSecretProofs.proofRecords must contain one proof per participant.',
        );
    }
    proofRecords.forEach((proofRecord, expectedPosition) => {
        assertProtocolHash(
            proofRecord.sameSecretProofRoot,
            'sameSecretProofs.proofRecords.sameSecretProofRoot',
        );
        if (proofRecord.trusteeRosterPosition !== expectedPosition) {
            throw new Error(
                'sameSecretProofs.proofRecords roster positions must be contiguous from zero.',
            );
        }
    });

    return proofRecords;
};

const targetConstantCoefficientRootsForBridge = (
    sourceTrusteeRecord: CompactVssSourceCoefficientRecord,
    targetRnsLimbCount: number,
): CompactVssSameSecretBridgeTargetConstantCommitmentRoot[] => {
    const constantRoots = sourceTrusteeRecord.coefficientCommitments.filter(
        (coefficientCommitment) =>
            coefficientCommitment.shamirCoefficientIndex === 0,
    );
    if (constantRoots.length !== targetRnsLimbCount) {
        throw new Error(
            'compact coefficient commitments must contain one target-basis constant coefficient root per RNS limb.',
        );
    }

    return constantRoots.map((coefficientCommitment, expectedRnsLimbIndex) => {
        if (coefficientCommitment.rnsLimbIndex !== expectedRnsLimbIndex) {
            throw new Error(
                'compact target-basis constant coefficient roots must be ordered by RNS limb.',
            );
        }
        assertProtocolHash(
            coefficientCommitment.coefficientCommitmentRoot,
            'compact coefficient commitment root',
        );

        return {
            rnsLimbIndex: coefficientCommitment.rnsLimbIndex,
            rnsPrime: coefficientCommitment.rnsPrime,
            shamirCoefficientIndex: 0,
            coefficientCommitmentRoot:
                coefficientCommitment.coefficientCommitmentRoot,
        };
    });
};

export const createCompactVssSameSecretBridgeStatementSet = (
    input: CompactVssSameSecretBridgeStatementSetInput,
): CompactVssSameSecretBridgeStatementSet => {
    assertProtocolHash(input.targetBasisHash, 'targetBasisHash');
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertContextMatches(
        input.setupContext,
        input.sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertContextMatches(
        input.setupContext,
        input.sameSecretProofs,
        'sameSecretProofs',
    );
    const compactCoefficientCommitmentSet =
        verifyCompactVssCoefficientCommitmentSet({
            coefficientCommitmentSet: input.compactCoefficientCommitmentSet,
        });
    if (
        compactCoefficientCommitmentSet.publicMatrixSeedHash !==
        input.publicMatrixSeedHash
    ) {
        throw new Error(
            'compact same-secret bridge statements must use the compact coefficient matrix seed hash.',
        );
    }
    if (
        input.sameSecretProofs.sameSecretConsistencyRoot !==
            input.sameSecretConsistency.sameSecretConsistencyRoot ||
        input.sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot
    ) {
        throw new Error(
            'sameSecretProofs must bind the same same-secret statement set.',
        );
    }
    if (
        input.sameSecretConsistency.participantCount !==
            compactCoefficientCommitmentSet.participantCount ||
        input.sameSecretProofs.participantCount !==
            compactCoefficientCommitmentSet.participantCount
    ) {
        throw new Error(
            'compact same-secret bridge inputs must use one participant count.',
        );
    }
    const compactSourceRecords = sortedCompactCoefficientSourceRecordsForBridge(
        compactCoefficientCommitmentSet,
    );
    const sameSecretStatementRecords = sortedStatementRecordsForProofs({
        participantCount: compactCoefficientCommitmentSet.participantCount,
        sameSecretConsistency: input.sameSecretConsistency,
    });
    const sameSecretProofRecords = sortedSameSecretProofRecordsForBridge({
        participantCount: compactCoefficientCommitmentSet.participantCount,
        sameSecretProofs: input.sameSecretProofs,
    });
    const statementRecords = compactSourceRecords.map(
        (compactSourceRecord, expectedPosition) => {
            const sameSecretStatementRecord =
                sameSecretStatementRecords[expectedPosition];
            const sameSecretProofRecord =
                sameSecretProofRecords[expectedPosition];
            if (
                sameSecretStatementRecord === undefined ||
                sameSecretProofRecord === undefined
            ) {
                throw new Error(
                    'compact same-secret bridge inputs must contain matching records.',
                );
            }
            if (
                compactSourceRecord.sourceTrusteeIdentity !==
                    sameSecretStatementRecord.trusteeIdentity ||
                compactSourceRecord.sourceTrusteeRosterPosition !==
                    sameSecretStatementRecord.trusteeRosterPosition ||
                sameSecretProofRecord.trusteeIdentity !==
                    sameSecretStatementRecord.trusteeIdentity ||
                sameSecretProofRecord.trusteeRosterPosition !==
                    sameSecretStatementRecord.trusteeRosterPosition
            ) {
                throw new Error(
                    'compact same-secret bridge records must bind one trustee identity and roster position.',
                );
            }
            if (
                sameSecretProofRecord.sameSecretStatementRoot !==
                    sameSecretStatementRecord.sameSecretStatementRoot ||
                sameSecretProofRecord.trusteeSecretCommitmentRoot !==
                    sameSecretStatementRecord.trusteeSecretCommitmentRoot ||
                sameSecretProofRecord.sameSecretProofFamilyBindingRoot !==
                    sameSecretStatementRecord.sameSecretProofFamilyBindingRoot
            ) {
                throw new Error(
                    'compact same-secret bridge proof records must bind the same statement record.',
                );
            }
            const statementRecordWithoutRoot = {
                objectType: 'CompactVssSameSecretBridgeStatement',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                compactCommitmentProfileId: compactVssCommitmentProfileId,
                setupProofProfileId,
                proofFamily: sameSecretProofFamily,
                ...contextFields(input.setupContext),
                targetBasisHash: input.targetBasisHash,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                trusteeIdentity: sameSecretStatementRecord.trusteeIdentity,
                trusteeRosterPosition:
                    sameSecretStatementRecord.trusteeRosterPosition,
                sameSecretStatementRoot:
                    sameSecretStatementRecord.sameSecretStatementRoot,
                sameSecretProofRoot: sameSecretProofRecord.sameSecretProofRoot,
                trusteeSecretCommitmentRoot:
                    sameSecretStatementRecord.trusteeSecretCommitmentRoot,
                sameSecretProofFamilyBindingRoot:
                    sameSecretStatementRecord.sameSecretProofFamilyBindingRoot,
                dataBasisRelation: sameSecretRelation,
                integerSupport: compactVssSameSecretBridgeIntegerSupport,
                signedRepresentativeConvention:
                    compactVssSameSecretBridgeSignedRepresentativeConvention,
                compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
                targetBasisLimbOrder:
                    compactVssSameSecretBridgeTargetBasisLimbOrder,
                targetConstantCoefficientCommitmentRoots:
                    targetConstantCoefficientRootsForBridge(
                        compactSourceRecord,
                        compactCoefficientCommitmentSet.rnsLimbCount,
                    ),
                relation: compactVssSameSecretBridgeRelation,
            } as const satisfies Omit<
                CompactVssSameSecretBridgeStatementRecord,
                'compactSameSecretBridgeStatementRoot'
            >;

            return {
                ...statementRecordWithoutRoot,
                compactSameSecretBridgeStatementRoot: deriveProtocolHash(
                    'SetupProofRecordBindingHash',
                    statementRecordWithoutRoot,
                ),
            };
        },
    );
    const statementSetWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeStatementSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        compactCommitmentProfileId: compactVssCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        ...contextFields(input.setupContext),
        targetBasisHash: input.targetBasisHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: compactCoefficientCommitmentSet.participantCount,
        targetRnsLimbCount: compactCoefficientCommitmentSet.rnsLimbCount,
        thresholdDegree: compactCoefficientCommitmentSet.thresholdDegree,
        compactCoefficientCommitmentRoot:
            compactCoefficientCommitmentSet.coefficientCommitmentRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        integerSupport: compactVssSameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            compactVssSameSecretBridgeSignedRepresentativeConvention,
        compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
        targetBasisLimbOrder: compactVssSameSecretBridgeTargetBasisLimbOrder,
        statementRecords,
    } as const satisfies Omit<
        CompactVssSameSecretBridgeStatementSet,
        'compactSameSecretBridgeStatementSetRoot'
    >;

    return {
        ...statementSetWithoutRoot,
        compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementSetWithoutRoot,
        ),
    };
};

const assertEvidenceContextMatchesStatementSet = (
    statementSet: CompactVssSameSecretBridgeStatementSet,
    evidenceSet: Readonly<Record<string, unknown>>,
    evidenceSetName: string,
): void => {
    for (const fieldName of setupContextFieldNames) {
        if (evidenceSet[fieldName] !== statementSet[fieldName]) {
            throw new Error(
                `${evidenceSetName}.${fieldName} must match the compact same-secret bridge statement set.`,
            );
        }
    }
};

const assertSameSecretEvidenceMatchesBridge = (input: {
    readonly statementSet: CompactVssSameSecretBridgeStatementSet;
    readonly sameSecretConsistency?: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs?: SameSecretProofSet;
    readonly transportedSameSecretProofMaterial?: TransportedSameSecretProofMaterialSet;
}): void => {
    if (
        (input.sameSecretConsistency === undefined) !==
        (input.sameSecretProofs === undefined)
    ) {
        throw new Error(
            'compact same-secret bridge evidence verification requires both sameSecretConsistency and sameSecretProofs.',
        );
    }
    if (
        input.sameSecretConsistency === undefined ||
        input.sameSecretProofs === undefined
    ) {
        return;
    }

    const { statementSet, sameSecretConsistency, sameSecretProofs } = input;
    assertEvidenceContextMatchesStatementSet(
        statementSet,
        sameSecretConsistency,
        'sameSecretConsistency',
    );
    assertEvidenceContextMatchesStatementSet(
        statementSet,
        sameSecretProofs,
        'sameSecretProofs',
    );
    if (
        sameSecretConsistency.sameSecretConsistencyRoot !==
            statementSet.sameSecretConsistencyRoot ||
        sameSecretProofs.sameSecretProofSetRoot !==
            statementSet.sameSecretProofSetRoot ||
        sameSecretConsistency.sameSecretProofFamilyBindingRoot !==
            statementSet.sameSecretProofFamilyBindingRoot ||
        sameSecretProofs.sameSecretProofFamilyBindingRoot !==
            statementSet.sameSecretProofFamilyBindingRoot ||
        sameSecretProofs.sameSecretConsistencyRoot !==
            sameSecretConsistency.sameSecretConsistencyRoot
    ) {
        throw new Error(
            'compact same-secret bridge evidence roots must match the statement set.',
        );
    }

    const {
        sameSecretConsistencyRoot: _sameSecretConsistencyRoot,
        ...sameSecretConsistencyWithoutRoot
    } = sameSecretConsistency;
    if (
        sameSecretConsistency.sameSecretConsistencyRoot !==
        deriveProtocolHash(
            'SameSecretConsistencyRoot',
            sameSecretConsistencyWithoutRoot,
        )
    ) {
        throw new Error(
            'same-secret consistency root does not match its bound statement set.',
        );
    }

    const {
        sameSecretProofSetRoot: _sameSecretProofSetRoot,
        ...sameSecretProofsWithoutRoot
    } = sameSecretProofs;
    if (
        sameSecretProofs.sameSecretProofSetRoot !==
        deriveProtocolHash('SameSecretProofRoot', sameSecretProofsWithoutRoot)
    ) {
        throw new Error(
            'same-secret proof set root does not match its bound proof records.',
        );
    }

    const sameSecretStatementRecords = sortedStatementRecordsForProofs({
        participantCount: statementSet.participantCount,
        sameSecretConsistency,
    });
    const sameSecretProofRecords = sortedSameSecretProofRecordsForBridge({
        participantCount: statementSet.participantCount,
        sameSecretProofs,
    });
    if (
        sameSecretConsistency.trusteeSecretCommitmentRoots.length !==
            statementSet.participantCount ||
        sameSecretProofs.sameSecretProofRoots.length !==
            statementSet.participantCount
    ) {
        throw new Error(
            'compact same-secret bridge evidence root references must cover every participant.',
        );
    }

    statementSet.statementRecords.forEach(
        (bridgeStatement, expectedPosition) => {
            const sameSecretStatement =
                sameSecretStatementRecords[expectedPosition];
            const sameSecretProof = sameSecretProofRecords[expectedPosition];
            const trusteeSecretRootReference =
                sameSecretConsistency.trusteeSecretCommitmentRoots[
                    expectedPosition
                ];
            const sameSecretProofRootReference =
                sameSecretProofs.sameSecretProofRoots[expectedPosition];
            if (
                sameSecretStatement === undefined ||
                sameSecretProof === undefined ||
                trusteeSecretRootReference === undefined ||
                sameSecretProofRootReference === undefined
            ) {
                throw new Error(
                    'compact same-secret bridge evidence records must cover every participant.',
                );
            }

            const {
                sameSecretStatementRoot: _sameSecretStatementRoot,
                ...sameSecretStatementWithoutRoot
            } = sameSecretStatement;
            if (
                sameSecretStatement.sameSecretStatementRoot !==
                deriveProtocolHash(
                    'SameSecretConsistencyRoot',
                    sameSecretStatementWithoutRoot,
                )
            ) {
                throw new Error(
                    'same-secret statement root does not match its bound statement.',
                );
            }

            const {
                sameSecretProofRoot: _sameSecretProofRoot,
                ...sameSecretProofWithoutRoot
            } = sameSecretProof;
            validateSameSecretProofMaterial(
                sameSecretProof,
                'sameSecretProofs.proofRecords',
            );
            if ((sameSecretProof as JsonRecord).proofBytesHex === undefined) {
                assertSameSecretProofRecordMatchesTransport(
                    sameSecretProof,
                    input.transportedSameSecretProofMaterial,
                );
            }
            if (
                sameSecretProof.sameSecretProofRoot !==
                deriveProtocolHash(
                    'SameSecretProofRoot',
                    sameSecretProofWithoutRoot,
                )
            ) {
                throw new Error(
                    'same-secret proof root does not match its bound proof record.',
                );
            }

            if (
                bridgeStatement.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                bridgeStatement.trusteeRosterPosition !== expectedPosition ||
                sameSecretProof.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                sameSecretProof.trusteeRosterPosition !== expectedPosition ||
                trusteeSecretRootReference.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                trusteeSecretRootReference.trusteeRosterPosition !==
                    expectedPosition ||
                sameSecretProofRootReference.trusteeIdentity !==
                    sameSecretStatement.trusteeIdentity ||
                sameSecretProofRootReference.trusteeRosterPosition !==
                    expectedPosition
            ) {
                throw new Error(
                    'compact same-secret bridge evidence records must bind the same trustee order.',
                );
            }

            if (
                bridgeStatement.sameSecretStatementRoot !==
                    sameSecretStatement.sameSecretStatementRoot ||
                bridgeStatement.trusteeSecretCommitmentRoot !==
                    sameSecretStatement.trusteeSecretCommitmentRoot ||
                bridgeStatement.sameSecretProofFamilyBindingRoot !==
                    sameSecretStatement.sameSecretProofFamilyBindingRoot ||
                sameSecretProof.sameSecretStatementRoot !==
                    sameSecretStatement.sameSecretStatementRoot ||
                sameSecretProof.trusteeSecretCommitmentRoot !==
                    sameSecretStatement.trusteeSecretCommitmentRoot ||
                sameSecretProof.sameSecretProofFamilyBindingRoot !==
                    sameSecretStatement.sameSecretProofFamilyBindingRoot ||
                bridgeStatement.sameSecretProofRoot !==
                    sameSecretProof.sameSecretProofRoot ||
                trusteeSecretRootReference.trusteeSecretCommitmentRoot !==
                    sameSecretStatement.trusteeSecretCommitmentRoot ||
                sameSecretProofRootReference.sameSecretProofRoot !==
                    sameSecretProof.sameSecretProofRoot
            ) {
                throw new Error(
                    'compact same-secret bridge evidence roots must match each bridge statement.',
                );
            }
        },
    );
};

export const verifyCompactVssSameSecretBridgeStatementSet = (input: {
    readonly statementSet: CompactVssSameSecretBridgeStatementSet;
    readonly sameSecretConsistency?: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs?: SameSecretProofSet;
    readonly transportedSameSecretProofMaterial?: TransportedSameSecretProofMaterialSet;
}): CompactVssSameSecretBridgeStatementSet => {
    const { statementSet } = input;
    assertExactString(
        statementSet.objectType,
        'compact same-secret bridge statement set objectType',
        'CompactVssSameSecretBridgeStatementSet',
    );
    if (statementSet.objectVersion !== 1) {
        throw new TypeError(
            'compact same-secret bridge statement set objectVersion is not supported.',
        );
    }
    for (const [fieldName, expectedValue] of [
        ['setupProfileId', 'CollectiveBgvSetup-v1'],
        ['compactCommitmentProfileId', compactVssCommitmentProfileId],
        ['setupProofProfileId', setupProofProfileId],
        ['proofFamily', sameSecretProofFamily],
    ] as const) {
        assertExactString(
            statementSet[fieldName],
            `compact same-secret bridge statement set ${fieldName}`,
            expectedValue,
        );
    }
    assertNonEmptyString(
        statementSet.ceremonyId,
        'compact same-secret bridge statement set ceremonyId',
    );
    assertNonEmptyString(
        statementSet.setupEpoch,
        'compact same-secret bridge statement set setupEpoch',
    );
    for (const fieldName of [
        'manifestHash',
        'rosterHash',
        'setupProfileHash',
        'qShareHash',
        'carryAwareVssShareRelationProfileHash',
        'commitmentProfileHash',
        'targetBasisHash',
        'publicMatrixSeedHash',
        'compactCoefficientCommitmentRoot',
        'sameSecretConsistencyRoot',
        'sameSecretProofSetRoot',
        'sameSecretProofFamilyBindingRoot',
    ] as const) {
        assertProtocolHash(
            statementSet[fieldName],
            `compact same-secret bridge statement set ${fieldName}`,
        );
    }
    assertPositiveSafeInteger(
        statementSet.participantCount,
        'compact same-secret bridge statement set participantCount',
    );
    assertPositiveSafeInteger(
        statementSet.targetRnsLimbCount,
        'compact same-secret bridge statement set targetRnsLimbCount',
    );
    assertPositiveSafeInteger(
        statementSet.thresholdDegree,
        'compact same-secret bridge statement set thresholdDegree',
    );
    assertExactString(
        statementSet.integerSupport,
        'compact same-secret bridge statement set integerSupport',
        compactVssSameSecretBridgeIntegerSupport,
    );
    assertExactString(
        statementSet.signedRepresentativeConvention,
        'compact same-secret bridge statement set signedRepresentativeConvention',
        compactVssSameSecretBridgeSignedRepresentativeConvention,
    );
    assertExactString(
        statementSet.compactCommitmentEncoding,
        'compact same-secret bridge statement set compactCommitmentEncoding',
        compactVssCommitmentBinaryFormat,
    );
    assertExactString(
        statementSet.targetBasisLimbOrder,
        'compact same-secret bridge statement set targetBasisLimbOrder',
        compactVssSameSecretBridgeTargetBasisLimbOrder,
    );
    if (
        statementSet.statementRecords.length !== statementSet.participantCount
    ) {
        throw new Error(
            'compact same-secret bridge statement set must contain one statement per participant.',
        );
    }
    statementSet.statementRecords.forEach(
        (statementRecord, expectedPosition) => {
            assertExactString(
                statementRecord.objectType,
                'compact same-secret bridge statement objectType',
                'CompactVssSameSecretBridgeStatement',
            );
            if (statementRecord.objectVersion !== 1) {
                throw new TypeError(
                    'compact same-secret bridge statement objectVersion is not supported.',
                );
            }
            for (const [fieldName, expectedValue] of [
                ['setupProfileId', statementSet.setupProfileId],
                [
                    'compactCommitmentProfileId',
                    statementSet.compactCommitmentProfileId,
                ],
                ['setupProofProfileId', statementSet.setupProofProfileId],
                ['proofFamily', statementSet.proofFamily],
            ] as const) {
                assertExactString(
                    statementRecord[fieldName],
                    `compact same-secret bridge statement ${fieldName}`,
                    expectedValue,
                );
            }
            for (const fieldName of setupContextFieldNames) {
                if (statementRecord[fieldName] !== statementSet[fieldName]) {
                    throw new Error(
                        `compact same-secret bridge statement ${fieldName} must match the statement set.`,
                    );
                }
            }
            if (
                statementRecord.targetBasisHash !==
                    statementSet.targetBasisHash ||
                statementRecord.publicMatrixSeedHash !==
                    statementSet.publicMatrixSeedHash
            ) {
                throw new Error(
                    'compact same-secret bridge statement target binding must match the statement set.',
                );
            }
            assertNonEmptyString(
                statementRecord.trusteeIdentity,
                'compact same-secret bridge statement trusteeIdentity',
            );
            if (statementRecord.trusteeRosterPosition !== expectedPosition) {
                throw new Error(
                    'compact same-secret bridge statement roster positions must be contiguous from zero.',
                );
            }
            for (const fieldName of [
                'sameSecretStatementRoot',
                'sameSecretProofRoot',
                'trusteeSecretCommitmentRoot',
                'sameSecretProofFamilyBindingRoot',
                'compactSameSecretBridgeStatementRoot',
            ] as const) {
                assertProtocolHash(
                    statementRecord[fieldName],
                    `compact same-secret bridge statement ${fieldName}`,
                );
            }
            if (
                statementRecord.sameSecretProofFamilyBindingRoot !==
                statementSet.sameSecretProofFamilyBindingRoot
            ) {
                throw new Error(
                    'compact same-secret bridge statement proof-family binding root must match the statement set.',
                );
            }
            assertExactString(
                statementRecord.dataBasisRelation,
                'compact same-secret bridge statement dataBasisRelation',
                sameSecretRelation,
            );
            for (const fieldName of [
                'integerSupport',
                'signedRepresentativeConvention',
                'compactCommitmentEncoding',
                'targetBasisLimbOrder',
            ] as const) {
                assertExactString(
                    statementRecord[fieldName],
                    `compact same-secret bridge statement ${fieldName}`,
                    statementSet[fieldName],
                );
            }
            assertExactString(
                statementRecord.relation,
                'compact same-secret bridge statement relation',
                compactVssSameSecretBridgeRelation,
            );
            if (
                statementRecord.targetConstantCoefficientCommitmentRoots
                    .length !== statementSet.targetRnsLimbCount
            ) {
                throw new Error(
                    'compact same-secret bridge statement must bind one target constant root per target RNS limb.',
                );
            }
            statementRecord.targetConstantCoefficientCommitmentRoots.forEach(
                (rootRecord, expectedRnsLimbIndex) => {
                    if (
                        rootRecord.rnsLimbIndex !== expectedRnsLimbIndex ||
                        rootRecord.shamirCoefficientIndex !== 0
                    ) {
                        throw new Error(
                            'compact same-secret bridge target constant roots must use canonical coordinates.',
                        );
                    }
                    assertPositiveSafeInteger(
                        rootRecord.rnsPrime,
                        'compact same-secret bridge target constant root rnsPrime',
                    );
                    assertProtocolHash(
                        rootRecord.coefficientCommitmentRoot,
                        'compact same-secret bridge target constant root coefficientCommitmentRoot',
                    );
                },
            );
            const {
                compactSameSecretBridgeStatementRoot:
                    _compactSameSecretBridgeStatementRoot,
                ...statementRecordWithoutRoot
            } = statementRecord;
            const expectedStatementRoot = deriveProtocolHash(
                'SetupProofRecordBindingHash',
                statementRecordWithoutRoot,
            );
            if (
                statementRecord.compactSameSecretBridgeStatementRoot !==
                expectedStatementRoot
            ) {
                throw new Error(
                    'compact same-secret bridge statement root does not match its bound roots.',
                );
            }
        },
    );
    const {
        compactSameSecretBridgeStatementSetRoot:
            _compactSameSecretBridgeStatementSetRoot,
        ...statementSetWithoutRoot
    } = statementSet;
    const expectedStatementSetRoot = deriveProtocolHash(
        'SetupProofRecordBindingHash',
        statementSetWithoutRoot,
    );
    if (
        statementSet.compactSameSecretBridgeStatementSetRoot !==
        expectedStatementSetRoot
    ) {
        throw new Error(
            'compact same-secret bridge statement set root does not match its statements.',
        );
    }
    assertSameSecretEvidenceMatchesBridge({
        statementSet,
        sameSecretConsistency: input.sameSecretConsistency,
        sameSecretProofs: input.sameSecretProofs,
        transportedSameSecretProofMaterial:
            input.transportedSameSecretProofMaterial,
    });

    return statementSet;
};

const compactVssSameSecretBridgeProofBytesHash = (
    proofBytes: Uint8Array,
): ProtocolHash =>
    hash512Hex(compactVssSameSecretBridgeProofBytesHashDomain, [proofBytes]);

const compactVssSameSecretBridgeProofInputsByStatementRoot = (
    proofRecordInputs: readonly CompactVssSameSecretBridgeProofRecordInput[],
): Map<ProtocolHash, CompactVssSameSecretBridgeProofRecordInput> => {
    const proofInputsByStatementRoot = new Map<
        ProtocolHash,
        CompactVssSameSecretBridgeProofRecordInput
    >();
    const proofStatementHashes = new Set<ProtocolHash>();
    proofRecordInputs.forEach((proofRecordInput, proofRecordIndex) => {
        assertProtocolHash(
            proofRecordInput.compactSameSecretBridgeStatementRoot,
            `proofRecordInputs.${String(proofRecordIndex)}.compactSameSecretBridgeStatementRoot`,
        );
        assertProtocolHash(
            proofRecordInput.proofStatementHash,
            `proofRecordInputs.${String(proofRecordIndex)}.proofStatementHash`,
        );
        if (
            proofRecordInput.proofStatement.proofStatementHash !==
            proofRecordInput.proofStatementHash
        ) {
            throw new Error(
                'compact same-secret bridge proof statement hash must match its proof record input.',
            );
        }
        if (proofStatementHashes.has(proofRecordInput.proofStatementHash)) {
            throw new Error(
                'compact same-secret bridge proof record inputs must not repeat a proof statement hash.',
            );
        }
        proofStatementHashes.add(proofRecordInput.proofStatementHash);
        bytesFromHex(
            proofRecordInput.proofBytesHex,
            `proofRecordInputs.${String(proofRecordIndex)}.proofBytesHex`,
        );
        if (
            proofInputsByStatementRoot.has(
                proofRecordInput.compactSameSecretBridgeStatementRoot,
            )
        ) {
            throw new Error(
                'compact same-secret bridge proof record inputs must not repeat a bridge statement root.',
            );
        }
        proofInputsByStatementRoot.set(
            proofRecordInput.compactSameSecretBridgeStatementRoot,
            proofRecordInput,
        );
    });

    return proofInputsByStatementRoot;
};

export const createCompactVssSameSecretBridgeProofMaterialSet = (input: {
    readonly statementSet: CompactVssSameSecretBridgeStatementSet;
    readonly proofRecordInputs: readonly CompactVssSameSecretBridgeProofRecordInput[];
}): CompactVssSameSecretBridgeProofMaterialSet => {
    const statementSet = verifyCompactVssSameSecretBridgeStatementSet({
        statementSet: input.statementSet,
    });
    const proofInputsByStatementRoot =
        compactVssSameSecretBridgeProofInputsByStatementRoot(
            input.proofRecordInputs,
        );
    if (proofInputsByStatementRoot.size !== statementSet.participantCount) {
        throw new Error(
            'compact same-secret bridge proof material inputs must contain one proof record per bridge statement.',
        );
    }

    const proofRecords = statementSet.statementRecords.map(
        (statementRecord) => {
            const proofRecordInput = proofInputsByStatementRoot.get(
                statementRecord.compactSameSecretBridgeStatementRoot,
            );
            if (proofRecordInput === undefined) {
                throw new Error(
                    'compact same-secret bridge proof material inputs must cover every bridge statement.',
                );
            }
            const proofBytes = bytesFromHex(
                proofRecordInput.proofBytesHex,
                'compact same-secret bridge proofBytesHex',
            );
            const proofRecordWithoutRoot = {
                objectType: 'CompactVssSameSecretBridgeProofRecord',
                objectVersion: 1,
                proofFamily: compactVssSameSecretBridgeProofFamily,
                compactSameSecretBridgeStatementRoot:
                    statementRecord.compactSameSecretBridgeStatementRoot,
                proofStatementHash: proofRecordInput.proofStatementHash,
                proofByteLength: proofBytes.byteLength,
                proofBytesHash:
                    compactVssSameSecretBridgeProofBytesHash(proofBytes),
                proofBytesHex: proofRecordInput.proofBytesHex,
            } as const satisfies Omit<
                CompactVssSameSecretBridgeProofRecord,
                'proofRecordRoot'
            >;

            return {
                ...proofRecordWithoutRoot,
                proofRecordRoot: deriveProtocolHash(
                    'SetupProofRecordBindingHash',
                    proofRecordWithoutRoot,
                ),
            };
        },
    );
    const proofStatements = statementSet.statementRecords.map(
        (statementRecord) => {
            const proofRecordInput = proofInputsByStatementRoot.get(
                statementRecord.compactSameSecretBridgeStatementRoot,
            );
            if (proofRecordInput === undefined) {
                throw new Error(
                    'compact same-secret bridge proof material inputs must cover every bridge statement.',
                );
            }

            return proofRecordInput.proofStatement;
        },
    );
    const proofMaterialSetWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeProofMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        compactCommitmentProfileId: compactVssCommitmentProfileId,
        setupProofProfileId,
        proofFamily: compactVssSameSecretBridgeProofFamily,
        ...contextFields(statementSet),
        targetBasisHash: statementSet.targetBasisHash,
        publicMatrixSeedHash: statementSet.publicMatrixSeedHash,
        participantCount: statementSet.participantCount,
        targetRnsLimbCount: statementSet.targetRnsLimbCount,
        thresholdDegree: statementSet.thresholdDegree,
        compactCoefficientCommitmentRoot:
            statementSet.compactCoefficientCommitmentRoot,
        sameSecretConsistencyRoot: statementSet.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: statementSet.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            statementSet.sameSecretProofFamilyBindingRoot,
        compactSameSecretBridgeStatementSetRoot:
            statementSet.compactSameSecretBridgeStatementSetRoot,
        proofRecords,
        proofStatements,
    } as const satisfies Omit<
        CompactVssSameSecretBridgeProofMaterialSet,
        'proofMaterialSetRoot'
    >;

    return {
        ...proofMaterialSetWithoutRoot,
        proofMaterialSetRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            proofMaterialSetWithoutRoot,
        ),
    };
};

export const verifyCompactVssSameSecretBridgeProofMaterialSet = (input: {
    readonly statementSet: CompactVssSameSecretBridgeStatementSet;
    readonly proofMaterialSet: CompactVssSameSecretBridgeProofMaterialSet;
}): CompactVssSameSecretBridgeProofMaterialSet => {
    const statementSet = verifyCompactVssSameSecretBridgeStatementSet({
        statementSet: input.statementSet,
    });
    const proofMaterialSet = input.proofMaterialSet;
    assertExactString(
        proofMaterialSet.objectType,
        'compact same-secret bridge proof material set objectType',
        'CompactVssSameSecretBridgeProofMaterialSet',
    );
    if (proofMaterialSet.objectVersion !== 1) {
        throw new TypeError(
            'compact same-secret bridge proof material set objectVersion is not supported.',
        );
    }
    for (const [fieldName, expectedValue] of [
        ['setupProfileId', statementSet.setupProfileId],
        ['compactCommitmentProfileId', statementSet.compactCommitmentProfileId],
        ['setupProofProfileId', statementSet.setupProofProfileId],
        ['proofFamily', compactVssSameSecretBridgeProofFamily],
        ['ceremonyId', statementSet.ceremonyId],
        ['manifestHash', statementSet.manifestHash],
        ['rosterHash', statementSet.rosterHash],
        ['setupProfileHash', statementSet.setupProfileHash],
        ['qShareHash', statementSet.qShareHash],
        [
            'carryAwareVssShareRelationProfileHash',
            statementSet.carryAwareVssShareRelationProfileHash,
        ],
        ['commitmentProfileHash', statementSet.commitmentProfileHash],
        ['setupEpoch', statementSet.setupEpoch],
        ['targetBasisHash', statementSet.targetBasisHash],
        ['publicMatrixSeedHash', statementSet.publicMatrixSeedHash],
        [
            'compactCoefficientCommitmentRoot',
            statementSet.compactCoefficientCommitmentRoot,
        ],
        ['sameSecretConsistencyRoot', statementSet.sameSecretConsistencyRoot],
        ['sameSecretProofSetRoot', statementSet.sameSecretProofSetRoot],
        [
            'sameSecretProofFamilyBindingRoot',
            statementSet.sameSecretProofFamilyBindingRoot,
        ],
        [
            'compactSameSecretBridgeStatementSetRoot',
            statementSet.compactSameSecretBridgeStatementSetRoot,
        ],
    ] as const) {
        if (proofMaterialSet[fieldName] !== expectedValue) {
            throw new Error(
                `compact same-secret bridge proof material set ${fieldName} must match the statement set.`,
            );
        }
    }
    if (
        proofMaterialSet.participantCount !== statementSet.participantCount ||
        proofMaterialSet.targetRnsLimbCount !==
            statementSet.targetRnsLimbCount ||
        proofMaterialSet.thresholdDegree !== statementSet.thresholdDegree
    ) {
        throw new Error(
            'compact same-secret bridge proof material set must bind the statement dimensions.',
        );
    }
    if (
        proofMaterialSet.proofRecords.length !==
            statementSet.participantCount ||
        proofMaterialSet.proofStatements.length !==
            statementSet.participantCount
    ) {
        throw new Error(
            'compact same-secret bridge proof material set must contain one proof record and one proof statement per bridge statement.',
        );
    }
    const proofStatementHashes = new Set<ProtocolHash>();
    proofMaterialSet.proofRecords.forEach((proofRecord, proofRecordIndex) => {
        const statementRecord = statementSet.statementRecords[proofRecordIndex];
        if (statementRecord === undefined) {
            throw new Error(
                'compact same-secret bridge proof material set has no matching bridge statement.',
            );
        }
        assertExactString(
            proofRecord.objectType,
            'compact same-secret bridge proof record objectType',
            'CompactVssSameSecretBridgeProofRecord',
        );
        if (proofRecord.objectVersion !== 1) {
            throw new TypeError(
                'compact same-secret bridge proof record objectVersion is not supported.',
            );
        }
        for (const [fieldName, expectedValue] of [
            ['proofFamily', proofMaterialSet.proofFamily],
            [
                'compactSameSecretBridgeStatementRoot',
                statementRecord.compactSameSecretBridgeStatementRoot,
            ],
        ] as const) {
            if (proofRecord[fieldName] !== expectedValue) {
                throw new Error(
                    `compact same-secret bridge proof record ${fieldName} must match its proof material set and statement.`,
                );
            }
        }
        assertProtocolHash(
            proofRecord.proofStatementHash,
            'compact same-secret bridge proof record proofStatementHash',
        );
        if (proofStatementHashes.has(proofRecord.proofStatementHash)) {
            throw new Error(
                'compact same-secret bridge proof records must not repeat a proof statement hash.',
            );
        }
        proofStatementHashes.add(proofRecord.proofStatementHash);
        const proofStatement =
            proofMaterialSet.proofStatements[proofRecordIndex];
        if (proofStatement === undefined) {
            throw new Error(
                'compact same-secret bridge proof material set has no matching proof statement.',
            );
        }
        if (
            proofStatement.proofStatementHash !== proofRecord.proofStatementHash
        ) {
            throw new Error(
                'compact same-secret bridge proof statement hash must match its proof record.',
            );
        }
        assertPositiveSafeInteger(
            proofRecord.proofByteLength,
            'compact same-secret bridge proof record proofByteLength',
        );
        assertProtocolHash(
            proofRecord.proofBytesHash,
            'compact same-secret bridge proof record proofBytesHash',
        );
        assertProtocolHash(
            proofRecord.proofRecordRoot,
            'compact same-secret bridge proof record proofRecordRoot',
        );
        const proofBytes = bytesFromHex(
            proofRecord.proofBytesHex,
            'compact same-secret bridge proof record proofBytesHex',
        );
        if (proofRecord.proofByteLength !== proofBytes.byteLength) {
            throw new Error(
                'compact same-secret bridge proof record proofByteLength must match proofBytesHex.',
            );
        }
        if (
            proofRecord.proofBytesHash !==
            compactVssSameSecretBridgeProofBytesHash(proofBytes)
        ) {
            throw new Error(
                'compact same-secret bridge proof record proofBytesHash must match proofBytesHex.',
            );
        }
        const { proofRecordRoot: _proofRecordRoot, ...proofRecordWithoutRoot } =
            proofRecord;
        if (
            proofRecord.proofRecordRoot !==
            deriveProtocolHash(
                'SetupProofRecordBindingHash',
                proofRecordWithoutRoot,
            )
        ) {
            throw new Error(
                `compact same-secret bridge proof record ${String(proofRecordIndex)} root does not match its bound proof bytes.`,
            );
        }
    });
    assertProtocolHash(
        proofMaterialSet.proofMaterialSetRoot,
        'compact same-secret bridge proof material set proofMaterialSetRoot',
    );
    const {
        proofMaterialSetRoot: _proofMaterialSetRoot,
        ...proofMaterialSetWithoutRoot
    } = proofMaterialSet;
    if (
        proofMaterialSet.proofMaterialSetRoot !==
        deriveProtocolHash(
            'SetupProofRecordBindingHash',
            proofMaterialSetWithoutRoot,
        )
    ) {
        throw new Error(
            'compact same-secret bridge proof material set root does not match its bound proof records.',
        );
    }

    return proofMaterialSet;
};

// Move embedded anchor proof bytes into binary chunked transport, mirroring
// the kernel transported same-secret proof material flow: each material keeps
// the transport reference fields, the chunks travel in the request-side
// transported proof material set.
export const createBinaryChunkedSameSecretProofMaterialTransport = (
    proofMaterials: readonly SameSecretProofMaterial[],
): BinaryChunkedSameSecretProofMaterialTransport => {
    const transportedProofMaterials: JsonRecord[] = [];
    const transportedRecords = proofMaterials.map(
        (proofMaterial, proofIndex) => {
            const materialRecord = proofMaterial as JsonRecord;
            const proofBytesHex = materialRecord.proofBytesHex;
            if (
                typeof proofBytesHex !== 'string' ||
                proofBytesHex.length === 0
            ) {
                throw new TypeError(
                    `proofMaterials.${String(proofIndex)}.proofBytesHex must be non-empty.`,
                );
            }
            const proofBytes = bytesFromHex(
                proofBytesHex,
                `proofMaterials.${String(proofIndex)}.proofBytesHex`,
            );
            if (proofMaterial.proofSizeBytes !== proofBytes.byteLength) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofSizeBytes must match proofBytesHex.`,
                );
            }
            const expectedProofBytesHash = hash512Hex(
                sameSecretAnchorProofBytesHashDomain,
                [proofBytes],
            );
            if (proofMaterial.proofBytesHash !== expectedProofBytesHash) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofBytesHash must match proofBytesHex before transport.`,
                );
            }
            const chunks: Uint8Array[] = [];
            for (
                let chunkStart = 0;
                chunkStart < proofBytes.byteLength;
                chunkStart += setupProofTransportChunkSizeBytes
            ) {
                chunks.push(
                    proofBytes.slice(
                        chunkStart,
                        Math.min(
                            chunkStart + setupProofTransportChunkSizeBytes,
                            proofBytes.byteLength,
                        ),
                    ),
                );
            }
            if (chunks.length === 0) {
                throw new Error(
                    `proofMaterials.${String(proofIndex)}.proofBytesHex must produce at least one transported chunk.`,
                );
            }
            const totalByteLength = proofBytes.byteLength;
            const fullObjectHash = setupProofMaterialFullObjectHashHex(
                sameSecretProofFamily,
                totalByteLength,
                chunks,
            );
            const chunkHashes = chunks.map((chunk, chunkIndex) =>
                setupProofMaterialChunkHash(
                    sameSecretProofFamily,
                    fullObjectHash,
                    chunkIndex,
                    chunk,
                ),
            );
            const chunkRoot = setupProofChunkManifestRoot(
                sameSecretProofFamily,
                chunkHashes,
                fullObjectHash,
                totalByteLength,
            );
            const proofMaterialRoot = deriveProtocolHash(
                'SameSecretLinkageAnchorProofMaterialRoot',
                {
                    objectType: 'SameSecretLinkageAnchorProofMaterialReference',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    setupProofProfileId,
                    proofFamily: sameSecretProofFamily,
                    trusteeIdentity: proofMaterial.trusteeIdentity,
                    trusteeRosterPosition: proofMaterial.trusteeRosterPosition,
                    statementHash: proofMaterial.statementHash,
                    proofSizeBytes: proofMaterial.proofSizeBytes,
                    proofBytesHash: proofMaterial.proofBytesHash,
                    chunkSizeBytes: setupProofTransportChunkSizeBytes,
                    chunkCount: chunkHashes.length,
                    totalByteLength,
                    fullObjectHash,
                    chunkRoot,
                    chunkHashes,
                },
            );
            transportedProofMaterials.push({
                objectType: 'SetupTransportedSameSecretProofMaterial',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                setupProofProfileId,
                proofFamily: sameSecretProofFamily,
                proofMaterialRoot,
                chunkSizeBytes: setupProofTransportChunkSizeBytes,
                chunkCount: chunkHashes.length,
                totalByteLength,
                fullObjectHash,
                chunkHashes,
                chunkRoot,
                chunks: chunks.map((chunk, chunkIndex) => ({
                    chunkIndex,
                    bytesHex: bytesToHex(chunk),
                })),
            });
            const transportedMaterial = {
                ...materialRecord,
                proofBytesEncoding: 'binary-chunked-proof-bytes',
                proofMaterialRoot,
                proofChunkSizeBytes: setupProofTransportChunkSizeBytes,
                proofChunkCount: chunkHashes.length,
                proofTotalByteLength: totalByteLength,
                proofFullObjectHash: fullObjectHash,
                proofChunkRoot: chunkRoot,
                proofChunkHashes: chunkHashes,
            } as JsonRecord;
            delete transportedMaterial.proofBytesHex;

            return transportedMaterial as unknown as SameSecretProofMaterial;
        },
    );

    return {
        proofMaterials: transportedRecords,
        transportedSameSecretProofMaterial: {
            objectType: 'SetupTransportedSameSecretProofMaterialSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            setupProofProfileId,
            proofFamily: sameSecretProofFamily,
            proofMaterials: transportedProofMaterials,
        },
    };
};
