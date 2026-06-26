import { deriveProtocolHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    setupCommitmentProfileId,
    setupCommitmentRootPayload,
    materialRecordsFromTransportedVssCoefficientCommitmentMaterial,
    type SetupPackageVssCoefficientCommitmentMaterialSet,
    type SetupTransportedVssCoefficientCommitmentMaterial,
    type SetupCommitmentValue,
    type VssCoefficientCommitmentMaterialRecord,
    type VssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentRecord,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeCoefficientCommitmentRecord,
} from './vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

type ThresholdCommitmentRowHash = Readonly<{
    readonly commitmentModulusIndex: number;
    readonly modulus: number;
    readonly rowCoefficientHash512: readonly string[];
}>;

export type ThresholdShareCommitmentLimb = Readonly<
    JsonRecord & {
        readonly objectType: 'ThresholdShareCommitment';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly derivationRule: typeof thresholdShareDerivationRule;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly trusteePoint: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly shamirCoefficientScalarsDecimal: readonly string[];
        readonly coefficientCommitmentRoots: readonly ProtocolHash[];
        readonly commitmentLimbs: readonly ThresholdCommitmentRowHash[];
        readonly thresholdShareCommitmentRoot: ProtocolHash;
    }
>;

export type ThresholdShareCommitmentRecipient = Readonly<
    JsonRecord & {
        readonly objectType: 'TrusteeThresholdShareCommitments';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly derivationRule: typeof thresholdShareDerivationRule;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly trusteePoint: number;
        readonly ringDegree: number;
        readonly limbCommitments: readonly ThresholdShareCommitmentLimb[];
        readonly recipientCommitmentRoot: ProtocolHash;
    }
>;

export type ThresholdShareCommitmentSet = Readonly<
    JsonRecord & {
        readonly objectType: 'ThresholdShareCommitmentSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly commitmentProfileId: typeof setupCommitmentProfileId;
        readonly derivationRule: typeof thresholdShareDerivationRule;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly participantCount: number;
        readonly thresholdDegree: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly recipientRecords: readonly ThresholdShareCommitmentRecipient[];
        readonly thresholdShareCommitmentRoot: ProtocolHash;
    }
>;

type ThresholdShareCommitmentsInput = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly vssCoefficientCommitments: VssCoefficientCommitmentSet;
    readonly vssCoefficientCommitmentMaterial:
        | SetupPackageVssCoefficientCommitmentMaterialSet
        | JsonRecord;
    readonly transportedVssCoefficientCommitmentMaterial?:
        | SetupTransportedVssCoefficientCommitmentMaterial
        | JsonRecord;
}>;

type SourceTrusteeCoordinate = Readonly<{
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: ProtocolHash;
}>;

type CommitmentMaterialCoordinate = Readonly<{
    readonly sourceTrusteeRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly shamirCoefficientIndex: number;
}>;

type ParsedCommitmentMaterial = Readonly<{
    readonly record: VssCoefficientCommitmentMaterialRecord;
    readonly commitment: SetupCommitmentValue;
}>;

const setupProfileId = 'CollectiveBgvSetup-v1';
const thresholdShareDerivationRule =
    'sum-source-trustee-polynomial-commitments-at-trustee-point';
const protocolHashPattern = /^[0-9a-f]{128}$/u;
const contextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupProfileHash',
    'qShareHash',
    'carryAwareVssShareRelationProfileHash',
    'commitmentProfileHash',
    'setupEpoch',
] as const;

const coefficientVectorBytes = (
    coefficients: readonly number[],
): Uint8Array => {
    // Inputs here are already constrained to [0, modulus) by parseCommitmentValue upstream; unlike the public-key-share encoder this does not re-validate, so callers must pass pre-validated residues.
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        let value = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(value & 0xffn);
            value >>= 8n;
        }
    });

    return bytes;
};

const coefficientVectorHash512 = (
    coefficients: readonly number[],
    domain: string,
): string => hash512Hex(domain, [coefficientVectorBytes(coefficients)]);

const assertProtocolHash = (
    value: unknown,
    fieldName: string,
): ProtocolHash => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }

    return value;
};

const assertNonEmptyString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }

    return value;
};

const assertPositiveSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value <= 0
    ) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }

    return value;
};

const assertNonNegativeSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

const assertJsonRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const assertJsonRecordArray = (
    value: unknown,
    fieldName: string,
): readonly JsonRecord[] => {
    if (!Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an array.`);
    }

    return value.map((entry, entryIndex) =>
        assertJsonRecord(entry, `${fieldName}.${String(entryIndex)}`),
    );
};

const assertObjectType = (
    value: JsonRecord,
    fieldName: string,
    expectedObjectType: string,
): void => {
    if (value.objectType !== expectedObjectType) {
        throw new Error(
            `${fieldName}.objectType must be ${expectedObjectType}.`,
        );
    }
    if (value.objectVersion !== 1) {
        throw new Error(`${fieldName}.objectVersion must be 1.`);
    }
};

const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    objectPath: string,
): void => {
    for (const fieldName of contextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${objectPath}.${fieldName} must match setupContext.${fieldName}.`,
            );
        }
    }
};

const setupContextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<CollectiveBgvSetupContext, (typeof contextFieldNames)[number]> => ({
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

const sortedSourceTrusteeRecords = (
    vssCoefficientCommitments: VssCoefficientCommitmentSet,
): readonly VssSourceTrusteeCoefficientCommitmentRecord[] => {
    const sourceTrusteeRecords = [
        ...vssCoefficientCommitments.sourceTrusteeRecords,
    ].sort(
        (left, right) =>
            left.sourceTrusteeRosterPosition -
            right.sourceTrusteeRosterPosition,
    );
    if (sourceTrusteeRecords.length === 0) {
        throw new Error(
            'vssCoefficientCommitments must contain at least one source trustee.',
        );
    }
    sourceTrusteeRecords.forEach((sourceTrusteeRecord, expectedPosition) => {
        if (
            sourceTrusteeRecord.sourceTrusteeRosterPosition !== expectedPosition
        ) {
            throw new Error(
                'vssCoefficientCommitments source trustee roster positions must be contiguous from zero.',
            );
        }
        assertNonEmptyString(
            sourceTrusteeRecord.sourceTrusteeIdentity,
            `vssCoefficientCommitments.sourceTrusteeRecords.${String(expectedPosition)}.sourceTrusteeIdentity`,
        );
        assertProtocolHash(
            sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
            `vssCoefficientCommitments.sourceTrusteeRecords.${String(expectedPosition)}.sourceTrusteeCommitmentRoot`,
        );
    });

    return sourceTrusteeRecords;
};

const materialCoordinateKey = (
    coordinate: CommitmentMaterialCoordinate,
): string =>
    [
        coordinate.sourceTrusteeRosterPosition,
        coordinate.rnsLimbIndex,
        coordinate.shamirCoefficientIndex,
    ]
        .map(String)
        .join(':');

const commitmentRecordCoordinateKey = (
    sourceTrusteeRosterPosition: number,
    commitmentRecord: VssCoefficientCommitmentRecord,
): string =>
    materialCoordinateKey({
        sourceTrusteeRosterPosition,
        rnsLimbIndex: commitmentRecord.rnsLimbIndex,
        shamirCoefficientIndex: commitmentRecord.shamirCoefficientIndex,
    });

const parseCommitmentValue = (
    commitmentValue: unknown,
    objectPath: string,
): SetupCommitmentValue => {
    const commitment = assertJsonRecord(commitmentValue, objectPath);
    assertObjectType(commitment, objectPath, 'SetupCommitment');
    if (commitment.profileId !== setupCommitmentProfileId) {
        throw new Error(
            `${objectPath}.profileId must be ${setupCommitmentProfileId}.`,
        );
    }
    const sourceRnsLimbIndex = assertNonNegativeSafeInteger(
        commitment.sourceRnsLimbIndex,
        `${objectPath}.sourceRnsLimbIndex`,
    );
    const sourceMessageModulus = assertPositiveSafeInteger(
        commitment.sourceMessageModulus,
        `${objectPath}.sourceMessageModulus`,
    );
    const shamirCoefficientIndex = assertNonNegativeSafeInteger(
        commitment.shamirCoefficientIndex,
        `${objectPath}.shamirCoefficientIndex`,
    );
    const ringDegree = assertPositiveSafeInteger(
        commitment.ringDegree,
        `${objectPath}.ringDegree`,
    );
    const commitmentLimbs = assertJsonRecordArray(
        commitment.commitmentLimbs,
        `${objectPath}.commitmentLimbs`,
    ).map((commitmentLimb, commitmentLimbIndex) => {
        const commitmentModulusIndex = assertNonNegativeSafeInteger(
            commitmentLimb.commitmentModulusIndex,
            `${objectPath}.commitmentLimbs.${String(commitmentLimbIndex)}.commitmentModulusIndex`,
        );
        const modulus = assertPositiveSafeInteger(
            commitmentLimb.modulus,
            `${objectPath}.commitmentLimbs.${String(commitmentLimbIndex)}.modulus`,
        );
        if (!Array.isArray(commitmentLimb.rows)) {
            throw new TypeError(
                `${objectPath}.commitmentLimbs.${String(commitmentLimbIndex)}.rows must be an array.`,
            );
        }

        return {
            commitmentModulusIndex,
            modulus,
            rows: (commitmentLimb.rows as readonly unknown[]).map(
                (rowValue, rowIndex) => {
                    if (!Array.isArray(rowValue)) {
                        throw new TypeError(
                            `${objectPath}.commitmentLimbs.${String(commitmentLimbIndex)}.rows.${String(rowIndex)} must be an array.`,
                        );
                    }
                    if (rowValue.length !== ringDegree) {
                        throw new Error(
                            `${objectPath}.commitmentLimbs.${String(commitmentLimbIndex)}.rows.${String(rowIndex)} length must match ringDegree.`,
                        );
                    }

                    return rowValue.map((coefficient, coefficientIndex) => {
                        if (
                            typeof coefficient !== 'number' ||
                            !Number.isSafeInteger(coefficient) ||
                            coefficient < 0 ||
                            coefficient >= modulus
                        ) {
                            throw new TypeError(
                                `${objectPath}.commitmentLimbs.${String(commitmentLimbIndex)}.rows.${String(rowIndex)}.${String(coefficientIndex)} must be a residue below the commitment modulus.`,
                            );
                        }

                        return coefficient;
                    });
                },
            ),
        };
    });
    if (commitmentLimbs.length === 0) {
        throw new Error(`${objectPath}.commitmentLimbs must be non-empty.`);
    }

    return {
        sourceRnsLimbIndex,
        sourceMessageModulus,
        shamirCoefficientIndex,
        ringDegree,
        commitmentLimbs,
    };
};

const parseMaterialSet = (
    setupContext: CollectiveBgvSetupContext,
    vssCoefficientCommitmentMaterial:
        | SetupPackageVssCoefficientCommitmentMaterialSet
        | JsonRecord,
): SetupPackageVssCoefficientCommitmentMaterialSet => {
    const materialSet = assertJsonRecord(
        vssCoefficientCommitmentMaterial,
        'vssCoefficientCommitmentMaterial',
    );
    assertObjectType(
        materialSet,
        'vssCoefficientCommitmentMaterial',
        'VssCoefficientCommitmentMaterialSet',
    );
    assertContextMatches(
        setupContext,
        materialSet,
        'vssCoefficientCommitmentMaterial',
    );
    if (materialSet.commitmentProfileId !== setupCommitmentProfileId) {
        throw new Error(
            `vssCoefficientCommitmentMaterial.commitmentProfileId must be ${setupCommitmentProfileId}.`,
        );
    }
    assertProtocolHash(
        materialSet.publicMatrixSeedHash,
        'vssCoefficientCommitmentMaterial.publicMatrixSeedHash',
    );
    assertProtocolHash(
        materialSet.vssCoefficientCommitmentRoot,
        'vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot',
    );
    assertProtocolHash(
        materialSet.vssCoefficientCommitmentMaterialRoot,
        'vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot',
    );
    assertPositiveSafeInteger(
        materialSet.participantCount,
        'vssCoefficientCommitmentMaterial.participantCount',
    );
    assertPositiveSafeInteger(
        materialSet.thresholdDegree,
        'vssCoefficientCommitmentMaterial.thresholdDegree',
    );
    assertPositiveSafeInteger(
        materialSet.rnsLimbCount,
        'vssCoefficientCommitmentMaterial.rnsLimbCount',
    );
    assertPositiveSafeInteger(
        materialSet.ringDegree,
        'vssCoefficientCommitmentMaterial.ringDegree',
    );
    if (
        materialSet.materialEncoding === 'full-public-setup-commitment-values'
    ) {
        const coefficientCommitments = assertJsonRecordArray(
            materialSet.coefficientCommitments,
            'vssCoefficientCommitmentMaterial.coefficientCommitments',
        );
        if (materialSet.materialRecordCount !== coefficientCommitments.length) {
            throw new Error(
                'vssCoefficientCommitmentMaterial.materialRecordCount must match coefficientCommitments length.',
            );
        }
    } else if (
        materialSet.materialEncoding ===
        'binary-chunked-full-public-setup-commitment-values'
    ) {
        if (materialSet.coefficientCommitments !== undefined) {
            throw new Error(
                'binary-chunked VSS material must not embed coefficientCommitments.',
            );
        }
        assertJsonRecord(
            materialSet.transport,
            'vssCoefficientCommitmentMaterial.transport',
        );
    } else {
        throw new Error(
            'vssCoefficientCommitmentMaterial.materialEncoding must be embedded full public values or binary-chunked full public values.',
        );
    }

    return materialSet as unknown as SetupPackageVssCoefficientCommitmentMaterialSet;
};

const parseMaterialRecordsByCoordinate = (
    materialSet: VssCoefficientCommitmentMaterialSet,
    sourceTrusteeByPosition: ReadonlyMap<number, SourceTrusteeCoordinate>,
    commitmentRecordByCoordinate: ReadonlyMap<
        string,
        VssCoefficientCommitmentRecord
    >,
): ReadonlyMap<string, ParsedCommitmentMaterial> => {
    const expectedRecordCount =
        materialSet.participantCount *
        materialSet.rnsLimbCount *
        materialSet.thresholdDegree;
    if (materialSet.coefficientCommitments.length !== expectedRecordCount) {
        throw new Error(
            'vssCoefficientCommitmentMaterial must cover every source trustee, RNS limb, and Shamir coefficient.',
        );
    }
    const materialByCoordinate = new Map<string, ParsedCommitmentMaterial>();
    materialSet.coefficientCommitments.forEach(
        (materialRecord, materialRecordIndex) => {
            const objectPath = `vssCoefficientCommitmentMaterial.coefficientCommitments.${String(materialRecordIndex)}`;
            assertObjectType(
                materialRecord,
                objectPath,
                'VssCoefficientCommitmentMaterial',
            );
            const sourceCoordinate = sourceTrusteeByPosition.get(
                materialRecord.sourceTrusteeRosterPosition,
            );
            if (sourceCoordinate === undefined) {
                throw new Error(
                    `${objectPath}.sourceTrusteeRosterPosition must identify a published source trustee record.`,
                );
            }
            if (
                materialRecord.sourceTrusteeIdentity !==
                sourceCoordinate.sourceTrusteeIdentity
            ) {
                throw new Error(
                    `${objectPath}.sourceTrusteeIdentity must match the published source trustee record.`,
                );
            }
            const commitment = parseCommitmentValue(
                materialRecord.commitment,
                `${objectPath}.commitment`,
            );
            if (commitment.ringDegree !== materialSet.ringDegree) {
                throw new Error(
                    `${objectPath}.commitment.ringDegree must match the material set ringDegree.`,
                );
            }
            if (
                commitment.sourceRnsLimbIndex !== materialRecord.rnsLimbIndex ||
                commitment.sourceMessageModulus !== materialRecord.rnsPrime ||
                commitment.shamirCoefficientIndex !==
                    materialRecord.shamirCoefficientIndex
            ) {
                throw new Error(
                    `${objectPath}.commitment coordinate must match the material record coordinate.`,
                );
            }
            const recomputedCommitmentRoot = deriveProtocolHash(
                'SetupCommitmentRoot',
                setupCommitmentRootPayload(commitment),
            );
            if (materialRecord.commitmentRoot !== recomputedCommitmentRoot) {
                throw new Error(
                    `${objectPath}.commitmentRoot must match the canonical setup commitment root.`,
                );
            }
            const coordinateKey = materialCoordinateKey({
                sourceTrusteeRosterPosition:
                    materialRecord.sourceTrusteeRosterPosition,
                rnsLimbIndex: materialRecord.rnsLimbIndex,
                shamirCoefficientIndex: materialRecord.shamirCoefficientIndex,
            });
            if (materialByCoordinate.has(coordinateKey)) {
                throw new Error(
                    'vssCoefficientCommitmentMaterial must not contain duplicate source/limb/coefficient records.',
                );
            }
            const publicCommitmentRecord =
                commitmentRecordByCoordinate.get(coordinateKey);
            if (publicCommitmentRecord === undefined) {
                throw new Error(
                    `${objectPath} must have a matching published VSS coefficient commitment record.`,
                );
            }
            if (
                publicCommitmentRecord.commitmentRoot !==
                    materialRecord.commitmentRoot ||
                publicCommitmentRecord.rnsPrime !== materialRecord.rnsPrime
            ) {
                throw new Error(
                    `${objectPath} must match the published VSS coefficient commitment root and RNS prime.`,
                );
            }
            materialByCoordinate.set(coordinateKey, {
                record: materialRecord,
                commitment,
            });
        },
    );

    return materialByCoordinate;
};

const buildPublicCommitmentRecordIndex = (
    sourceTrusteeRecords: readonly VssSourceTrusteeCoefficientCommitmentRecord[],
): ReadonlyMap<string, VssCoefficientCommitmentRecord> => {
    const recordsByCoordinate = new Map<
        string,
        VssCoefficientCommitmentRecord
    >();
    sourceTrusteeRecords.forEach((sourceTrusteeRecord) => {
        sourceTrusteeRecord.coefficientCommitments.forEach(
            (commitmentRecord) => {
                const coordinateKey = commitmentRecordCoordinateKey(
                    sourceTrusteeRecord.sourceTrusteeRosterPosition,
                    commitmentRecord,
                );
                if (recordsByCoordinate.has(coordinateKey)) {
                    throw new Error(
                        'vssCoefficientCommitments must not contain duplicate source/limb/coefficient records.',
                    );
                }
                recordsByCoordinate.set(coordinateKey, commitmentRecord);
            },
        );
    });

    return recordsByCoordinate;
};

const zeroRows = (rowCount: number, ringDegree: number): bigint[][] =>
    Array.from({ length: rowCount }, () =>
        Array.from({ length: ringDegree }, () => 0n),
    );

const addScaledRows = (
    targetRows: bigint[][],
    sourceRows: readonly (readonly number[])[],
    scalar: bigint,
    modulus: number,
): void => {
    if (sourceRows.length !== targetRows.length) {
        throw new Error('commitment rows must use a consistent row count.');
    }
    const modulusWide = BigInt(modulus);
    sourceRows.forEach((sourceRow, rowIndex) => {
        const targetRow = targetRows[rowIndex];
        if (sourceRow.length !== targetRow?.length) {
            throw new Error(
                'commitment rows must use a consistent ring degree.',
            );
        }
        sourceRow.forEach((coefficient, coefficientIndex) => {
            targetRow[coefficientIndex] =
                ((targetRow[coefficientIndex] ?? 0n) +
                    BigInt(coefficient) * scalar) %
                modulusWide;
        });
    });
};

const rowHashes = (rows: readonly (readonly number[])[]): readonly string[] =>
    rows.map((row) =>
        coefficientVectorHash512(
            row,
            'sealed-lattice-threshold-share-commitment/row-coefficients-v1',
        ),
    );

const shamirCoefficientScalars = (
    trusteePoint: number,
    thresholdDegree: number,
): readonly bigint[] => {
    const scalars: bigint[] = [];
    let scalar = 1n;
    for (
        let shamirCoefficientIndex = 0;
        shamirCoefficientIndex < thresholdDegree;
        shamirCoefficientIndex += 1
    ) {
        scalars.push(scalar);
        scalar *= BigInt(trusteePoint);
    }

    return scalars;
};

const aggregateThresholdCommitmentLimb = (
    setupContext: CollectiveBgvSetupContext,
    publicMatrixSeedHash: ProtocolHash,
    sourceTrusteeRecords: readonly VssSourceTrusteeCoefficientCommitmentRecord[],
    materialByCoordinate: ReadonlyMap<string, ParsedCommitmentMaterial>,
    recipientIdentity: string,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
    rnsPrime: number,
    thresholdDegree: number,
    ringDegree: number,
    trusteePoint: number,
): ThresholdShareCommitmentLimb => {
    if (trusteePoint >= rnsPrime) {
        throw new Error(
            'recipient trustee points must be nonzero and collision-free in every Q_share field.',
        );
    }

    const firstMaterial = materialByCoordinate.get(
        materialCoordinateKey({
            sourceTrusteeRosterPosition: 0,
            rnsLimbIndex,
            shamirCoefficientIndex: 0,
        }),
    );
    if (firstMaterial === undefined) {
        throw new Error(
            'vssCoefficientCommitmentMaterial must include the first commitment coordinate.',
        );
    }
    const aggregateLimbs = firstMaterial.commitment.commitmentLimbs.map(
        (commitmentLimb) => ({
            commitmentModulusIndex: commitmentLimb.commitmentModulusIndex,
            modulus: commitmentLimb.modulus,
            rows: zeroRows(commitmentLimb.rows.length, ringDegree),
        }),
    );
    const coefficientCommitmentRoots: ProtocolHash[] = [];
    const coefficientScalars = shamirCoefficientScalars(
        trusteePoint,
        thresholdDegree,
    );

    sourceTrusteeRecords.forEach((sourceTrusteeRecord) => {
        for (
            let shamirCoefficientIndex = 0;
            shamirCoefficientIndex < thresholdDegree;
            shamirCoefficientIndex += 1
        ) {
            const material = materialByCoordinate.get(
                materialCoordinateKey({
                    sourceTrusteeRosterPosition:
                        sourceTrusteeRecord.sourceTrusteeRosterPosition,
                    rnsLimbIndex,
                    shamirCoefficientIndex,
                }),
            );
            if (material === undefined) {
                throw new Error(
                    'vssCoefficientCommitmentMaterial must cover every threshold-share source coordinate.',
                );
            }
            coefficientCommitmentRoots.push(material.record.commitmentRoot);
            material.commitment.commitmentLimbs.forEach((commitmentLimb) => {
                const aggregateLimb = aggregateLimbs.find(
                    (candidateLimb) =>
                        candidateLimb.commitmentModulusIndex ===
                        commitmentLimb.commitmentModulusIndex,
                );
                if (aggregateLimb === undefined) {
                    throw new Error(
                        'commitment limbs must use a consistent commitment modulus basis.',
                    );
                }
                if (aggregateLimb.modulus !== commitmentLimb.modulus) {
                    throw new Error(
                        'commitment limbs must use consistent modulus values.',
                    );
                }
                const scalar =
                    (coefficientScalars[shamirCoefficientIndex] ?? 0n) %
                    BigInt(commitmentLimb.modulus);
                addScaledRows(
                    aggregateLimb.rows,
                    commitmentLimb.rows,
                    scalar,
                    commitmentLimb.modulus,
                );
            });
        }
    });

    const commitmentLimbs = aggregateLimbs.map((aggregateLimb) => ({
        commitmentModulusIndex: aggregateLimb.commitmentModulusIndex,
        modulus: aggregateLimb.modulus,
        rowCoefficientHash512: rowHashes(
            aggregateLimb.rows.map((row) =>
                row.map((coefficient) => Number(coefficient)),
            ),
        ),
    }));
    const limbWithoutRoot = {
        objectType: 'ThresholdShareCommitment',
        objectVersion: 1,
        setupProfileId,
        ...setupContextFields(setupContext),
        commitmentProfileId: setupCommitmentProfileId,
        derivationRule: thresholdShareDerivationRule,
        publicMatrixSeedHash,
        recipientIdentity,
        recipientRosterPosition,
        trusteePoint,
        rnsLimbIndex,
        rnsPrime,
        ringDegree,
        shamirCoefficientScalarsDecimal: coefficientScalars.map((scalar) =>
            scalar.toString(),
        ),
        coefficientCommitmentRoots,
        commitmentLimbs,
    } as const satisfies Omit<
        ThresholdShareCommitmentLimb,
        'thresholdShareCommitmentRoot'
    >;

    return {
        ...limbWithoutRoot,
        thresholdShareCommitmentRoot: deriveProtocolHash(
            'ThresholdShareCommitmentRoot',
            limbWithoutRoot,
        ),
    };
};

const deriveRecipientCommitment = (
    setupContext: CollectiveBgvSetupContext,
    publicMatrixSeedHash: ProtocolHash,
    sourceTrusteeRecords: readonly VssSourceTrusteeCoefficientCommitmentRecord[],
    materialByCoordinate: ReadonlyMap<string, ParsedCommitmentMaterial>,
    recipientRecord: VssSourceTrusteeCoefficientCommitmentRecord,
    rnsPrimes: readonly number[],
    thresholdDegree: number,
    ringDegree: number,
): ThresholdShareCommitmentRecipient => {
    // Shamir evaluation point = rosterPosition + 1 (point 0 holds the secret); scalars [1, x, x^2, ...] evaluate the committed polynomial at x via the additive homomorphism, so points must be nonzero and distinct mod every Q_share prime.
    const trusteePoint = recipientRecord.sourceTrusteeRosterPosition + 1;
    const recipientWithoutRoot = {
        objectType: 'TrusteeThresholdShareCommitments',
        objectVersion: 1,
        setupProfileId,
        ...setupContextFields(setupContext),
        commitmentProfileId: setupCommitmentProfileId,
        derivationRule: thresholdShareDerivationRule,
        publicMatrixSeedHash,
        recipientIdentity: recipientRecord.sourceTrusteeIdentity,
        recipientRosterPosition: recipientRecord.sourceTrusteeRosterPosition,
        trusteePoint,
        ringDegree,
        limbCommitments: rnsPrimes.map((rnsPrime, rnsLimbIndex) =>
            aggregateThresholdCommitmentLimb(
                setupContext,
                publicMatrixSeedHash,
                sourceTrusteeRecords,
                materialByCoordinate,
                recipientRecord.sourceTrusteeIdentity,
                recipientRecord.sourceTrusteeRosterPosition,
                rnsLimbIndex,
                rnsPrime,
                thresholdDegree,
                ringDegree,
                trusteePoint,
            ),
        ),
    } as const satisfies Omit<
        ThresholdShareCommitmentRecipient,
        'recipientCommitmentRoot'
    >;

    return {
        ...recipientWithoutRoot,
        recipientCommitmentRoot: deriveProtocolHash(
            'ThresholdShareCommitmentRoot',
            recipientWithoutRoot,
        ),
    };
};

const rnsPrimesFromMaterial = (
    materialByCoordinate: ReadonlyMap<string, ParsedCommitmentMaterial>,
    rnsLimbCount: number,
): readonly number[] =>
    Array.from({ length: rnsLimbCount }, (_unused, rnsLimbIndex) => {
        const material = materialByCoordinate.get(
            materialCoordinateKey({
                sourceTrusteeRosterPosition: 0,
                rnsLimbIndex,
                shamirCoefficientIndex: 0,
            }),
        );
        if (material === undefined) {
            throw new Error(
                'vssCoefficientCommitmentMaterial must include every RNS limb.',
            );
        }

        return material.record.rnsPrime;
    });

export const deriveThresholdShareCommitments = (
    input: ThresholdShareCommitmentsInput,
): ThresholdShareCommitmentSet => {
    for (const fieldName of contextFieldNames) {
        assertNonEmptyString(
            input.setupContext[fieldName],
            `setupContext.${fieldName}`,
        );
    }
    assertObjectType(
        input.vssCoefficientCommitments,
        'vssCoefficientCommitments',
        'VssCoefficientCommitmentSet',
    );
    assertContextMatches(
        input.setupContext,
        input.vssCoefficientCommitments,
        'vssCoefficientCommitments',
    );
    const sourceTrusteeRecords = sortedSourceTrusteeRecords(
        input.vssCoefficientCommitments,
    );
    const sourceTrusteeByPosition = new Map(
        sourceTrusteeRecords.map((sourceTrusteeRecord) => [
            sourceTrusteeRecord.sourceTrusteeRosterPosition,
            {
                sourceTrusteeIdentity:
                    sourceTrusteeRecord.sourceTrusteeIdentity,
                sourceTrusteeRosterPosition:
                    sourceTrusteeRecord.sourceTrusteeRosterPosition,
                sourceTrusteeCommitmentRoot:
                    sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
            },
        ]),
    );
    const publicRecordByCoordinate =
        buildPublicCommitmentRecordIndex(sourceTrusteeRecords);
    const materialSet = parseMaterialSet(
        input.setupContext,
        input.vssCoefficientCommitmentMaterial,
    );
    if (
        materialSet.publicMatrixSeedHash !==
        input.vssCoefficientCommitments.publicMatrixSeedHash
    ) {
        throw new Error(
            'vssCoefficientCommitmentMaterial.publicMatrixSeedHash must match vssCoefficientCommitments.publicMatrixSeedHash.',
        );
    }
    if (
        materialSet.vssCoefficientCommitmentRoot !==
        input.vssCoefficientCommitments.vssCoefficientCommitmentRoot
    ) {
        throw new Error(
            'vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot must match vssCoefficientCommitments.vssCoefficientCommitmentRoot.',
        );
    }
    if (materialSet.participantCount !== sourceTrusteeRecords.length) {
        throw new Error(
            'vssCoefficientCommitmentMaterial.participantCount must match the source trustee record count.',
        );
    }
    const coefficientCommitments =
        materialSet.materialEncoding ===
        'binary-chunked-full-public-setup-commitment-values'
            ? materialRecordsFromTransportedVssCoefficientCommitmentMaterial({
                  setupContext: input.setupContext,
                  vssCoefficientCommitments: input.vssCoefficientCommitments,
                  materialSet: materialSet,
                  transportedVssCoefficientCommitmentMaterial:
                      input.transportedVssCoefficientCommitmentMaterial ??
                      (() => {
                          throw new Error(
                              'transportedVssCoefficientCommitmentMaterial is required for binary-chunked VSS material.',
                          );
                      })(),
              })
            : materialSet.coefficientCommitments;
    const materialSetWithRecords = {
        ...materialSet,
        coefficientCommitments,
    } as VssCoefficientCommitmentMaterialSet;
    const materialByCoordinate = parseMaterialRecordsByCoordinate(
        materialSetWithRecords,
        sourceTrusteeByPosition,
        publicRecordByCoordinate,
    );
    const rnsPrimes = rnsPrimesFromMaterial(
        materialByCoordinate,
        materialSet.rnsLimbCount,
    );
    const recipientRecords = sourceTrusteeRecords.map((recipientRecord) =>
        deriveRecipientCommitment(
            input.setupContext,
            input.vssCoefficientCommitments.publicMatrixSeedHash,
            sourceTrusteeRecords,
            materialByCoordinate,
            recipientRecord,
            rnsPrimes,
            materialSet.thresholdDegree,
            materialSet.ringDegree,
        ),
    );

    const thresholdShareCommitmentsWithoutRoot = {
        objectType: 'ThresholdShareCommitmentSet',
        objectVersion: 1,
        setupProfileId,
        ...setupContextFields(input.setupContext),
        commitmentProfileId: setupCommitmentProfileId,
        derivationRule: thresholdShareDerivationRule,
        publicMatrixSeedHash:
            input.vssCoefficientCommitments.publicMatrixSeedHash,
        participantCount: materialSet.participantCount,
        thresholdDegree: materialSet.thresholdDegree,
        rnsLimbCount: materialSet.rnsLimbCount,
        ringDegree: materialSet.ringDegree,
        recipientRecords,
    } as const satisfies Omit<
        ThresholdShareCommitmentSet,
        'thresholdShareCommitmentRoot'
    >;

    return {
        ...thresholdShareCommitmentsWithoutRoot,
        thresholdShareCommitmentRoot: deriveProtocolHash(
            'ThresholdShareCommitmentRoot',
            thresholdShareCommitmentsWithoutRoot,
        ),
    };
};
