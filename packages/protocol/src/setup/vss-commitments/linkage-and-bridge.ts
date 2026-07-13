import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type {
    SetupCommitmentValue,
    VssCoefficientCommitmentMaterialSet,
    VssCoefficientCommitmentSet,
} from '../vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    setupContextFields,
    type VssCommittedMaterialCommitmentValue,
    type VssPublicCoefficientCommitmentSet,
    type VssGeneratedCanonicalProofMaterial,
} from './commitment-sets.js';

export type VssShareLinkageStatement = {
    readonly objectType: string;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly qShareRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly recipientShareCommitmentRoot: ProtocolHash;
    readonly aggregateThresholdCommitmentRoot: ProtocolHash;
    readonly sourceStatementRecords: readonly Record<string, unknown>[];
    readonly statementRoot: ProtocolHash;
};

export const vssShareLinkageProofFamily = 'vss-share-linkage';

export type GeneratedVssCanonicalProofMaterial = Readonly<{
    readonly proofMaterialRoot: ProtocolHash;
    readonly descriptorBytes: Uint8Array;
}>;

export type VssShareLinkageProofMaterialBuild<
    ProofMaterialSet extends Record<string, unknown> = Record<string, unknown>,
> = Readonly<{
    readonly proofMaterialSet: ProofMaterialSet;
    readonly canonicalProofMaterials: readonly GeneratedVssCanonicalProofMaterial[];
}>;

// Same-secret bridge constants. These are bound into the bridge
// statement (and thus its recomputed root), so they must match the kernel
// verifier byte for byte.
const sameSecretRelation =
    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs';
const sameSecretBridgeRelation =
    'public constant coefficient commitments bind to the same signed ternary trustee secret as the source VSS constant commitments across Q_share';
const sameSecretBridgeIntegerSupport =
    'the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound source and public commitment over Q_share';
const sameSecretBridgeSignedRepresentativeConvention =
    'coefficients are interpreted as signed representatives before reduction into each Q_share RNS prime';
const vssPublicCommitmentBinaryFormat =
    'sealed-lattice-vss-public-commitment-binary';
const sameSecretBridgeQShareLimbOrder =
    'target constant roots are ordered by contiguous Q_share rnsLimbIndex values starting at zero and bind the listed Q_share prime';
export const sameSecretBridgeProofFamily = 'same-secret-bridge';

export type VssSameSecretBridgeTargetConstantRoot = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
};

export type VssSameSecretBridgeTargetConstantCommitment = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

export type VssSameSecretBridgeSourceConstantCommitment = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: 0;
    readonly commitment: SetupCommitmentValue;
};

export type VssSameSecretBridgeStatement = {
    readonly objectType: 'VssSameSecretBridgeStatement';
    readonly proofFamily: typeof sameSecretBridgeProofFamily;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly dataBasisRelation: string;
    readonly integerSupport: string;
    readonly signedRepresentativeConvention: string;
    readonly vssPublicCommitmentEncoding: string;
    readonly qShareLimbOrder: string;
    readonly sourceConstantCoefficientCommitments: readonly VssSameSecretBridgeSourceConstantCommitment[];
    readonly targetConstantCoefficientCommitmentRoots: readonly VssSameSecretBridgeTargetConstantRoot[];
    readonly targetConstantCoefficientCommitments: readonly VssSameSecretBridgeTargetConstantCommitment[];
    readonly relation: string;
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
};

export type VssSameSecretBridgeStatementSet = {
    readonly objectType: 'VssSameSecretBridgeStatementSet';
    readonly proofFamily: typeof sameSecretBridgeProofFamily;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly qShareRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly integerSupport: string;
    readonly signedRepresentativeConvention: string;
    readonly vssPublicCommitmentEncoding: string;
    readonly qShareLimbOrder: string;
    readonly statementRecords: readonly VssSameSecretBridgeStatement[];
    readonly sameSecretBridgeStatementSetRoot: ProtocolHash;
};

// The same-secret bridge statement set ties each trustee's public constant
// commitments to the canonical source VSS commitment set across all Q_share
// limbs. The proof material then proves both commitment forms use one signed
// ternary secret.
export const createVssSameSecretBridgeStatementSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly sourceCoefficientCommitmentSet: VssCoefficientCommitmentSet;
    readonly sourceCoefficientCommitmentMaterialSet: VssCoefficientCommitmentMaterialSet;
}): VssSameSecretBridgeStatementSet => {
    const { coefficientCommitmentSet } = input;
    const { ringDegree, participantCount, rnsLimbCount, thresholdDegree } =
        coefficientCommitmentSet;
    const sourceCommitmentSet = input.sourceCoefficientCommitmentSet;
    const sourceMaterialSet = input.sourceCoefficientCommitmentMaterialSet;
    const sourceContextMatches = (
        source: Readonly<Record<string, unknown>>,
    ): boolean =>
        source.ceremonyId === input.setupContext.ceremonyId &&
        source.manifestHash === input.setupContext.manifestHash &&
        source.rosterHash === input.setupContext.rosterHash &&
        source.setupParametersHash === input.setupContext.setupParametersHash &&
        source.setupEpoch === input.setupContext.setupEpoch;
    if (
        !sourceContextMatches(sourceCommitmentSet) ||
        !sourceContextMatches(sourceMaterialSet) ||
        sourceCommitmentSet.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        sourceMaterialSet.vssCoefficientCommitmentRoot !==
            sourceCommitmentSet.vssCoefficientCommitmentRoot ||
        sourceMaterialSet.publicMatrixSeedHash !== input.publicMatrixSeedHash ||
        sourceMaterialSet.participantCount !== participantCount ||
        sourceMaterialSet.thresholdDegree !== thresholdDegree ||
        sourceMaterialSet.ringDegree !== ringDegree ||
        sourceMaterialSet.rnsLimbCount !== rnsLimbCount ||
        sourceCommitmentSet.sourceTrusteeRecords.length !== participantCount ||
        sourceMaterialSet.materialRecordCount !==
            sourceMaterialSet.coefficientCommitments.length ||
        sourceMaterialSet.materialRecordCount !==
            participantCount * rnsLimbCount * thresholdDegree
    ) {
        throw new Error(
            'Same-secret bridge source commitment material must match the canonical source commitment set and setup dimensions.',
        );
    }
    const statementRecords = coefficientCommitmentSet.sourceTrusteeRecords.map(
        (
            coefficientSourceRecord,
            sourceTrusteeRosterPosition,
        ): VssSameSecretBridgeStatement => {
            const sourceCommitmentRecord =
                sourceCommitmentSet.sourceTrusteeRecords[
                    sourceTrusteeRosterPosition
                ];
            if (
                sourceCommitmentRecord?.sourceTrusteeRosterPosition !==
                    sourceTrusteeRosterPosition ||
                sourceCommitmentRecord.sourceTrusteeIdentity !==
                    coefficientSourceRecord.sourceTrusteeIdentity ||
                sourceCommitmentRecord.publicMatrixSeedHash !==
                    input.publicMatrixSeedHash ||
                sourceCommitmentRecord.coefficientCommitments.length !==
                    rnsLimbCount * thresholdDegree ||
                sourceCommitmentRecord.coefficientCommitments.some(
                    (commitmentRecord, commitmentRecordIndex) =>
                        commitmentRecord.sourceTrusteeRosterPosition !==
                            sourceTrusteeRosterPosition ||
                        commitmentRecord.sourceTrusteeIdentity !==
                            sourceCommitmentRecord.sourceTrusteeIdentity ||
                        commitmentRecord.publicMatrixSeedHash !==
                            input.publicMatrixSeedHash ||
                        commitmentRecord.rnsLimbIndex !==
                            Math.floor(
                                commitmentRecordIndex / thresholdDegree,
                            ) ||
                        commitmentRecord.shamirCoefficientIndex !==
                            commitmentRecordIndex % thresholdDegree,
                )
            ) {
                throw new Error(
                    'Same-secret bridge requires one aligned canonical source VSS commitment record per trustee.',
                );
            }
            const sourceConstantCommitmentRecords =
                sourceCommitmentRecord.coefficientCommitments.filter(
                    (record) => record.shamirCoefficientIndex === 0,
                );
            const sourceConstantMaterialRecords =
                sourceMaterialSet.coefficientCommitments.filter(
                    (record) =>
                        record.sourceTrusteeRosterPosition ===
                            sourceTrusteeRosterPosition &&
                        record.shamirCoefficientIndex === 0,
                );
            if (
                sourceConstantCommitmentRecords.length !==
                    sourceMaterialSet.rnsLimbCount ||
                sourceConstantMaterialRecords.length !==
                    sourceConstantCommitmentRecords.length
            ) {
                throw new Error(
                    'Same-secret bridge requires one canonical source constant commitment body per source limb.',
                );
            }
            const sourceConstantCoefficientCommitments =
                sourceConstantCommitmentRecords.map(
                    (
                        publicCommitmentRecord,
                        sourceRnsLimbIndex,
                    ): VssSameSecretBridgeSourceConstantCommitment => {
                        const matchingMaterialRecords =
                            sourceConstantMaterialRecords.filter(
                                (materialRecord) =>
                                    materialRecord.rnsLimbIndex ===
                                    sourceRnsLimbIndex,
                            );
                        const [materialRecord] = matchingMaterialRecords;
                        const commitment = materialRecord?.commitment;
                        if (
                            publicCommitmentRecord.rnsLimbIndex !==
                                sourceRnsLimbIndex ||
                            publicCommitmentRecord.rnsPrime !==
                                materialRecord?.rnsPrime ||
                            publicCommitmentRecord.shamirCoefficientIndex !==
                                0 ||
                            publicCommitmentRecord.commitmentRoot !==
                                materialRecord.commitmentRoot ||
                            matchingMaterialRecords.length !== 1 ||
                            materialRecord.sourceTrusteeIdentity !==
                                sourceCommitmentRecord.sourceTrusteeIdentity ||
                            commitment?.objectType !== 'SetupCommitment' ||
                            commitment.sourceRnsLimbIndex !==
                                sourceRnsLimbIndex ||
                            commitment.sourceMessageModulus !==
                                publicCommitmentRecord.rnsPrime ||
                            commitment.shamirCoefficientIndex !== 0 ||
                            commitment.ringDegree !== ringDegree ||
                            !Array.isArray(commitment.commitmentLimbs)
                        ) {
                            throw new Error(
                                'Same-secret bridge source constant commitments must match their canonical public coordinates and roots.',
                            );
                        }

                        return {
                            rnsLimbIndex: sourceRnsLimbIndex,
                            rnsPrime: publicCommitmentRecord.rnsPrime,
                            shamirCoefficientIndex: 0,
                            commitment,
                        };
                    },
                );
            const targetConstantCoefficientCommitmentRoots: VssSameSecretBridgeTargetConstantRoot[] =
                [];
            const targetConstantCoefficientCommitments: VssSameSecretBridgeTargetConstantCommitment[] =
                [];
            for (
                let rnsLimbIndex = 0;
                rnsLimbIndex < rnsLimbCount;
                rnsLimbIndex += 1
            ) {
                const constantCoefficient =
                    coefficientSourceRecord.coefficientCommitments[
                        rnsLimbIndex * thresholdDegree
                    ];
                if (constantCoefficient === undefined) {
                    throw new Error(
                        'Same-secret bridge requires a constant coefficient commitment per target limb.',
                    );
                }
                targetConstantCoefficientCommitmentRoots.push({
                    rnsLimbIndex: constantCoefficient.rnsLimbIndex,
                    rnsPrime: constantCoefficient.rnsPrime,
                    shamirCoefficientIndex:
                        constantCoefficient.shamirCoefficientIndex,
                    coefficientCommitmentRoot:
                        constantCoefficient.coefficientCommitmentRoot,
                });
                targetConstantCoefficientCommitments.push({
                    rnsLimbIndex: constantCoefficient.rnsLimbIndex,
                    rnsPrime: constantCoefficient.rnsPrime,
                    shamirCoefficientIndex:
                        constantCoefficient.shamirCoefficientIndex,
                    commitment: constantCoefficient.commitment,
                });
            }

            const statementWithoutRoot = {
                objectType: 'VssSameSecretBridgeStatement',
                proofFamily: sameSecretBridgeProofFamily,
                ...setupContextFields(input.setupContext),
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                ringDegree,
                trusteeIdentity: coefficientSourceRecord.sourceTrusteeIdentity,
                trusteeRosterPosition: sourceTrusteeRosterPosition,
                dataBasisRelation: sameSecretRelation,
                integerSupport: sameSecretBridgeIntegerSupport,
                signedRepresentativeConvention:
                    sameSecretBridgeSignedRepresentativeConvention,
                vssPublicCommitmentEncoding: vssPublicCommitmentBinaryFormat,
                qShareLimbOrder: sameSecretBridgeQShareLimbOrder,
                sourceConstantCoefficientCommitments,
                targetConstantCoefficientCommitmentRoots,
                targetConstantCoefficientCommitments,
                relation: sameSecretBridgeRelation,
            } as const;

            return {
                ...statementWithoutRoot,
                sameSecretBridgeStatementRoot:
                    deriveCanonicalObjectHash(statementWithoutRoot),
            };
        },
    );

    const statementSetWithoutRoot = {
        objectType: 'VssSameSecretBridgeStatementSet',
        proofFamily: sameSecretBridgeProofFamily,
        ...setupContextFields(input.setupContext),
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        ringDegree,
        participantCount,
        qShareRnsLimbCount: rnsLimbCount,
        thresholdDegree,
        coefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        vssCoefficientCommitmentRoot:
            input.sourceCoefficientCommitmentSet.vssCoefficientCommitmentRoot,
        integerSupport: sameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            sameSecretBridgeSignedRepresentativeConvention,
        vssPublicCommitmentEncoding: vssPublicCommitmentBinaryFormat,
        qShareLimbOrder: sameSecretBridgeQShareLimbOrder,
        statementRecords,
    } as const;

    return {
        ...statementSetWithoutRoot,
        sameSecretBridgeStatementSetRoot: deriveCanonicalObjectHash(
            statementSetWithoutRoot,
        ),
    };
};

export type SameSecretBridgeProofContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
};

export type SameSecretBridgeSourceLinkage = {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly commitments: readonly SetupCommitmentValue[];
};

// The kernel-backed same-secret bridge proof (bound to the WASM
// `GenerateSameSecretBridgeProof` command by the SDK). Injected so the
// protocol layer assembles the witness but never runs the kernel prover.
// Target committed material carries no algebraic opening randomness. The
// opening-randomness witness belongs to the full source BDLOP commitment set;
// target seeds and context hashes regenerate the committed-material trees.
export type SameSecretBridgeProofComputer = (input: {
    readonly context: SameSecretBridgeProofContext;
    readonly ringDegree: number;
    readonly sameSecretLinkage: SameSecretBridgeSourceLinkage;
    readonly sameSecretBridge: Record<string, unknown>;
    readonly secretCoefficients: readonly number[];
    readonly negativeIndicatorCoefficients: readonly number[];
    readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
    readonly vssCommittedMaterialSeedsByBoundMessage: readonly string[];
    readonly vssCommittedMaterialContextHashesByBoundMessage: readonly string[];
    readonly proofRandomnessSeedHex: string;
    readonly proofRandomnessNonceHex: string;
}) => Promise<VssGeneratedCanonicalProofMaterial>;

type VssSameSecretBridgeProofRecord = {
    readonly objectType: 'VssSameSecretBridgeProofRecord';
    readonly proofFamily: typeof sameSecretBridgeProofFamily;
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
    readonly sameSecretBridgeProofRecordRoot: ProtocolHash;
};

export type VssSameSecretBridgeProofMaterialSet = {
    readonly objectType: 'VssSameSecretBridgeProofMaterialSet';
    readonly proofFamily: typeof sameSecretBridgeProofFamily;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly qShareRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly sameSecretBridgeStatementSetRoot: ProtocolHash;
    readonly proofRecords: readonly VssSameSecretBridgeProofRecord[];
    readonly proofMaterialSetRoot?: ProtocolHash;
};

export type VssSameSecretBridgeProofMaterialBuild<
    ProofMaterialSet extends VssSameSecretBridgeProofMaterialSet =
        VssSameSecretBridgeProofMaterialSet,
> = Readonly<{
    readonly proofMaterialSet: ProofMaterialSet;
    readonly canonicalProofMaterials: readonly GeneratedVssCanonicalProofMaterial[];
}>;
