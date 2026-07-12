import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    canonicalGeneratedSetupProofMaterialDescriptor,
    type CanonicalGeneratedSetupProofMaterial,
} from '../setup-proof-material-transport.js';
import type {
    SetupCommitmentValue,
    VssCoefficientCommitmentMaterialSet,
    VssCoefficientCommitmentSet,
} from '../vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    setupContextFields,
    type VssCommittedMaterialCommitmentValue,
    type VssPublicAggregateThresholdCommitmentSet,
    type VssPublicCoefficientCommitmentSet,
    type VssPublicCoefficientCredential,
    type VssPublicRecipientShareCommitmentSet,
    type VssPublicRecipientShareCredential,
    type VssGeneratedCanonicalProofMaterial,
    type VssShareLinkageProofComputer,
} from './commitment-sets.js';

export type VssShareLinkageStatement = {
    readonly objectType: string;
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly recipientShareCommitmentRoot: ProtocolHash;
    readonly aggregateThresholdCommitmentRoot: ProtocolHash;
    readonly sourceStatementRecords: readonly Record<string, unknown>[];
    readonly statementRoot: ProtocolHash;
};

// The share-linkage statement binds the three commitment set roots and,
// per source trustee, the opening roots the share-linkage proof covers. It is
// pure root assembly over the already-built sets: the accepted-setup verifier
// recomputes every root it references, so acceptance never trusts this object,
// only the roots it recomputes and the proof that binds them.
export const createVssShareLinkageStatement = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: VssPublicAggregateThresholdCommitmentSet;
}): VssShareLinkageStatement => {
    const {
        coefficientCommitmentSet,
        recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
    } = input;
    const targetRnsLimbCount = recipientShareCommitmentSet.rnsLimbCount;
    const { ringDegree, participantCount, thresholdDegree } =
        coefficientCommitmentSet;
    const coefficientOpeningRootCount = targetRnsLimbCount * thresholdDegree;
    const sourceStatementRecords =
        coefficientCommitmentSet.sourceTrusteeRecords.map(
            (coefficientSourceRecord, sourceRecordIndex) => {
                const recipientSourceRecord =
                    recipientShareCommitmentSet.sourceTrusteeRecords[
                        sourceRecordIndex
                    ];
                if (recipientSourceRecord === undefined) {
                    throw new Error(
                        'VSS share linkage statement inputs must contain matching source records.',
                    );
                }
                const coefficientOpeningRoots =
                    coefficientSourceRecord.coefficientCommitments
                        .slice(0, coefficientOpeningRootCount)
                        .map(
                            (coefficientCommitment) =>
                                coefficientCommitment.coefficientOpeningRoot,
                        );
                const recipientShareOpeningRoots =
                    recipientSourceRecord.recipientShareCommitments.map(
                        (recipientShareCommitment) =>
                            recipientShareCommitment.shareOpeningRoot,
                    );
                const sourceStatementWithoutRoot = {
                    objectType: 'VssShareLinkageSourceStatement',
                    ...setupContextFields(input.setupContext),
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    targetBasisHash: input.targetBasisHash,
                    sourceTrusteeIdentity:
                        coefficientSourceRecord.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        coefficientSourceRecord.sourceTrusteeRosterPosition,
                    ringDegree,
                    participantCount,
                    targetRnsLimbCount,
                    thresholdDegree,
                    coefficientCommitmentRoot:
                        coefficientCommitmentSet.coefficientCommitmentRoot,
                    sourceCoefficientCommitmentRoot:
                        coefficientSourceRecord.sourceCoefficientCommitmentRoot,
                    sourceRecipientShareCommitmentRoot:
                        recipientSourceRecord.sourceRecipientShareCommitmentRoot,
                    coefficientOpeningRoots,
                    recipientShareOpeningRoots,
                    aggregateThresholdCommitmentRoot:
                        aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
                };

                return {
                    ...sourceStatementWithoutRoot,
                    sourceStatementRoot: deriveCanonicalObjectHash(
                        sourceStatementWithoutRoot,
                    ),
                };
            },
        );

    const statementWithoutRoot = {
        objectType: 'VssShareLinkageStatement',
        ...setupContextFields(input.setupContext),
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        targetBasisHash: input.targetBasisHash,
        ringDegree,
        participantCount,
        targetRnsLimbCount,
        thresholdDegree,
        coefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        recipientShareCommitmentRoot:
            recipientShareCommitmentSet.recipientShareCommitmentRoot,
        aggregateThresholdCommitmentRoot:
            aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
        sourceStatementRecords,
    };

    return {
        ...statementWithoutRoot,
        statementRoot: deriveCanonicalObjectHash(statementWithoutRoot),
    };
};

export const vssShareLinkageProofFamily = 'vss-share-linkage';

const canonicalSetupProofMaterialEncoding = 'binary-chunked-proof-bytes';
const protocolHashPattern = /^[0-9a-f]{128}$/u;

export type GeneratedVssCanonicalProofMaterial = Readonly<{
    readonly proofMaterialRoot: ProtocolHash;
    readonly descriptorBytes: Uint8Array;
}>;

const validatedGeneratedVssCanonicalProofMaterial = (
    proofFamily: string,
    generatedProof: VssGeneratedCanonicalProofMaterial,
): GeneratedVssCanonicalProofMaterial => {
    if (
        generatedProof.proofBytesEncoding !==
        canonicalSetupProofMaterialEncoding
    ) {
        throw new TypeError(
            `${proofFamily} proof bytes must use the canonical binary chunked encoding.`,
        );
    }
    if (!protocolHashPattern.test(generatedProof.proofBytesHash)) {
        throw new TypeError(
            `${proofFamily} proofBytesHash must be a protocol hash.`,
        );
    }
    if (!protocolHashPattern.test(generatedProof.proofMaterialRoot)) {
        throw new TypeError(
            `${proofFamily} proofMaterialRoot must be a protocol hash.`,
        );
    }
    const expectedProofMaterialRoot = deriveCanonicalObjectHash({
        objectType: 'SetupProofMaterialReference',
        proofFamily,
        proofBytesHash: generatedProof.proofBytesHash,
    });
    if (generatedProof.proofMaterialRoot !== expectedProofMaterialRoot) {
        throw new Error(
            `${proofFamily} proofMaterialRoot must bind its proof family and proofBytesHash.`,
        );
    }

    const canonicalMaterial: CanonicalGeneratedSetupProofMaterial =
        generatedProof.canonicalMaterial;

    return {
        proofMaterialRoot: generatedProof.proofMaterialRoot,
        descriptorBytes:
            canonicalGeneratedSetupProofMaterialDescriptor(canonicalMaterial),
    };
};

// Fresh prover blinding randomness per proof record. The share-linkage proof is
// zero-knowledge, so this is independent per (source trustee, proof record) and
// binds nothing the verifier recomputes.
type VssShareLinkageProofRandomnessProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
    readonly proofRecordIndex: number;
}) => { readonly seedHex: string; readonly nonceHex: string };

type VssShareLinkageProofMaterialSetInput = {
    readonly statement: VssShareLinkageStatement;
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly coefficientCredentials: readonly VssPublicCoefficientCredential[];
    readonly recipientShareCredentials: readonly VssPublicRecipientShareCredential[];
    readonly shareLinkageProofRandomness: VssShareLinkageProofRandomnessProvider;
    readonly generateVssShareLinkageProof: VssShareLinkageProofComputer;
};

export type VssShareLinkageProofMaterialBuild<
    ProofMaterialSet extends Record<string, unknown> = Record<string, unknown>,
> = Readonly<{
    readonly proofMaterialSet: ProofMaterialSet;
    readonly canonicalProofMaterials: readonly GeneratedVssCanonicalProofMaterial[];
}>;

const vssShareLinkageCoordinateKey = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): string =>
    `${String(sourceTrusteeRosterPosition)}:${String(rnsLimbIndex)}:${String(shamirCoefficientIndex)}`;

const vssPublicRecipientShareCoordinateKey = (
    sourceTrusteeRosterPosition: number,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): string =>
    `${String(sourceTrusteeRosterPosition)}:${String(recipientRosterPosition)}:${String(rnsLimbIndex)}`;

// The share-linkage proof material set: one succinct proof per source trustee
// per target RNS limb, each covering that source's Shamir share to every
// recipient at that limb. The verifier recomputes the covered opening roots and
// the statement root and checks the proof, so this builder only assembles the
// witness the injected prover consumes and binds the proof bytes.
export function createVssShareLinkageProofMaterialSet(
    input: VssShareLinkageProofMaterialSetInput & {
        readonly deriveProofMaterialSetRoot?: true;
    },
): Promise<
    VssShareLinkageProofMaterialBuild<
        Record<string, unknown> & {
            readonly proofMaterialSetRoot: ProtocolHash;
        }
    >
>;
export function createVssShareLinkageProofMaterialSet(
    input: VssShareLinkageProofMaterialSetInput & {
        readonly deriveProofMaterialSetRoot: false;
    },
): Promise<VssShareLinkageProofMaterialBuild>;
export async function createVssShareLinkageProofMaterialSet(
    input: VssShareLinkageProofMaterialSetInput & {
        readonly deriveProofMaterialSetRoot?: boolean;
    },
): Promise<VssShareLinkageProofMaterialBuild> {
    const { statement, coefficientCommitmentSet, recipientShareCommitmentSet } =
        input;
    const {
        participantCount,
        targetRnsLimbCount,
        thresholdDegree,
        ringDegree,
    } = statement;
    const recipientLimbCount = recipientShareCommitmentSet.rnsLimbCount;

    const coefficientCredentialByCoordinate = new Map(
        input.coefficientCredentials.map((credential) => [
            vssShareLinkageCoordinateKey(
                credential.sourceTrusteeRosterPosition,
                credential.rnsLimbIndex,
                credential.shamirCoefficientIndex,
            ),
            credential,
        ]),
    );
    const recipientShareCredentialByCoordinate = new Map(
        input.recipientShareCredentials.map((credential) => [
            vssPublicRecipientShareCoordinateKey(
                credential.sourceTrusteeRosterPosition,
                credential.recipientRosterPosition,
                credential.rnsLimbIndex,
            ),
            credential,
        ]),
    );
    const requireCoefficientCredential = (
        sourceTrusteeRosterPosition: number,
        rnsLimbIndex: number,
        shamirCoefficientIndex: number,
    ): VssPublicCoefficientCredential => {
        const credential = coefficientCredentialByCoordinate.get(
            vssShareLinkageCoordinateKey(
                sourceTrusteeRosterPosition,
                rnsLimbIndex,
                shamirCoefficientIndex,
            ),
        );
        if (credential === undefined) {
            throw new Error(
                'VSS share linkage proof requires a coefficient credential for every covered coordinate.',
            );
        }

        return credential;
    };
    const requireRecipientShareCredential = (
        sourceTrusteeRosterPosition: number,
        recipientRosterPosition: number,
        rnsLimbIndex: number,
    ): VssPublicRecipientShareCredential => {
        const credential = recipientShareCredentialByCoordinate.get(
            vssPublicRecipientShareCoordinateKey(
                sourceTrusteeRosterPosition,
                recipientRosterPosition,
                rnsLimbIndex,
            ),
        );
        if (credential === undefined) {
            throw new Error(
                'VSS share linkage proof requires a recipient-share credential for every covered coordinate.',
            );
        }

        return credential;
    };

    const buildLinkageItemRecord = (
        sourceTrusteeRosterPosition: number,
        recipientRosterPosition: number,
        rnsLimbIndex: number,
    ): Record<string, unknown> => {
        const coefficientSourceRecord =
            coefficientCommitmentSet.sourceTrusteeRecords[
                sourceTrusteeRosterPosition
            ];
        const recipientSourceRecord =
            recipientShareCommitmentSet.sourceTrusteeRecords[
                sourceTrusteeRosterPosition
            ];
        if (
            coefficientSourceRecord === undefined ||
            recipientSourceRecord === undefined
        ) {
            throw new Error(
                'VSS share linkage proof requires matching coefficient and recipient source records.',
            );
        }
        const coefficientRecordOffset = rnsLimbIndex * thresholdDegree;
        const selectedCoefficientRecords =
            coefficientSourceRecord.coefficientCommitments.slice(
                coefficientRecordOffset,
                coefficientRecordOffset + thresholdDegree,
            );
        const recipientRecord =
            recipientSourceRecord.recipientShareCommitments[
                recipientRosterPosition * recipientLimbCount + rnsLimbIndex
            ];
        if (recipientRecord === undefined) {
            throw new Error(
                'VSS share linkage proof requires a recipient-share commitment for every covered coordinate.',
            );
        }

        return {
            sourceTrusteeIdentity:
                coefficientSourceRecord.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition,
            sourceCoefficientCommitmentRoot:
                coefficientSourceRecord.sourceCoefficientCommitmentRoot,
            sourceRecipientShareCommitmentRoot:
                recipientSourceRecord.sourceRecipientShareCommitmentRoot,
            recipientIdentity: recipientRecord.recipientIdentity,
            recipientRosterPosition,
            sourceRnsLimbIndex: rnsLimbIndex,
            sourceMessageModulus: recipientRecord.rnsPrime,
            coefficientCommitmentRoots: selectedCoefficientRecords.map(
                (coefficientRecord) =>
                    coefficientRecord.coefficientCommitmentRoot,
            ),
            coefficientOpeningRoots: selectedCoefficientRecords.map(
                (coefficientRecord) => coefficientRecord.coefficientOpeningRoot,
            ),
            coefficientCommitments: selectedCoefficientRecords.map(
                (coefficientRecord) => coefficientRecord.commitment,
            ),
            recipientShareCommitmentRoot: recipientRecord.shareCommitmentRoot,
            recipientShareOpeningRoot: recipientRecord.shareOpeningRoot,
            recipientShareCommitment: recipientRecord.commitment,
        };
    };

    const proofRecords: Record<string, unknown>[] = [];
    const canonicalProofMaterials: GeneratedVssCanonicalProofMaterial[] = [];
    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < participantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        for (
            let rnsLimbIndex = 0;
            rnsLimbIndex < targetRnsLimbCount;
            rnsLimbIndex += 1
        ) {
            const proofRecordIndex = rnsLimbIndex;
            const linkageItemRecords: Record<string, unknown>[] = [];
            const linkageItems: Record<string, unknown>[] = [];
            const recipientShareMessagesByItem: number[][] = [];
            const carryWitnessesByItem: number[][] = [];
            const recipientShareMaterialSeeds: string[] = [];
            const recipientShareMaterialContextHashes: string[] = [];
            for (
                let recipientRosterPosition = 0;
                recipientRosterPosition < participantCount;
                recipientRosterPosition += 1
            ) {
                linkageItemRecords.push(
                    buildLinkageItemRecord(
                        sourceTrusteeRosterPosition,
                        recipientRosterPosition,
                        rnsLimbIndex,
                    ),
                );
                linkageItems.push({
                    sourceTrusteeRosterPosition,
                    recipientRosterPosition,
                    sourceRnsLimbIndex: rnsLimbIndex,
                    itemIndex: recipientRosterPosition,
                });
                const recipientShareCredential =
                    requireRecipientShareCredential(
                        sourceTrusteeRosterPosition,
                        recipientRosterPosition,
                        rnsLimbIndex,
                    );
                recipientShareMessagesByItem.push([
                    ...recipientShareCredential.shareValues,
                ]);
                carryWitnessesByItem.push([
                    ...recipientShareCredential.carries,
                ]);
                recipientShareMaterialSeeds.push(
                    recipientShareCredential.materialSeedHex,
                );
                recipientShareMaterialContextHashes.push(
                    recipientShareCredential.commitmentContextHash,
                );
            }

            const [primaryLinkageItemRecord] = linkageItemRecords;
            if (primaryLinkageItemRecord === undefined) {
                throw new Error(
                    'VSS share linkage proof record requires at least one covered recipient.',
                );
            }
            const vssShareLinkage = {
                ...primaryLinkageItemRecord,
                publicMatrixSeedHash: statement.publicMatrixSeedHash,
                shareLinkageStatementRoot: statement.statementRoot,
                additionalLinkageItems: linkageItemRecords.slice(1),
            };

            const coefficientMessagesByShamirIndex: number[][] = [];
            const coefficientMaterialSeeds: string[] = [];
            const coefficientMaterialContextHashes: string[] = [];
            for (
                let shamirCoefficientIndex = 0;
                shamirCoefficientIndex < thresholdDegree;
                shamirCoefficientIndex += 1
            ) {
                const coefficientCredential = requireCoefficientCredential(
                    sourceTrusteeRosterPosition,
                    rnsLimbIndex,
                    shamirCoefficientIndex,
                );
                coefficientMessagesByShamirIndex.push([
                    ...coefficientCredential.coefficientMessage,
                ]);
                coefficientMaterialSeeds.push(
                    coefficientCredential.materialSeedHex,
                );
                coefficientMaterialContextHashes.push(
                    coefficientCredential.commitmentContextHash,
                );
            }

            // Committed-material regeneration inputs in the statement's
            // bound-commitment order: every unique coefficient witness slot
            // (one proof record covers a single source limb, so the unique
            // slots are its Shamir coefficients in order), then each linkage
            // item's recipient share in item order. The committed-material
            // commitments carry no algebraic opening randomness.
            const vssCommittedMaterialSeedsByBoundMessage = [
                ...coefficientMaterialSeeds,
                ...recipientShareMaterialSeeds,
            ];
            const vssCommittedMaterialContextHashesByBoundMessage = [
                ...coefficientMaterialContextHashes,
                ...recipientShareMaterialContextHashes,
            ];

            const proofRandomness = input.shareLinkageProofRandomness({
                sourceTrusteeRosterPosition,
                proofRecordIndex,
            });
            const generatedProof = await input.generateVssShareLinkageProof({
                context: {
                    ceremonyId: statement.ceremonyId,
                    manifestHash: statement.manifestHash,
                    rosterHash: statement.rosterHash,
                    trusteeIdentity: vssShareLinkageProofFamily,
                    trusteeRosterPosition: 0,
                    setupEpoch: statement.setupEpoch,
                    shareLinkageStatementRoot: statement.statementRoot,
                },
                ringDegree,
                vssShareLinkage,
                coefficientMessagesByShamirIndex,
                recipientShareMessages: recipientShareMessagesByItem[0],
                coefficientOpeningRandomnessByShamirIndex: [],
                recipientShareOpeningRandomness: [],
                carryWitnesses: carryWitnessesByItem[0],
                recipientShareMessagesByItem,
                recipientShareOpeningRandomnessByItem: [],
                carryWitnessesByItem,
                vssCommittedMaterialSeedsByBoundMessage,
                vssCommittedMaterialContextHashesByBoundMessage,
                proofRandomnessSeedHex: proofRandomness.seedHex,
                proofRandomnessNonceHex: proofRandomness.nonceHex,
            });
            const canonicalProofMaterial =
                validatedGeneratedVssCanonicalProofMaterial(
                    vssShareLinkageProofFamily,
                    generatedProof,
                );
            canonicalProofMaterials.push(canonicalProofMaterial);
            const proofRecordWithoutRoot = {
                objectType: 'VssShareLinkageProofRecord',
                proofFamily: vssShareLinkageProofFamily,
                linkageItems,
                vssShareLinkage,
                proofBytesHash: generatedProof.proofBytesHash,
                proofBytesEncoding: canonicalSetupProofMaterialEncoding,
                proofMaterialRoot: generatedProof.proofMaterialRoot,
            };
            proofRecords.push({
                ...proofRecordWithoutRoot,
                proofRecordRoot: deriveCanonicalObjectHash(
                    proofRecordWithoutRoot,
                ),
            });
        }
    }

    const proofMaterialSetWithoutRoot = {
        objectType: 'VssShareLinkageProofMaterialSet',
        proofFamily: vssShareLinkageProofFamily,
        ceremonyId: statement.ceremonyId,
        manifestHash: statement.manifestHash,
        rosterHash: statement.rosterHash,
        setupParametersHash: statement.setupParametersHash,
        setupEpoch: statement.setupEpoch,
        publicMatrixSeedHash: statement.publicMatrixSeedHash,
        targetBasisHash: statement.targetBasisHash,
        ringDegree,
        participantCount,
        targetRnsLimbCount,
        thresholdDegree,
        coefficientCommitmentRoot: statement.coefficientCommitmentRoot,
        recipientShareCommitmentRoot: statement.recipientShareCommitmentRoot,
        aggregateThresholdCommitmentRoot:
            statement.aggregateThresholdCommitmentRoot,
        statementRoot: statement.statementRoot,
        proofRecords,
    };

    if (input.deriveProofMaterialSetRoot === false) {
        return {
            proofMaterialSet: proofMaterialSetWithoutRoot,
            canonicalProofMaterials,
        };
    }

    return {
        proofMaterialSet: {
            ...proofMaterialSetWithoutRoot,
            proofMaterialSetRoot: deriveCanonicalObjectHash(
                proofMaterialSetWithoutRoot,
            ),
        },
        canonicalProofMaterials,
    };
}

// The single threshold-share commitment form: it binds the
// aggregate threshold commitment set to the share-linkage statement and proof
// material, so the accepted-setup verifier recomputes this root over the
// roots it already verified rather than trusting a separate threshold object.
export const createThresholdShareCommitmentBinding = (input: {
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly statement: VssShareLinkageStatement;
    readonly aggregateThresholdCommitmentSet: VssPublicAggregateThresholdCommitmentSet;
    readonly shareLinkageProofMaterialSetRoot: ProtocolHash;
}): Record<string, unknown> => {
    const bindingWithoutRoot = {
        objectType: 'ThresholdShareCommitmentBinding',
        publicMatrixSeedHash:
            input.coefficientCommitmentSet.publicMatrixSeedHash,
        participantCount: input.coefficientCommitmentSet.participantCount,
        thresholdDegree: input.coefficientCommitmentSet.thresholdDegree,
        targetRnsLimbCount: input.statement.targetRnsLimbCount,
        ringDegree: input.coefficientCommitmentSet.ringDegree,
        aggregateThresholdCommitmentRoot:
            input.aggregateThresholdCommitmentSet
                .aggregateThresholdCommitmentRoot,
        shareLinkageStatementRoot: input.statement.statementRoot,
        shareLinkageProofMaterialSetRoot:
            input.shareLinkageProofMaterialSetRoot,
    };

    return {
        ...bindingWithoutRoot,
        thresholdShareCommitmentRoot:
            deriveCanonicalObjectHash(bindingWithoutRoot),
    };
};

// Same-secret bridge constants. These are bound into the bridge
// statement (and thus its recomputed root), so they must match the kernel
// verifier byte for byte.
const sameSecretRelation =
    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs';
const sameSecretBridgeRelation =
    'target-basis constant coefficient commitments bind to the same signed ternary trustee secret as the source data-basis VSS constant commitments';
const sameSecretBridgeIntegerSupport =
    'the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb';
const sameSecretBridgeSignedRepresentativeConvention =
    'coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime';
const vssPublicCommitmentBinaryFormat =
    'sealed-lattice-vss-public-commitment-binary';
const sameSecretBridgeTargetBasisLimbOrder =
    'target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime';
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
    readonly targetBasisHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly dataBasisRelation: string;
    readonly integerSupport: string;
    readonly signedRepresentativeConvention: string;
    readonly vssPublicCommitmentEncoding: string;
    readonly targetBasisLimbOrder: string;
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
    readonly targetBasisHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly integerSupport: string;
    readonly signedRepresentativeConvention: string;
    readonly vssPublicCommitmentEncoding: string;
    readonly targetBasisLimbOrder: string;
    readonly statementRecords: readonly VssSameSecretBridgeStatement[];
    readonly sameSecretBridgeStatementSetRoot: ProtocolHash;
};

// The same-secret bridge statement set ties each trustee's target-basis
// constant commitments to the canonical source VSS commitment set. The proof
// material then proves both bases use one signed ternary secret.
export const createVssSameSecretBridgeStatementSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
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
                targetBasisHash: input.targetBasisHash,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                ringDegree,
                trusteeIdentity: coefficientSourceRecord.sourceTrusteeIdentity,
                trusteeRosterPosition: sourceTrusteeRosterPosition,
                dataBasisRelation: sameSecretRelation,
                integerSupport: sameSecretBridgeIntegerSupport,
                signedRepresentativeConvention:
                    sameSecretBridgeSignedRepresentativeConvention,
                vssPublicCommitmentEncoding: vssPublicCommitmentBinaryFormat,
                targetBasisLimbOrder: sameSecretBridgeTargetBasisLimbOrder,
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
        targetBasisHash: input.targetBasisHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        ringDegree,
        participantCount,
        targetRnsLimbCount: rnsLimbCount,
        thresholdDegree,
        coefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        vssCoefficientCommitmentRoot:
            input.sourceCoefficientCommitmentSet.vssCoefficientCommitmentRoot,
        integerSupport: sameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            sameSecretBridgeSignedRepresentativeConvention,
        vssPublicCommitmentEncoding: vssPublicCommitmentBinaryFormat,
        targetBasisLimbOrder: sameSecretBridgeTargetBasisLimbOrder,
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

// Private prover input for one trustee. The statement carries the canonical
// shamir-zero source bodies; this provider supplies only their secret opening
// witness in that same source-limb order.
type SameSecretBridgeSourceWitnessProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
}) => {
    readonly secretCoefficients: readonly number[];
    readonly sourceOpeningRandomnessByLimb: readonly (readonly (readonly number[])[])[];
};

type SameSecretBridgeProofRandomnessProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
}) => { readonly seedHex: string; readonly nonceHex: string };

type VssSameSecretBridgeProofMaterialSetInput = {
    readonly statementSet: VssSameSecretBridgeStatementSet;
    readonly coefficientCredentials: readonly VssPublicCoefficientCredential[];
    readonly sourceWitness: SameSecretBridgeSourceWitnessProvider;
    readonly bridgeProofRandomness: SameSecretBridgeProofRandomnessProvider;
    readonly generateSameSecretBridgeProof: SameSecretBridgeProofComputer;
};

type VssSameSecretBridgeProofRecord = {
    readonly objectType: 'VssSameSecretBridgeProofRecord';
    readonly proofFamily: typeof sameSecretBridgeProofFamily;
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
    readonly proofBytesHash: ProtocolHash;
    readonly proofBytesEncoding: typeof canonicalSetupProofMaterialEncoding;
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
    readonly targetBasisHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
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

// The same-secret bridge proof material set: one succinct bridge proof
// per source trustee. The verifier recomputes the statement roots and the proof
// bytes hash and checks each proof, so this builder assembles the witness (the
// trustee secret, its sign indicators, and the per-limb constant-coefficient
// commitment randomness) and binds the proof bytes.
export function createVssSameSecretBridgeProofMaterialSet(
    input: VssSameSecretBridgeProofMaterialSetInput & {
        readonly deriveProofMaterialSetRoot?: true;
    },
): Promise<
    VssSameSecretBridgeProofMaterialBuild<
        VssSameSecretBridgeProofMaterialSet &
            Required<
                Pick<
                    VssSameSecretBridgeProofMaterialSet,
                    'proofMaterialSetRoot'
                >
            >
    >
>;
export function createVssSameSecretBridgeProofMaterialSet(
    input: VssSameSecretBridgeProofMaterialSetInput & {
        readonly deriveProofMaterialSetRoot: false;
    },
): Promise<
    VssSameSecretBridgeProofMaterialBuild<
        Omit<VssSameSecretBridgeProofMaterialSet, 'proofMaterialSetRoot'>
    >
>;
export async function createVssSameSecretBridgeProofMaterialSet(
    input: VssSameSecretBridgeProofMaterialSetInput & {
        readonly deriveProofMaterialSetRoot?: boolean;
    },
): Promise<VssSameSecretBridgeProofMaterialBuild> {
    const { statementSet } = input;
    const constantCoefficientCredentialByCoordinate = new Map(
        input.coefficientCredentials
            .filter((credential) => credential.shamirCoefficientIndex === 0)
            .map((credential) => [
                `${String(credential.sourceTrusteeRosterPosition)}:${String(credential.rnsLimbIndex)}`,
                credential,
            ]),
    );
    const requireConstantCoefficientCredential = (
        sourceTrusteeRosterPosition: number,
        rnsLimbIndex: number,
    ): VssPublicCoefficientCredential => {
        const credential = constantCoefficientCredentialByCoordinate.get(
            `${String(sourceTrusteeRosterPosition)}:${String(rnsLimbIndex)}`,
        );
        if (credential === undefined) {
            throw new Error(
                'Same-secret bridge proof requires a constant coefficient credential per target limb.',
            );
        }

        return credential;
    };

    const canonicalProofMaterials: GeneratedVssCanonicalProofMaterial[] = [];
    const proofRecords: VssSameSecretBridgeProofRecord[] = [];
    for (const statementRecord of statementSet.statementRecords) {
        const sourceTrusteeRosterPosition =
            statementRecord.trusteeRosterPosition;
        const { secretCoefficients, sourceOpeningRandomnessByLimb } =
            input.sourceWitness({ sourceTrusteeRosterPosition });
        const sourceConstantCommitments =
            statementRecord.sourceConstantCoefficientCommitments.map(
                (sourceConstantCommitment, sourceRnsLimbIndex) => {
                    if (
                        sourceConstantCommitment.rnsLimbIndex !==
                            sourceRnsLimbIndex ||
                        sourceConstantCommitment.shamirCoefficientIndex !== 0 ||
                        sourceConstantCommitment.commitment
                            .sourceRnsLimbIndex !== sourceRnsLimbIndex ||
                        sourceConstantCommitment.commitment
                            .sourceMessageModulus !==
                            sourceConstantCommitment.rnsPrime ||
                        sourceConstantCommitment.commitment
                            .shamirCoefficientIndex !== 0 ||
                        sourceConstantCommitment.commitment.ringDegree !==
                            statementRecord.ringDegree
                    ) {
                        throw new Error(
                            'Same-secret bridge statement must carry canonical source constant commitments in source-limb order.',
                        );
                    }

                    return sourceConstantCommitment.commitment;
                },
            );
        if (
            sourceConstantCommitments.length === 0 ||
            sourceOpeningRandomnessByLimb.length !==
                sourceConstantCommitments.length
        ) {
            throw new Error(
                'Same-secret bridge source witness must cover every canonical source limb exactly once in order.',
            );
        }
        const negativeIndicatorCoefficients = secretCoefficients.map(
            (coefficient) => (coefficient < 0 ? 1 : 0),
        );
        // Committed-material regeneration inputs in the statement's
        // bound-commitment order: the bridge binds its target-constant
        // commitments in target order. Context hashes are read off the
        // published commitments; the seeds are the same seeds those
        // commitments were created with.
        const vssCommittedMaterialSeedsByBoundMessage =
            statementRecord.targetConstantCoefficientCommitments.map(
                (targetConstantCommitment) =>
                    requireConstantCoefficientCredential(
                        sourceTrusteeRosterPosition,
                        targetConstantCommitment.rnsLimbIndex,
                    ).materialSeedHex,
            );
        const vssCommittedMaterialContextHashesByBoundMessage =
            statementRecord.targetConstantCoefficientCommitments.map(
                (targetConstantCommitment) =>
                    targetConstantCommitment.commitment.commitmentContextHash,
            );
        const sameSecretBridge = {
            publicMatrixSeedHash: statementRecord.publicMatrixSeedHash,
            sourceTrusteeIdentity: statementRecord.trusteeIdentity,
            sourceTrusteeRosterPosition,
            targetBasisHash: statementRecord.targetBasisHash,
            targetRnsPrimes:
                statementRecord.targetConstantCoefficientCommitmentRoots.map(
                    (targetConstantRoot) => targetConstantRoot.rnsPrime,
                ),
            targetConstantCommitmentRoots:
                statementRecord.targetConstantCoefficientCommitmentRoots.map(
                    (targetConstantRoot) =>
                        targetConstantRoot.coefficientCommitmentRoot,
                ),
            targetConstantCommitments:
                statementRecord.targetConstantCoefficientCommitments.map(
                    (targetConstantCommitment) =>
                        targetConstantCommitment.commitment,
                ),
        };
        const proofRandomness = input.bridgeProofRandomness({
            sourceTrusteeRosterPosition,
        });
        const generatedProof = await input.generateSameSecretBridgeProof({
            context: {
                ceremonyId: statementSet.ceremonyId,
                manifestHash: statementSet.manifestHash,
                rosterHash: statementSet.rosterHash,
                trusteeIdentity: statementRecord.trusteeIdentity,
                trusteeRosterPosition: sourceTrusteeRosterPosition,
                setupEpoch: statementSet.setupEpoch,
            },
            ringDegree: statementRecord.ringDegree,
            sameSecretLinkage: {
                publicMatrixSeedHash: statementRecord.publicMatrixSeedHash,
                commitments: sourceConstantCommitments,
            },
            sameSecretBridge,
            secretCoefficients,
            negativeIndicatorCoefficients,
            openingRandomnessByLimb: sourceOpeningRandomnessByLimb,
            vssCommittedMaterialSeedsByBoundMessage,
            vssCommittedMaterialContextHashesByBoundMessage,
            proofRandomnessSeedHex: proofRandomness.seedHex,
            proofRandomnessNonceHex: proofRandomness.nonceHex,
        });
        const canonicalProofMaterial =
            validatedGeneratedVssCanonicalProofMaterial(
                sameSecretBridgeProofFamily,
                generatedProof,
            );
        canonicalProofMaterials.push(canonicalProofMaterial);
        const proofRecordWithoutRoot = {
            objectType: 'VssSameSecretBridgeProofRecord',
            proofFamily: sameSecretBridgeProofFamily,
            sameSecretBridgeStatementRoot:
                statementRecord.sameSecretBridgeStatementRoot,
            proofBytesHash: generatedProof.proofBytesHash,
            proofBytesEncoding: canonicalSetupProofMaterialEncoding,
            proofMaterialRoot: generatedProof.proofMaterialRoot,
        } as const;

        proofRecords.push({
            ...proofRecordWithoutRoot,
            sameSecretBridgeProofRecordRoot: deriveCanonicalObjectHash(
                proofRecordWithoutRoot,
            ),
        });
    }

    const proofMaterialSetWithoutRoot = {
        objectType: 'VssSameSecretBridgeProofMaterialSet',
        proofFamily: sameSecretBridgeProofFamily,
        ceremonyId: statementSet.ceremonyId,
        manifestHash: statementSet.manifestHash,
        rosterHash: statementSet.rosterHash,
        setupParametersHash: statementSet.setupParametersHash,
        setupEpoch: statementSet.setupEpoch,
        targetBasisHash: statementSet.targetBasisHash,
        publicMatrixSeedHash: statementSet.publicMatrixSeedHash,
        ringDegree: statementSet.ringDegree,
        participantCount: statementSet.participantCount,
        targetRnsLimbCount: statementSet.targetRnsLimbCount,
        thresholdDegree: statementSet.thresholdDegree,
        coefficientCommitmentRoot: statementSet.coefficientCommitmentRoot,
        vssCoefficientCommitmentRoot: statementSet.vssCoefficientCommitmentRoot,
        sameSecretBridgeStatementSetRoot:
            statementSet.sameSecretBridgeStatementSetRoot,
        proofRecords,
    } as const;

    if (input.deriveProofMaterialSetRoot === false) {
        return {
            proofMaterialSet: proofMaterialSetWithoutRoot,
            canonicalProofMaterials,
        };
    }

    return {
        proofMaterialSet: {
            ...proofMaterialSetWithoutRoot,
            proofMaterialSetRoot: deriveCanonicalObjectHash(
                proofMaterialSetWithoutRoot,
            ),
        },
        canonicalProofMaterials,
    };
}
