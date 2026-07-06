import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type {
    SameSecretConsistencyStatementSet,
    SameSecretProofSet,
} from '../same-secret-consistency-records.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import {
    setupContextFields,
    type VssPublicAggregateThresholdCommitmentSet,
    type VssPublicCoefficientCommitmentSet,
    type VssPublicCoefficientCredential,
    type VssPublicCommitmentValue,
    type VssPublicRecipientShareCommitmentSet,
    type VssPublicRecipientShareCredential,
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
export const vssShareLinkageProofBytesHashDomain =
    'sealed-lattice/setup/vss-share-linkage/proof-bytes-v1';
const standardBase64Alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    if (hex.length % 2 !== 0) {
        throw new Error(`${fieldName} must have an even hex length.`);
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        const parsedByte = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
        if (Number.isNaN(parsedByte)) {
            throw new Error(`${fieldName} must be valid hexadecimal.`);
        }
        bytes[byteIndex] = parsedByte;
    }

    return bytes;
};

// Standard RFC 4648 base64 with padding, byte-for-byte the kernel's
// encode_standard_base64 so the canonical decoder the verifier runs accepts it
// and the proof bytes stay canonically bound.
const encodeStandardBase64 = (bytes: Uint8Array): string => {
    let encoded = '';
    for (let chunkStart = 0; chunkStart < bytes.length; chunkStart += 3) {
        const remaining = bytes.length - chunkStart;
        const first = bytes[chunkStart];
        const second = remaining >= 2 ? bytes[chunkStart + 1] : 0;
        const third = remaining >= 3 ? bytes[chunkStart + 2] : 0;
        encoded += standardBase64Alphabet[first >> 2];
        encoded +=
            standardBase64Alphabet[((first & 0x03) << 4) | (second >> 4)];
        encoded +=
            remaining >= 2
                ? standardBase64Alphabet[((second & 0x0f) << 2) | (third >> 6)]
                : '=';
        encoded += remaining >= 3 ? standardBase64Alphabet[third & 0x3f] : '=';
    }

    return encoded;
};

export type VssShareLinkageProofContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
    readonly shareLinkageStatementRoot: ProtocolHash;
};

// The kernel-backed share-linkage proof (bound to the WASM
// `GenerateVssShareLinkageProof` command by the SDK). Injected so the
// protocol layer assembles the witness but never runs the certified prover.
export type VssShareLinkageProofComputer = (input: {
    readonly context: VssShareLinkageProofContext;
    readonly ringDegree: number;
    readonly vssShareLinkage: Record<string, unknown>;
    readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
    readonly recipientShareMessages: readonly number[];
    readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
    readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
    readonly carryWitnesses: readonly number[];
    readonly recipientShareMessagesByItem: readonly (readonly number[])[];
    readonly recipientShareOpeningRandomnessByItem: readonly (readonly (readonly number[])[])[];
    readonly carryWitnessesByItem: readonly (readonly number[])[];
    readonly proofRandomnessSeedHex: string;
    readonly proofRandomnessNonceHex: string;
}) => { readonly proofBytesHex: string };

// Fresh prover blinding randomness per proof record. The share-linkage proof is
// zero-knowledge, so this is independent per (source trustee, proof record) and
// binds nothing the verifier recomputes.
type VssShareLinkageProofRandomnessProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
    readonly proofRecordIndex: number;
}) => { readonly seedHex: string; readonly nonceHex: string };

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
export const createVssShareLinkageProofMaterialSet = (input: {
    readonly statement: VssShareLinkageStatement;
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly coefficientCredentials: readonly VssPublicCoefficientCredential[];
    readonly recipientShareCredentials: readonly VssPublicRecipientShareCredential[];
    readonly shareLinkageProofRandomness: VssShareLinkageProofRandomnessProvider;
    readonly generateVssShareLinkageProof: VssShareLinkageProofComputer;
}): Record<string, unknown> & {
    readonly proofMaterialSetRoot: ProtocolHash;
} => {
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
            const recipientShareOpeningRandomnessByItem: number[][][] = [];
            const carryWitnessesByItem: number[][] = [];
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
                recipientShareOpeningRandomnessByItem.push(
                    recipientShareCredential.randomnessByColumn.map(
                        (column) => [...column],
                    ),
                );
                carryWitnessesByItem.push([
                    ...recipientShareCredential.carries,
                ]);
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
            const coefficientOpeningRandomnessByShamirIndex: number[][][] = [];
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
                coefficientOpeningRandomnessByShamirIndex.push(
                    coefficientCredential.randomnessByColumn.map((column) => [
                        ...column,
                    ]),
                );
            }

            const proofRandomness = input.shareLinkageProofRandomness({
                sourceTrusteeRosterPosition,
                proofRecordIndex,
            });
            const generatedProof = input.generateVssShareLinkageProof({
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
                coefficientOpeningRandomnessByShamirIndex,
                recipientShareOpeningRandomness:
                    recipientShareOpeningRandomnessByItem[0],
                carryWitnesses: carryWitnessesByItem[0],
                recipientShareMessagesByItem,
                recipientShareOpeningRandomnessByItem,
                carryWitnessesByItem,
                proofRandomnessSeedHex: proofRandomness.seedHex,
                proofRandomnessNonceHex: proofRandomness.nonceHex,
            });
            const proofBytes = bytesFromHex(
                generatedProof.proofBytesHex,
                'VSS share linkage proofBytesHex',
            );
            const proofRecordWithoutRoot = {
                objectType: 'VssShareLinkageProofRecord',
                proofFamily: vssShareLinkageProofFamily,
                linkageItems,
                vssShareLinkage,
                proofBytesHash: hash512Hex(
                    vssShareLinkageProofBytesHashDomain,
                    [proofBytes],
                ),
                proofBytesBase64: encodeStandardBase64(proofBytes),
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

    return {
        ...proofMaterialSetWithoutRoot,
        proofMaterialSetRoot: deriveCanonicalObjectHash(
            proofMaterialSetWithoutRoot,
        ),
    };
};

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
const sameSecretProofFamily = 'same-secret-linkage-anchor';
const sameSecretRelation =
    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs';
const sameSecretBridgeRelation =
    'target-basis constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof';
const sameSecretBridgeIntegerSupport =
    'the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb';
const sameSecretBridgeSignedRepresentativeConvention =
    'coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime';
const vssPublicCommitmentBinaryFormat =
    'sealed-lattice-vss-public-commitment-binary-v1';
const sameSecretBridgeTargetBasisLimbOrder =
    'target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime';
export const sameSecretBridgeProofFamily = 'same-secret-bridge';
export const sameSecretBridgeProofBytesHashDomain =
    'sealed-lattice/setup/same-secret-bridge/proof-bytes-v1';

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
    readonly commitment: VssPublicCommitmentValue;
};

export type VssSameSecretBridgeStatement = {
    readonly objectType: string;
    readonly proofFamily: string;
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
    readonly sameSecretStatementRoot: ProtocolHash;
    readonly sameSecretProofRoot: ProtocolHash;
    readonly trusteeSecretCommitmentRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
    readonly dataBasisRelation: string;
    readonly integerSupport: string;
    readonly signedRepresentativeConvention: string;
    readonly vssPublicCommitmentEncoding: string;
    readonly targetBasisLimbOrder: string;
    readonly targetConstantCoefficientCommitmentRoots: readonly VssSameSecretBridgeTargetConstantRoot[];
    readonly targetConstantCoefficientCommitments: readonly VssSameSecretBridgeTargetConstantCommitment[];
    readonly relation: string;
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
};

export type VssSameSecretBridgeStatementSet = {
    readonly objectType: string;
    readonly proofFamily: string;
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
    readonly sameSecretConsistencyRoot: ProtocolHash;
    readonly sameSecretProofSetRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
    readonly integerSupport: string;
    readonly signedRepresentativeConvention: string;
    readonly vssPublicCommitmentEncoding: string;
    readonly targetBasisLimbOrder: string;
    readonly statementRecords: readonly VssSameSecretBridgeStatement[];
    readonly sameSecretBridgeStatementSetRoot: ProtocolHash;
};

// The same-secret bridge statement set: per source trustee, it ties the
// target-basis constant coefficient commitments to the accepted
// data-basis same-secret proof, so the verifier recomputes the shared roots and
// checks one bridge proof per trustee proves both bases open to one secret.
export const createVssSameSecretBridgeStatementSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
}): VssSameSecretBridgeStatementSet => {
    const { coefficientCommitmentSet } = input;
    const { ringDegree, participantCount, rnsLimbCount, thresholdDegree } =
        coefficientCommitmentSet;
    const statementRecords = coefficientCommitmentSet.sourceTrusteeRecords.map(
        (
            coefficientSourceRecord,
            sourceTrusteeRosterPosition,
        ): VssSameSecretBridgeStatement => {
            const sameSecretStatement =
                input.sameSecretConsistency.statementRecords[
                    sourceTrusteeRosterPosition
                ];
            const sameSecretProof =
                input.sameSecretProofs.proofRecords[
                    sourceTrusteeRosterPosition
                ];
            if (
                sameSecretStatement === undefined ||
                sameSecretProof === undefined
            ) {
                throw new Error(
                    'Same-secret bridge requires a same-secret statement and proof per source trustee.',
                );
            }
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
                proofFamily: sameSecretProofFamily,
                ...setupContextFields(input.setupContext),
                targetBasisHash: input.targetBasisHash,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                ringDegree,
                trusteeIdentity: coefficientSourceRecord.sourceTrusteeIdentity,
                trusteeRosterPosition: sourceTrusteeRosterPosition,
                sameSecretStatementRoot:
                    sameSecretStatement.sameSecretStatementRoot,
                sameSecretProofRoot: sameSecretProof.sameSecretProofRoot,
                trusteeSecretCommitmentRoot:
                    sameSecretStatement.trusteeSecretCommitmentRoot,
                sameSecretProofFamilyBindingRoot:
                    sameSecretStatement.sameSecretProofFamilyBindingRoot,
                dataBasisRelation: sameSecretRelation,
                integerSupport: sameSecretBridgeIntegerSupport,
                signedRepresentativeConvention:
                    sameSecretBridgeSignedRepresentativeConvention,
                vssPublicCommitmentEncoding: vssPublicCommitmentBinaryFormat,
                targetBasisLimbOrder: sameSecretBridgeTargetBasisLimbOrder,
                targetConstantCoefficientCommitmentRoots,
                targetConstantCoefficientCommitments,
                relation: sameSecretBridgeRelation,
            };

            return {
                ...statementWithoutRoot,
                sameSecretBridgeStatementRoot:
                    deriveCanonicalObjectHash(statementWithoutRoot),
            };
        },
    );

    const statementSetWithoutRoot = {
        objectType: 'VssSameSecretBridgeStatementSet',
        proofFamily: sameSecretProofFamily,
        ...setupContextFields(input.setupContext),
        targetBasisHash: input.targetBasisHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        ringDegree,
        participantCount,
        targetRnsLimbCount: rnsLimbCount,
        thresholdDegree,
        coefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        integerSupport: sameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            sameSecretBridgeSignedRepresentativeConvention,
        vssPublicCommitmentEncoding: vssPublicCommitmentBinaryFormat,
        targetBasisLimbOrder: sameSecretBridgeTargetBasisLimbOrder,
        statementRecords,
    };

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
    readonly sameSecretBridgeStatementRoot: ProtocolHash;
    readonly sameSecretStatementRoot: ProtocolHash;
    readonly sameSecretProofRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
};

// The kernel-backed same-secret bridge proof (bound to the WASM
// `GenerateSameSecretBridgeProof` command by the SDK). Injected so the
// protocol layer assembles the witness but never runs the certified prover.
export type SameSecretBridgeProofComputer = (input: {
    readonly context: SameSecretBridgeProofContext;
    readonly ringDegree: number;
    readonly sameSecretBridge: Record<string, unknown>;
    readonly secretCoefficients: readonly number[];
    readonly negativeIndicatorCoefficients: readonly number[];
    readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
    readonly proofRandomnessSeedHex: string;
    readonly proofRandomnessNonceHex: string;
    readonly transportedSameSecretProofMaterial?: Record<string, unknown>;
}) => { readonly proofBytesHex: string };

// The source trustee's centered ternary secret coefficient vector, the same
// secret the data-basis same-secret proof binds. The bridge proves the
// target-basis constant commitments open to this exact vector.
type SameSecretBridgeSecretProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
}) => { readonly secretCoefficients: readonly number[] };

type SameSecretBridgeProofRandomnessProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
}) => { readonly seedHex: string; readonly nonceHex: string };

// Optional per-trustee transported same-secret proof material, present only when
// the data-basis same-secret proof is delivered by transport rather than
// embedded; the bridge proof binds it so both bases reference one proof.
type SameSecretBridgeTransportedProofMaterialProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
}) => Record<string, unknown> | undefined;

// The same-secret bridge proof material set: one succinct bridge proof
// per source trustee. The verifier recomputes the statement roots and the proof
// bytes hash and checks each proof, so this builder assembles the witness (the
// trustee secret, its sign indicators, and the per-limb constant-coefficient
// commitment randomness) and binds the proof bytes.
export const createVssSameSecretBridgeProofMaterialSet = (input: {
    readonly statementSet: VssSameSecretBridgeStatementSet;
    readonly coefficientCredentials: readonly VssPublicCoefficientCredential[];
    readonly bridgeSecret: SameSecretBridgeSecretProvider;
    readonly bridgeProofRandomness: SameSecretBridgeProofRandomnessProvider;
    readonly transportedSameSecretProofMaterial?: SameSecretBridgeTransportedProofMaterialProvider;
    readonly generateSameSecretBridgeProof: SameSecretBridgeProofComputer;
}): Record<string, unknown> => {
    const { statementSet } = input;
    const constantCoefficientRandomnessByCoordinate = new Map(
        input.coefficientCredentials
            .filter((credential) => credential.shamirCoefficientIndex === 0)
            .map((credential) => [
                `${String(credential.sourceTrusteeRosterPosition)}:${String(credential.rnsLimbIndex)}`,
                credential.randomnessByColumn,
            ]),
    );
    const requireConstantCoefficientRandomness = (
        sourceTrusteeRosterPosition: number,
        rnsLimbIndex: number,
    ): readonly (readonly number[])[] => {
        const randomness = constantCoefficientRandomnessByCoordinate.get(
            `${String(sourceTrusteeRosterPosition)}:${String(rnsLimbIndex)}`,
        );
        if (randomness === undefined) {
            throw new Error(
                'Same-secret bridge proof requires constant coefficient commitment randomness per target limb.',
            );
        }

        return randomness;
    };

    const proofRecords = statementSet.statementRecords.map(
        (statementRecord): Record<string, unknown> => {
            const sourceTrusteeRosterPosition =
                statementRecord.trusteeRosterPosition;
            const { secretCoefficients } = input.bridgeSecret({
                sourceTrusteeRosterPosition,
            });
            const negativeIndicatorCoefficients = secretCoefficients.map(
                (coefficient) => (coefficient < 0 ? 1 : 0),
            );
            const openingRandomnessByLimb =
                statementRecord.targetConstantCoefficientCommitmentRoots.map(
                    (targetConstantRoot) =>
                        requireConstantCoefficientRandomness(
                            sourceTrusteeRosterPosition,
                            targetConstantRoot.rnsLimbIndex,
                        ).map((column) => [...column]),
                );
            const sameSecretBridge = {
                sameSecretBridgeStatementRoot:
                    statementRecord.sameSecretBridgeStatementRoot,
                sameSecretStatementRoot:
                    statementRecord.sameSecretStatementRoot,
                sameSecretProofRoot: statementRecord.sameSecretProofRoot,
                sameSecretProofFamilyBindingRoot:
                    statementRecord.sameSecretProofFamilyBindingRoot,
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
            const transportedSameSecretProofMaterial =
                input.transportedSameSecretProofMaterial?.({
                    sourceTrusteeRosterPosition,
                });
            const generatedProof = input.generateSameSecretBridgeProof({
                context: {
                    ceremonyId: statementSet.ceremonyId,
                    manifestHash: statementSet.manifestHash,
                    rosterHash: statementSet.rosterHash,
                    trusteeIdentity: statementRecord.trusteeIdentity,
                    trusteeRosterPosition: sourceTrusteeRosterPosition,
                    setupEpoch: statementSet.setupEpoch,
                    sameSecretBridgeStatementRoot:
                        statementRecord.sameSecretBridgeStatementRoot,
                    sameSecretStatementRoot:
                        statementRecord.sameSecretStatementRoot,
                    sameSecretProofRoot: statementRecord.sameSecretProofRoot,
                    sameSecretProofFamilyBindingRoot:
                        statementRecord.sameSecretProofFamilyBindingRoot,
                },
                ringDegree: statementRecord.ringDegree,
                sameSecretBridge,
                secretCoefficients,
                negativeIndicatorCoefficients,
                openingRandomnessByLimb,
                proofRandomnessSeedHex: proofRandomness.seedHex,
                proofRandomnessNonceHex: proofRandomness.nonceHex,
                ...(transportedSameSecretProofMaterial === undefined
                    ? {}
                    : { transportedSameSecretProofMaterial }),
            });
            const proofBytes = bytesFromHex(
                generatedProof.proofBytesHex,
                'same-secret bridge proofBytesHex',
            );
            const proofRecordWithoutRoot = {
                objectType: 'VssSameSecretBridgeProofRecord',
                proofFamily: sameSecretBridgeProofFamily,
                sameSecretBridgeStatementRoot:
                    statementRecord.sameSecretBridgeStatementRoot,
                proofBytesHash: hash512Hex(
                    sameSecretBridgeProofBytesHashDomain,
                    [proofBytes],
                ),
                proofBytesBase64: encodeStandardBase64(proofBytes),
            };

            return {
                ...proofRecordWithoutRoot,
                proofRecordRoot: deriveCanonicalObjectHash(
                    proofRecordWithoutRoot,
                ),
            };
        },
    );

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
        sameSecretConsistencyRoot: statementSet.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: statementSet.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            statementSet.sameSecretProofFamilyBindingRoot,
        sameSecretBridgeStatementSetRoot:
            statementSet.sameSecretBridgeStatementSetRoot,
        proofRecords,
    };

    return {
        ...proofMaterialSetWithoutRoot,
        proofMaterialSetRoot: deriveCanonicalObjectHash(
            proofMaterialSetWithoutRoot,
        ),
    };
};
