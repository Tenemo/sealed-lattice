// VSS public material assembly. The trustees' per-coefficient secret
// polynomial evaluations are committed with a single committed-material
// commitment per (source trustee, RNS limb, Shamir coefficient), and the whole
// set is bound by canonical object roots. The heavy cryptography lives in the
// kernel commands; this module orchestrates the per-coefficient commitment
// computation and binds the roots the accepted-setup verifier recomputes.
import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { bytesFromHex } from '../common-fields.js';
import { encodeStandardBase64 } from '../proof-byte-encoding.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

export type VssCommittedMaterialCommitmentRole =
    | 'coefficient'
    | 'recipient-share'
    | 'aggregate-threshold-share';

export type VssCommittedMaterialCommitmentField = {
    readonly commitmentModulusIndex: number;
    readonly modulus: number;
    readonly materialRootHex: string;
};

// The committed-material commitment body: per-commitment-field salted Merkle
// roots over the message's canonical digit columns, derived from the holder's
// private material seed and the public commitment context. There are no public
// coordinates and no opening-randomness columns.
export type VssCommittedMaterialCommitmentValue = {
    readonly objectType: 'VssCommittedMaterialCommitment';
    readonly commitmentRole: string;
    readonly commitmentContextHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly materialColumnMaskDegree: number;
    readonly commitmentFields: readonly VssCommittedMaterialCommitmentField[];
};

export type VssCommittedMaterialCommitmentComputation = {
    readonly commitment: VssCommittedMaterialCommitmentValue;
    readonly commitmentRoot: ProtocolHash;
    readonly openingRoot: ProtocolHash;
    readonly commitmentContextHash: ProtocolHash;
};

// The kernel-backed commitment computation (bound to the WASM
// `ComputeVssCommittedMaterialCommitment` command by the SDK layer). Injected
// so the protocol layer never reimplements the certified commitment.
export type VssCommittedMaterialCommitmentComputer = (input: {
    readonly commitmentRole: VssCommittedMaterialCommitmentRole;
    readonly commitmentContext: Record<string, unknown>;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly messageCoefficientBound?: number;
    readonly messageCoefficients: readonly number[];
    readonly materialSeedHex: string;
}) => VssCommittedMaterialCommitmentComputation;

export type VssCommittedMaterialSeedRequest = {
    readonly commitmentRole: VssCommittedMaterialCommitmentRole;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    // Set for coefficient and recipient-share commitments: the committing
    // source trustee.
    readonly sourceTrusteeRosterPosition?: number;
    // Set for coefficient commitments.
    readonly shamirCoefficientIndex?: number;
    // Set for recipient-share and aggregate-threshold-share commitments.
    readonly recipientRosterPosition?: number;
};

// The holder's private deterministic material seed for one committed-material
// commitment: a 128-character lowercase hexadecimal string. The same seed must
// be threaded into every proof that opens the commitment, so the prover
// regenerates byte-identical committed-material trees; the seed itself never
// appears in the published package.
export type VssCommittedMaterialSeedProvider = (
    input: VssCommittedMaterialSeedRequest,
) => string;

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
// The committed-material commitments carry no algebraic opening randomness,
// so the randomness arrays are always empty; the bound-message seed and
// context-hash arrays let the prover regenerate the committed trees.
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
    readonly vssCommittedMaterialSeedsByBoundMessage: readonly string[];
    readonly vssCommittedMaterialContextHashesByBoundMessage: readonly string[];
    readonly proofRandomnessSeedHex: string;
    readonly proofRandomnessNonceHex: string;
}) => { readonly proofBytesHex: string };

// Typed commitment set outputs. These are the exact objects the
// accepted-setup verifier recomputes canonical roots over, so downstream
// builders (share-linkage statement and proof material) read them type-safely
// instead of casting through untyped records.
export type VssPublicCoefficientCommitment = {
    readonly objectType: 'VssPublicCoefficientCommitment';
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly coefficientOpeningRoot: ProtocolHash;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

export type VssPublicSourceCoefficientCommitments = {
    readonly objectType: string;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly coefficientCommitments: readonly VssPublicCoefficientCommitment[];
    readonly sourceCoefficientCommitmentRoot: ProtocolHash;
};

export type VssPublicCoefficientCommitmentSet = {
    readonly objectType: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly ringDegree: number;
    readonly sourceTrusteeRecords: readonly VssPublicSourceCoefficientCommitments[];
    readonly coefficientCommitmentRoot: ProtocolHash;
};

export type VssPublicRecipientShareCommitment = {
    readonly objectType: 'VssPublicRecipientShareCommitment';
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shareCommitmentRoot: ProtocolHash;
    readonly shareOpeningRoot: ProtocolHash;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

export type VssPublicSourceRecipientShareCommitments = {
    readonly objectType: string;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientShareCommitments: readonly VssPublicRecipientShareCommitment[];
    readonly sourceRecipientShareCommitmentRoot: ProtocolHash;
};

export type VssPublicRecipientShareCommitmentSet = {
    readonly objectType: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
    readonly sourceTrusteeRecords: readonly VssPublicSourceRecipientShareCommitments[];
    readonly recipientShareCommitmentRoot: ProtocolHash;
};

export type VssPublicAggregateThresholdCommitment = {
    readonly objectType: 'VssPublicAggregateThresholdCommitment';
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly aggregateCommitmentRoot: ProtocolHash;
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly commitment: VssCommittedMaterialCommitmentValue;
    readonly sourceShareCommitmentRoots: readonly ProtocolHash[];
    readonly sourceShareOpeningRoots: readonly ProtocolHash[];
};

// The proven "aggregate equals modular sum of the source shares" binding for
// one aggregate record: a share-linkage proof with a unit evaluation point
// whose "coefficients" are the source recipient-share commitments and whose
// "recipient share" is the aggregate commitment.
export type VssAggregateThresholdProofRecord = {
    readonly objectType: 'VssAggregateThresholdProofRecord';
    readonly proofFamily: string;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly vssShareLinkage: Record<string, unknown>;
    readonly proofBytesHash: string;
    readonly proofBytesBase64: string;
};

export type VssPublicAggregateThresholdCommitmentSet = {
    readonly objectType: string;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
    readonly recipientRecords: readonly VssPublicAggregateThresholdCommitment[];
    readonly aggregateThresholdCommitmentRoot: ProtocolHash;
    // A sibling of the committed records, excluded from the set root: each
    // proof is bound by its own statement, which references the committed
    // roots the set root already covers.
    readonly aggregateThresholdProofs: readonly VssAggregateThresholdProofRecord[];
};

export type VssPublicCoefficientOpening = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientMessage: readonly number[];
};

export type VssPublicSourceTrusteeOpeningState = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly coefficientOpenings: readonly VssPublicCoefficientOpening[];
};

// The source trustee's per-coefficient opening witness (message plus the exact
// private material seed and public context hash of the committed-material
// commitment). Carried out of the coefficient-set builder so the share-linkage
// and bridge proofs regenerate the same committed trees the set bound, rather
// than re-deriving a seed and risking a mismatch.
export type VssPublicCoefficientCredential = {
    readonly sourceTrusteeRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientMessage: readonly number[];
    readonly materialSeedHex: string;
    readonly commitmentContextHash: ProtocolHash;
};

type VssPublicCoefficientCommitmentBundle = {
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly coefficientCredentials: readonly VssPublicCoefficientCredential[];
};

type VssPublicSetupContextFields = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
};

export const setupContextFields = (
    setupContext: CollectiveBgvSetupContext,
): VssPublicSetupContextFields => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupParametersHash: setupContext.setupParametersHash,
    setupEpoch: setupContext.setupEpoch,
});

const openingCoordinateKey = (
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): string => `${String(rnsLimbIndex)}:${String(shamirCoefficientIndex)}`;

export const createVssPublicCoefficientCommitmentSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningStates: readonly VssPublicSourceTrusteeOpeningState[];
    readonly committedMaterialSeed: VssCommittedMaterialSeedProvider;
    readonly computeVssCommittedMaterialCommitment: VssCommittedMaterialCommitmentComputer;
}): VssPublicCoefficientCommitmentBundle => {
    const coefficientCredentials: VssPublicCoefficientCredential[] = [];
    const sourceTrusteeRecords = [...input.sourceTrusteeOpeningStates]
        .sort(
            (left, right) =>
                left.sourceTrusteeRosterPosition -
                right.sourceTrusteeRosterPosition,
        )
        .map(
            (
                sourceTrusteeOpeningState,
            ): VssPublicSourceCoefficientCommitments => {
                const openingsByCoordinate = new Map(
                    sourceTrusteeOpeningState.coefficientOpenings.map(
                        (opening) => [
                            openingCoordinateKey(
                                opening.rnsLimbIndex,
                                opening.shamirCoefficientIndex,
                            ),
                            opening,
                        ],
                    ),
                );
                const coefficientCommitments: VssPublicCoefficientCommitment[] =
                    [];
                input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
                    for (
                        let shamirCoefficientIndex = 0;
                        shamirCoefficientIndex < input.thresholdDegree;
                        shamirCoefficientIndex += 1
                    ) {
                        const opening = openingsByCoordinate.get(
                            openingCoordinateKey(
                                rnsLimbIndex,
                                shamirCoefficientIndex,
                            ),
                        );
                        if (opening === undefined) {
                            throw new Error(
                                'Source trustee coefficient openings must cover every VSS coefficient coordinate.',
                            );
                        }
                        if (opening.rnsPrime !== rnsPrime) {
                            throw new Error(
                                'Source trustee coefficient opening RNS primes must match qSharePrimes.',
                            );
                        }
                        const commitmentContext = {
                            objectType: 'VssPublicCoefficientCommitmentContext',
                            ...setupContextFields(input.setupContext),
                            sourceTrusteeIdentity:
                                sourceTrusteeOpeningState.sourceTrusteeIdentity,
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            rnsLimbIndex,
                            rnsPrime,
                            shamirCoefficientIndex,
                        };
                        const materialSeedHex = input.committedMaterialSeed({
                            commitmentRole: 'coefficient',
                            rnsLimbIndex,
                            rnsPrime,
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            shamirCoefficientIndex,
                        });
                        const computation =
                            input.computeVssCommittedMaterialCommitment({
                                commitmentRole: 'coefficient',
                                commitmentContext,
                                rnsLimbIndex,
                                rnsPrime,
                                ringDegree: input.ringDegree,
                                messageCoefficientBound: rnsPrime,
                                messageCoefficients: opening.coefficientMessage,
                                materialSeedHex,
                            });
                        coefficientCommitments.push({
                            objectType: 'VssPublicCoefficientCommitment',
                            sourceTrusteeIdentity:
                                sourceTrusteeOpeningState.sourceTrusteeIdentity,
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            rnsLimbIndex,
                            rnsPrime,
                            shamirCoefficientIndex,
                            coefficientCommitmentRoot:
                                computation.commitmentRoot,
                            coefficientOpeningRoot: computation.openingRoot,
                            commitment: computation.commitment,
                        });
                        coefficientCredentials.push({
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            rnsLimbIndex,
                            rnsPrime,
                            shamirCoefficientIndex,
                            coefficientMessage: opening.coefficientMessage,
                            materialSeedHex,
                            commitmentContextHash:
                                computation.commitmentContextHash,
                        });
                    }
                });

                const sourceRecordWithoutRoot = {
                    objectType: 'VssPublicSourceCoefficientCommitments',
                    sourceTrusteeIdentity:
                        sourceTrusteeOpeningState.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    coefficientCommitments,
                };

                return {
                    ...sourceRecordWithoutRoot,
                    sourceCoefficientCommitmentRoot: deriveCanonicalObjectHash(
                        sourceRecordWithoutRoot,
                    ),
                };
            },
        );

    const setWithoutRoot = {
        objectType: 'VssPublicCoefficientCommitmentSet',
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        thresholdDegree: input.thresholdDegree,
        ringDegree: input.ringDegree,
        sourceTrusteeRecords,
    };

    return {
        coefficientCommitmentSet: {
            ...setWithoutRoot,
            coefficientCommitmentRoot:
                deriveCanonicalObjectHash(setWithoutRoot),
        },
        coefficientCredentials,
    };
};

export type VssPublicRecipientShareCredential = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shareValues: readonly number[];
    readonly carries: readonly number[];
    readonly materialSeedHex: string;
    readonly commitmentContextHash: ProtocolHash;
    readonly shareCommitmentRoot: ProtocolHash;
    readonly shareOpeningRoot: ProtocolHash;
    readonly commitment: VssCommittedMaterialCommitmentValue;
};

type VssPublicRecipientShareCommitmentBundle = {
    readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly recipientShareCredentials: readonly VssPublicRecipientShareCredential[];
};

// The recipient's Shamir share of a source trustee's coefficient polynomial,
// evaluated at the recipient's canonical point (recipientRosterPosition + 1) and
// decomposed into the residue (the committed share value) and the integer carry
// the kernel's share-linkage proof binds. Computed in BigInt because the lifted
// pre-reduction share can exceed the safe-integer range.
const vssPublicRecipientShareValuesAndCarries = (input: {
    readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
    readonly recipientPoint: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
}): { readonly shareValues: number[]; readonly carries: number[] } => {
    const point = BigInt(input.recipientPoint);
    const prime = BigInt(input.rnsPrime);
    const shareValues = new Array<number>(input.ringDegree).fill(0);
    const carries = new Array<number>(input.ringDegree).fill(0);
    for (
        let coefficientPosition = 0;
        coefficientPosition < input.ringDegree;
        coefficientPosition += 1
    ) {
        let liftedShare = 0n;
        let pointPower = 1n;
        input.coefficientMessagesByShamirIndex.forEach((messages) => {
            liftedShare += BigInt(messages[coefficientPosition]) * pointPower;
            pointPower *= point;
        });
        shareValues[coefficientPosition] = Number(liftedShare % prime);
        carries[coefficientPosition] = Number(liftedShare / prime);
    }

    return { shareValues, carries };
};

export const createVssPublicRecipientShareCommitmentSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningStates: readonly VssPublicSourceTrusteeOpeningState[];
    readonly committedMaterialSeed: VssCommittedMaterialSeedProvider;
    readonly computeVssCommittedMaterialCommitment: VssCommittedMaterialCommitmentComputer;
}): VssPublicRecipientShareCommitmentBundle => {
    const recipientShareCredentials: VssPublicRecipientShareCredential[] = [];
    const sourceTrusteeRecords = [...input.sourceTrusteeOpeningStates]
        .sort(
            (left, right) =>
                left.sourceTrusteeRosterPosition -
                right.sourceTrusteeRosterPosition,
        )
        .map(
            (
                sourceTrusteeOpeningState,
            ): VssPublicSourceRecipientShareCommitments => {
                const openingsByCoordinate = new Map(
                    sourceTrusteeOpeningState.coefficientOpenings.map(
                        (opening) => [
                            openingCoordinateKey(
                                opening.rnsLimbIndex,
                                opening.shamirCoefficientIndex,
                            ),
                            opening,
                        ],
                    ),
                );
                const recipientShareCommitments: VssPublicRecipientShareCommitment[] =
                    [];
                for (
                    let recipientRosterPosition = 0;
                    recipientRosterPosition < input.participantCount;
                    recipientRosterPosition += 1
                ) {
                    const recipientIdentity = `trustee-${String(recipientRosterPosition)}`;
                    const recipientPoint = recipientRosterPosition + 1;
                    input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
                        const coefficientMessagesByShamirIndex: number[][] = [];
                        for (
                            let shamirCoefficientIndex = 0;
                            shamirCoefficientIndex < input.thresholdDegree;
                            shamirCoefficientIndex += 1
                        ) {
                            const opening = openingsByCoordinate.get(
                                openingCoordinateKey(
                                    rnsLimbIndex,
                                    shamirCoefficientIndex,
                                ),
                            );
                            if (opening === undefined) {
                                throw new Error(
                                    'Source trustee coefficient openings must cover every VSS coefficient coordinate.',
                                );
                            }
                            coefficientMessagesByShamirIndex.push([
                                ...opening.coefficientMessage,
                            ]);
                        }
                        const { shareValues, carries } =
                            vssPublicRecipientShareValuesAndCarries({
                                coefficientMessagesByShamirIndex,
                                recipientPoint,
                                rnsPrime,
                                ringDegree: input.ringDegree,
                            });
                        const commitmentContext = {
                            objectType:
                                'VssPublicRecipientShareCommitmentContext',
                            ...setupContextFields(input.setupContext),
                            sourceTrusteeIdentity:
                                sourceTrusteeOpeningState.sourceTrusteeIdentity,
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            recipientIdentity,
                            recipientRosterPosition,
                            recipientTrusteePoint: recipientPoint,
                            rnsLimbIndex,
                            rnsPrime,
                        };
                        const materialSeedHex = input.committedMaterialSeed({
                            commitmentRole: 'recipient-share',
                            rnsLimbIndex,
                            rnsPrime,
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            recipientRosterPosition,
                        });
                        const computation =
                            input.computeVssCommittedMaterialCommitment({
                                commitmentRole: 'recipient-share',
                                commitmentContext,
                                rnsLimbIndex,
                                rnsPrime,
                                ringDegree: input.ringDegree,
                                messageCoefficientBound: rnsPrime,
                                messageCoefficients: shareValues,
                                materialSeedHex,
                            });
                        recipientShareCommitments.push({
                            objectType: 'VssPublicRecipientShareCommitment',
                            sourceTrusteeIdentity:
                                sourceTrusteeOpeningState.sourceTrusteeIdentity,
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            recipientIdentity,
                            recipientRosterPosition,
                            recipientTrusteePoint: recipientPoint,
                            rnsLimbIndex,
                            rnsPrime,
                            shareCommitmentRoot: computation.commitmentRoot,
                            shareOpeningRoot: computation.openingRoot,
                            commitment: computation.commitment,
                        });
                        recipientShareCredentials.push({
                            sourceTrusteeIdentity:
                                sourceTrusteeOpeningState.sourceTrusteeIdentity,
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            recipientRosterPosition,
                            rnsLimbIndex,
                            rnsPrime,
                            shareValues,
                            carries,
                            materialSeedHex,
                            commitmentContextHash:
                                computation.commitmentContextHash,
                            shareCommitmentRoot: computation.commitmentRoot,
                            shareOpeningRoot: computation.openingRoot,
                            commitment: computation.commitment,
                        });
                    });
                }

                const sourceRecordWithoutRoot = {
                    objectType: 'VssPublicSourceRecipientShareCommitments',
                    sourceTrusteeIdentity:
                        sourceTrusteeOpeningState.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                    recipientShareCommitments,
                };

                return {
                    ...sourceRecordWithoutRoot,
                    sourceRecipientShareCommitmentRoot:
                        deriveCanonicalObjectHash(sourceRecordWithoutRoot),
                };
            },
        );

    const setWithoutRoot = {
        objectType: 'VssPublicRecipientShareCommitmentSet',
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        sourceTrusteeRecords,
    };

    return {
        recipientShareCommitmentSet: {
            ...setWithoutRoot,
            recipientShareCommitmentRoot:
                deriveCanonicalObjectHash(setWithoutRoot),
        },
        recipientShareCredentials,
    };
};

const aggregateCoordinateGroupKey = (
    recipientRosterPosition: number,
    rnsLimbIndex: number,
): string => `${String(recipientRosterPosition)}:${String(rnsLimbIndex)}`;

// The aggregate proofs reuse the share-linkage proof family: each one is a
// unit-evaluation-point share-linkage proof showing the committed threshold
// share is the modular sum of the committed source recipient shares.
const vssAggregateThresholdProofFamily = 'vss-share-linkage';
const vssAggregateThresholdProofBytesHashDomain =
    'sealed-lattice/setup/vss-aggregate-threshold/proof-bytes';

// Fresh prover blinding randomness per aggregate proof record. The proof is
// zero-knowledge, so this is independent per (recipient, RNS limb) and binds
// nothing the verifier recomputes.
type VssAggregateThresholdProofRandomnessProvider = (input: {
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
}) => { readonly seedHex: string; readonly nonceHex: string };

// The per-record aggregation witness: the modular-sum message the aggregate
// record committed, the integer wrap values of that sum, and the material seed
// that built the aggregate commitment, kept alongside the summand credentials
// so the aggregate proof opens exactly the committed trees.
type VssPublicAggregateThresholdCredential = {
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly aggregateMessage: readonly number[];
    readonly wrapWitnesses: readonly number[];
    readonly materialSeedHex: string;
    readonly sourceCredentials: readonly VssPublicRecipientShareCredential[];
    readonly record: VssPublicAggregateThresholdCommitment;
};

// One aggregate threshold proof record: a unit-evaluation-point share-linkage
// statement whose "coefficients" are the source recipient-share commitments
// and whose "recipient share" is the aggregate commitment, plus the proof
// bytes the injected kernel prover produced for it.
const createVssAggregateThresholdProofRecord = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly aggregateCredential: VssPublicAggregateThresholdCredential;
    readonly aggregateThresholdProofRandomness: VssAggregateThresholdProofRandomnessProvider;
    readonly generateVssShareLinkageProof: VssShareLinkageProofComputer;
}): VssAggregateThresholdProofRecord => {
    const { aggregateCredential } = input;
    const {
        recipientRosterPosition,
        rnsLimbIndex,
        rnsPrime,
        sourceCredentials,
        record,
    } = aggregateCredential;
    const recipientIdentity = record.recipientIdentity;
    const coefficientSourceRecord =
        input.coefficientCommitmentSet.sourceTrusteeRecords[
            recipientRosterPosition
        ];
    const recipientSourceRecord =
        input.recipientShareCommitmentSet.sourceTrusteeRecords[
            recipientRosterPosition
        ];
    if (
        coefficientSourceRecord === undefined ||
        recipientSourceRecord === undefined
    ) {
        throw new Error(
            'Aggregate threshold proof requires source records for every recipient roster position.',
        );
    }

    const statementWithoutRoot = {
        objectType: 'VssShareLinkageStatement',
        isThresholdAggregate: true,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        sourceTrusteeIdentity: recipientIdentity,
        sourceTrusteeRosterPosition: recipientRosterPosition,
        sourceCoefficientCommitmentRoot:
            coefficientSourceRecord.sourceCoefficientCommitmentRoot,
        sourceRecipientShareCommitmentRoot:
            recipientSourceRecord.sourceRecipientShareCommitmentRoot,
        recipientIdentity,
        recipientRosterPosition,
        sourceRnsLimbIndex: rnsLimbIndex,
        sourceMessageModulus: rnsPrime,
        coefficientCommitmentRoots: sourceCredentials.map(
            (credential) => credential.shareCommitmentRoot,
        ),
        coefficientOpeningRoots: sourceCredentials.map(
            (credential) => credential.shareOpeningRoot,
        ),
        coefficientCommitments: sourceCredentials.map(
            (credential) => credential.commitment,
        ),
        recipientShareCommitmentRoot: record.aggregateCommitmentRoot,
        recipientShareOpeningRoot: record.aggregateOpeningRoot,
        recipientShareCommitment: record.commitment,
        additionalLinkageItems: [],
    };
    const vssShareLinkage = {
        ...statementWithoutRoot,
        shareLinkageStatementRoot:
            deriveCanonicalObjectHash(statementWithoutRoot),
    };

    // Bound-commitment order: the summand slots (the source recipient-share
    // commitments in source order), then the single aggregate recipient
    // share. Context hashes are read off the published commitments; the seeds
    // are the same seeds those commitments were created with.
    const vssCommittedMaterialSeedsByBoundMessage = [
        ...sourceCredentials.map((credential) => credential.materialSeedHex),
        aggregateCredential.materialSeedHex,
    ];
    const vssCommittedMaterialContextHashesByBoundMessage = [
        ...sourceCredentials.map(
            (credential) => credential.commitment.commitmentContextHash,
        ),
        record.commitment.commitmentContextHash,
    ];

    const proofRandomness = input.aggregateThresholdProofRandomness({
        recipientRosterPosition,
        rnsLimbIndex,
    });
    const generatedProof = input.generateVssShareLinkageProof({
        context: {
            ceremonyId: input.setupContext.ceremonyId,
            manifestHash: input.setupContext.manifestHash,
            rosterHash: input.setupContext.rosterHash,
            trusteeIdentity: 'vss-aggregate-threshold',
            trusteeRosterPosition: 0,
            setupEpoch: input.setupContext.setupEpoch,
            shareLinkageStatementRoot:
                vssShareLinkage.shareLinkageStatementRoot,
        },
        ringDegree: input.ringDegree,
        vssShareLinkage,
        coefficientMessagesByShamirIndex: sourceCredentials.map(
            (credential) => credential.shareValues,
        ),
        recipientShareMessages: aggregateCredential.aggregateMessage,
        coefficientOpeningRandomnessByShamirIndex: [],
        recipientShareOpeningRandomness: [],
        carryWitnesses: aggregateCredential.wrapWitnesses,
        recipientShareMessagesByItem: [aggregateCredential.aggregateMessage],
        recipientShareOpeningRandomnessByItem: [],
        carryWitnessesByItem: [aggregateCredential.wrapWitnesses],
        vssCommittedMaterialSeedsByBoundMessage,
        vssCommittedMaterialContextHashesByBoundMessage,
        proofRandomnessSeedHex: proofRandomness.seedHex,
        proofRandomnessNonceHex: proofRandomness.nonceHex,
    });
    const proofBytes = bytesFromHex(
        generatedProof.proofBytesHex,
        'VSS aggregate threshold proofBytesHex',
    );

    return {
        objectType: 'VssAggregateThresholdProofRecord',
        proofFamily: vssAggregateThresholdProofFamily,
        recipientRosterPosition,
        rnsLimbIndex,
        vssShareLinkage,
        proofBytesHash: hash512Hex(vssAggregateThresholdProofBytesHashDomain, [
            proofBytes,
        ]),
        proofBytesBase64: encodeStandardBase64(proofBytes),
    };
};

export const createVssPublicAggregateThresholdCommitmentSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly recipientShareCredentials: readonly VssPublicRecipientShareCredential[];
    readonly committedMaterialSeed: VssCommittedMaterialSeedProvider;
    readonly computeVssCommittedMaterialCommitment: VssCommittedMaterialCommitmentComputer;
    readonly aggregateThresholdProofRandomness: VssAggregateThresholdProofRandomnessProvider;
    readonly generateVssShareLinkageProof: VssShareLinkageProofComputer;
}): VssPublicAggregateThresholdCommitmentSet => {
    const credentialsByCoordinate = new Map<
        string,
        VssPublicRecipientShareCredential[]
    >();
    input.recipientShareCredentials.forEach((credential) => {
        const key = aggregateCoordinateGroupKey(
            credential.recipientRosterPosition,
            credential.rnsLimbIndex,
        );
        const group = credentialsByCoordinate.get(key);
        if (group === undefined) {
            credentialsByCoordinate.set(key, [credential]);
        } else {
            group.push(credential);
        }
    });

    const recipientRecords: VssPublicAggregateThresholdCommitment[] = [];
    const aggregateCredentials: VssPublicAggregateThresholdCredential[] = [];
    for (
        let recipientRosterPosition = 0;
        recipientRosterPosition < input.participantCount;
        recipientRosterPosition += 1
    ) {
        const recipientIdentity = `trustee-${String(recipientRosterPosition)}`;
        const recipientPoint = recipientRosterPosition + 1;
        input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
            const sourceCredentials = [
                ...(credentialsByCoordinate.get(
                    aggregateCoordinateGroupKey(
                        recipientRosterPosition,
                        rnsLimbIndex,
                    ),
                ) ?? []),
            ].sort(
                (left, right) =>
                    left.sourceTrusteeRosterPosition -
                    right.sourceTrusteeRosterPosition,
            );
            if (sourceCredentials.length !== input.participantCount) {
                throw new Error(
                    'Aggregate threshold commitment requires one source recipient-share commitment per trustee.',
                );
            }
            const sourceShareCommitmentRoots = sourceCredentials.map(
                (credential) => credential.shareCommitmentRoot,
            );
            const sourceShareOpeningRoots = sourceCredentials.map(
                (credential) => credential.shareOpeningRoot,
            );
            // The threshold share is the modular sum of every source's
            // recipient share for this recipient and limb; the integer wrap of
            // that sum is the carry witness the aggregate proof binds.
            // Computed in BigInt because the pre-reduction sum can approach
            // the safe-integer range.
            const prime = BigInt(rnsPrime);
            const aggregateMessage = new Array<number>(input.ringDegree).fill(
                0,
            );
            const wrapWitnesses = new Array<number>(input.ringDegree).fill(0);
            for (
                let coefficientPosition = 0;
                coefficientPosition < input.ringDegree;
                coefficientPosition += 1
            ) {
                let summed = 0n;
                sourceCredentials.forEach((credential) => {
                    summed += BigInt(
                        credential.shareValues[coefficientPosition],
                    );
                });
                aggregateMessage[coefficientPosition] = Number(summed % prime);
                wrapWitnesses[coefficientPosition] = Number(summed / prime);
            }
            const commitmentContext = {
                objectType: 'VssPublicAggregateThresholdCommitmentContext',
                ...setupContextFields(input.setupContext),
                recipientIdentity,
                recipientRosterPosition,
                recipientTrusteePoint: recipientPoint,
                rnsLimbIndex,
                rnsPrime,
                sourceShareCommitmentRoots,
                sourceShareOpeningRoots,
            };
            const materialSeedHex = input.committedMaterialSeed({
                commitmentRole: 'aggregate-threshold-share',
                rnsLimbIndex,
                rnsPrime,
                recipientRosterPosition,
            });
            const computation = input.computeVssCommittedMaterialCommitment({
                commitmentRole: 'aggregate-threshold-share',
                commitmentContext,
                rnsLimbIndex,
                rnsPrime,
                ringDegree: input.ringDegree,
                messageCoefficientBound: rnsPrime,
                messageCoefficients: aggregateMessage,
                materialSeedHex,
            });
            const record: VssPublicAggregateThresholdCommitment = {
                objectType: 'VssPublicAggregateThresholdCommitment',
                recipientIdentity,
                recipientRosterPosition,
                recipientTrusteePoint: recipientPoint,
                rnsLimbIndex,
                rnsPrime,
                aggregateCommitmentRoot: computation.commitmentRoot,
                aggregateOpeningRoot: computation.openingRoot,
                commitment: computation.commitment,
                sourceShareCommitmentRoots,
                sourceShareOpeningRoots,
            };
            recipientRecords.push(record);
            aggregateCredentials.push({
                recipientRosterPosition,
                rnsLimbIndex,
                rnsPrime,
                aggregateMessage,
                wrapWitnesses,
                materialSeedHex,
                sourceCredentials,
                record,
            });
        });
    }

    const setWithoutRoot = {
        objectType: 'VssPublicAggregateThresholdCommitmentSet',
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        recipientRecords,
    };
    const aggregateThresholdCommitmentRoot =
        deriveCanonicalObjectHash(setWithoutRoot);

    // The proven "aggregate equals sum" bindings are a sibling of the records,
    // added after the set root so they are bound by their own statements
    // (which reference the committed roots), not folded into the commitment
    // set root.
    const aggregateThresholdProofs = aggregateCredentials.map(
        (aggregateCredential): VssAggregateThresholdProofRecord =>
            createVssAggregateThresholdProofRecord({
                setupContext: input.setupContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                ringDegree: input.ringDegree,
                coefficientCommitmentSet: input.coefficientCommitmentSet,
                recipientShareCommitmentSet: input.recipientShareCommitmentSet,
                aggregateCredential,
                aggregateThresholdProofRandomness:
                    input.aggregateThresholdProofRandomness,
                generateVssShareLinkageProof:
                    input.generateVssShareLinkageProof,
            }),
    );

    return {
        ...setWithoutRoot,
        aggregateThresholdCommitmentRoot,
        aggregateThresholdProofs,
    };
};
