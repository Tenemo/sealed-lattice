// VSS public material assembly. The trustees' per-coefficient secret
// polynomial evaluations are committed with a single committed-material
// commitment per (source trustee, RNS limb, Shamir coefficient), and the whole
// set is bound by canonical object roots. The heavy cryptography lives in the
// kernel commands; this module orchestrates the per-coefficient commitment
// computation and binds the roots the accepted-setup verifier recomputes.
import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { bytesToHex } from '../common-fields.js';
import {
    canonicalGeneratedSetupProofMaterialDescriptor,
    type CanonicalGeneratedSetupProofMaterial,
} from '../setup-proof-material-transport.js';
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
// so the protocol layer never reimplements the kernel-owned commitment.
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
// protocol layer assembles the witness but never runs the kernel prover.
// The committed-material commitments carry no algebraic opening randomness,
// so the randomness arrays are always empty; the bound-message seed and
// context-hash arrays let the prover regenerate the committed trees.
export type VssShareLinkageProofInput = {
    readonly context: VssShareLinkageProofContext;
    readonly ringDegree: number;
    readonly vssShareLinkage: Record<string, unknown>;
    readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
    readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
    readonly recipientShareMessagesByItem: readonly (readonly number[])[];
    readonly recipientShareOpeningRandomnessByItem: readonly (readonly (readonly number[])[])[];
    readonly carryWitnessesByItem: readonly (readonly number[])[];
    readonly vssCommittedMaterialSeedsByBoundMessage: readonly string[];
    readonly vssCommittedMaterialContextHashesByBoundMessage: readonly string[];
    readonly proofRandomnessSeedHex: string;
    readonly proofRandomnessNonceHex: string;
};

export type VssGeneratedCanonicalProofMaterial = {
    readonly proofBytesEncoding: 'binary-chunked-proof-bytes';
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
    readonly canonicalMaterial: CanonicalGeneratedSetupProofMaterial;
};

export type VssShareLinkageProofComputer = (
    input: VssShareLinkageProofInput,
) => Promise<VssGeneratedCanonicalProofMaterial>;

// Aggregate-threshold proofs use the share-linkage relation, but their local
// setup path receives only the canonical stream reference and its external
// descriptor. The proof bytes never cross the Rust/WASM boundary as a
// whole hexadecimal or base64 string.
export type VssAggregateThresholdProofComputer = (
    input: VssShareLinkageProofInput,
) => Promise<VssGeneratedCanonicalProofMaterial>;

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
    readonly proofBytesEncoding: 'binary-chunked-proof-bytes';
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
};

export type VssAggregateThresholdProofMaterial = {
    readonly objectType: 'SetupTransportedVssShareLinkageProofMaterial';
    readonly proofFamily: 'vss-share-linkage';
    readonly proofMaterialRoot: ProtocolHash;
    readonly descriptorBytes: Uint8Array;
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

type LocalTrusteeVssPublicAggregateOpeningCredential = {
    readonly objectType: 'LocalTrusteeVssPublicAggregateOpeningCredential';
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly aggregateCommitmentRoot: ProtocolHash;
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly aggregateCommitmentMessageValuesLeHex: string;
    readonly aggregateMaterialSeedHex: string;
};

// Private setup output retained by the recipient that locally formed the
// aggregate commitment. It is never an input to public-set assembly.
export type LocalTrusteeVssPublicAggregateOpeningCredentialHandoff = {
    readonly objectType: 'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly aggregateOpeningCredentials: readonly LocalTrusteeVssPublicAggregateOpeningCredential[];
};

// One recipient's public contribution. The local creator returns this sibling
// of its private opening handoff; a relay may assemble these public
// contributions without learning any recipient-share or aggregate-opening
// credential.
type VssPublicAggregateThresholdCommitmentContribution = {
    readonly objectType: 'VssPublicAggregateThresholdCommitmentContribution';
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly recipientRecords: readonly VssPublicAggregateThresholdCommitment[];
    readonly aggregateThresholdProofs: readonly VssAggregateThresholdProofRecord[];
};

export type LocalTrusteeVssPublicAggregateThresholdCommitmentBundle = {
    readonly publicAggregateThresholdCommitmentContribution: VssPublicAggregateThresholdCommitmentContribution;
    // External canonical proof material for the public contribution. Callers
    // merge these entries into transportedVssShareLinkageProofMaterial; they
    // are never embedded in the semantic aggregate commitment set.
    readonly aggregateThresholdProofMaterials: readonly VssAggregateThresholdProofMaterial[];
    readonly localTrusteeAggregateOpeningCredentialHandoff: LocalTrusteeVssPublicAggregateOpeningCredentialHandoff;
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

const trusteeIdentitiesByRosterPosition = (input: {
    readonly participantCount: number;
    readonly sourceTrusteeOpeningStates: readonly VssPublicSourceTrusteeOpeningState[];
}): readonly string[] => {
    const trusteeIdentities = new Array<string | undefined>(
        input.participantCount,
    ).fill(undefined);
    input.sourceTrusteeOpeningStates.forEach((openingState) => {
        const rosterPosition = openingState.sourceTrusteeRosterPosition;
        if (
            rosterPosition < 0 ||
            rosterPosition >= input.participantCount ||
            trusteeIdentities[rosterPosition] !== undefined
        ) {
            throw new Error(
                'Source trustee opening states must contain each roster position exactly once.',
            );
        }
        if (openingState.sourceTrusteeIdentity.length === 0) {
            throw new Error('Source trustee identities must not be empty.');
        }
        trusteeIdentities[rosterPosition] = openingState.sourceTrusteeIdentity;
    });
    if (trusteeIdentities.some((identity) => identity === undefined)) {
        throw new Error(
            'Source trustee opening states must cover every roster position.',
        );
    }

    return trusteeIdentities as readonly string[];
};

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
    const maximumSafeCarry = BigInt(Number.MAX_SAFE_INTEGER);
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
        const carry = liftedShare / prime;
        if (carry > maximumSafeCarry) {
            throw new RangeError(
                'VSS recipient-share carry exceeds the JavaScript safe integer range',
            );
        }
        shareValues[coefficientPosition] = Number(liftedShare % prime);
        carries[coefficientPosition] = Number(carry);
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
    const recipientIdentities = trusteeIdentitiesByRosterPosition(input);
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
                    const recipientIdentity =
                        recipientIdentities[recipientRosterPosition];
                    if (recipientIdentity === undefined) {
                        throw new Error(
                            'Source trustee opening states must identify every recipient.',
                        );
                    }
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

const recipientIdentityFromCommitmentSet = (
    commitmentSet: VssPublicRecipientShareCommitmentSet,
    recipientRosterPosition: number,
): string => {
    const recordIndex = recipientRosterPosition * commitmentSet.rnsLimbCount;
    const recipientIdentity =
        commitmentSet.sourceTrusteeRecords[0]?.recipientShareCommitments[
            recordIndex
        ]?.recipientIdentity;
    if (recipientIdentity === undefined || recipientIdentity.length === 0) {
        throw new Error(
            'Recipient-share commitment set must identify every aggregate recipient.',
        );
    }
    commitmentSet.sourceTrusteeRecords.forEach((sourceRecord) => {
        const sourceRecipientIdentity =
            sourceRecord.recipientShareCommitments[recordIndex]
                ?.recipientIdentity;
        if (sourceRecipientIdentity !== recipientIdentity) {
            throw new Error(
                'Recipient-share commitment records must agree on each recipient identity.',
            );
        }
    });

    return recipientIdentity;
};

const coefficientVectorToLittleEndianHex = (
    coefficients: readonly number[],
): string => {
    const bytes = new Uint8Array(coefficients.length * 8);
    const view = new DataView(bytes.buffer);
    coefficients.forEach((coefficient, coefficientIndex) => {
        if (
            !Number.isSafeInteger(coefficient) ||
            coefficient < 0 ||
            Object.is(coefficient, -0)
        ) {
            throw new Error(
                'Aggregate commitment message coefficients must be non-negative safe integers.',
            );
        }
        view.setBigUint64(coefficientIndex * 8, BigInt(coefficient), true);
    });

    return bytesToHex(bytes);
};

// The aggregate proofs reuse the share-linkage proof family: each one is a
// unit-evaluation-point share-linkage proof showing the committed threshold
// share is the modular sum of the committed source recipient shares.
const vssAggregateThresholdProofFamily = 'vss-share-linkage';
const canonicalProofMaterialEncoding = 'binary-chunked-proof-bytes';
const protocolHashPattern = /^[0-9a-f]{128}$/u;

const assertCanonicalAggregateProofMaterial = (
    generatedProof: VssGeneratedCanonicalProofMaterial,
): Readonly<{
    readonly proofBytesHash: ProtocolHash;
    readonly proofMaterialRoot: ProtocolHash;
    readonly descriptorBytes: Uint8Array;
}> => {
    if (generatedProof.proofBytesEncoding !== canonicalProofMaterialEncoding) {
        throw new TypeError(
            'VSS aggregate threshold proof bytes must use the canonical binary chunked encoding.',
        );
    }
    if (!protocolHashPattern.test(generatedProof.proofBytesHash)) {
        throw new TypeError(
            'VSS aggregate threshold proofBytesHash must be a protocol hash.',
        );
    }
    if (!protocolHashPattern.test(generatedProof.proofMaterialRoot)) {
        throw new TypeError(
            'VSS aggregate threshold proofMaterialRoot must be a protocol hash.',
        );
    }
    const expectedProofMaterialRoot = deriveCanonicalObjectHash({
        objectType: 'SetupProofMaterialReference',
        proofFamily: vssAggregateThresholdProofFamily,
        proofBytesHash: generatedProof.proofBytesHash,
    });
    if (generatedProof.proofMaterialRoot !== expectedProofMaterialRoot) {
        throw new Error(
            'VSS aggregate threshold proofMaterialRoot must bind its proof family and proofBytesHash.',
        );
    }

    return {
        proofBytesHash: generatedProof.proofBytesHash,
        proofMaterialRoot: generatedProof.proofMaterialRoot,
        descriptorBytes: canonicalGeneratedSetupProofMaterialDescriptor(
            generatedProof.canonicalMaterial,
        ),
    };
};

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
// and whose "recipient share" is the aggregate commitment. The semantic record
// retains only the proof hash and canonical stream material root; the external
// descriptor travels as its sibling transport material.
const createVssAggregateThresholdProofRecord = async (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly ringDegree: number;
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly aggregateCredential: VssPublicAggregateThresholdCredential;
    readonly aggregateThresholdProofRandomness: VssAggregateThresholdProofRandomnessProvider;
    readonly generateVssShareLinkageProof: VssAggregateThresholdProofComputer;
}): Promise<
    Readonly<{
        readonly proofRecord: VssAggregateThresholdProofRecord;
        readonly proofMaterial: VssAggregateThresholdProofMaterial;
    }>
> => {
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
        input.coefficientCommitmentSet.sourceTrusteeRecords.find(
            (sourceRecord) =>
                sourceRecord.sourceTrusteeRosterPosition ===
                recipientRosterPosition,
        );
    const recipientSourceRecord =
        input.recipientShareCommitmentSet.sourceTrusteeRecords.find(
            (sourceRecord) =>
                sourceRecord.sourceTrusteeRosterPosition ===
                recipientRosterPosition,
        );
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
    const generatedProof = await input.generateVssShareLinkageProof({
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
        coefficientOpeningRandomnessByShamirIndex: [],
        recipientShareMessagesByItem: [aggregateCredential.aggregateMessage],
        recipientShareOpeningRandomnessByItem: [],
        carryWitnessesByItem: [aggregateCredential.wrapWitnesses],
        vssCommittedMaterialSeedsByBoundMessage,
        vssCommittedMaterialContextHashesByBoundMessage,
        proofRandomnessSeedHex: proofRandomness.seedHex,
        proofRandomnessNonceHex: proofRandomness.nonceHex,
    });
    const canonicalProofMaterial =
        assertCanonicalAggregateProofMaterial(generatedProof);

    return {
        proofRecord: {
            objectType: 'VssAggregateThresholdProofRecord',
            proofFamily: vssAggregateThresholdProofFamily,
            recipientRosterPosition,
            rnsLimbIndex,
            vssShareLinkage,
            proofBytesEncoding: canonicalProofMaterialEncoding,
            proofBytesHash: canonicalProofMaterial.proofBytesHash,
            proofMaterialRoot: canonicalProofMaterial.proofMaterialRoot,
        },
        proofMaterial: {
            objectType: 'SetupTransportedVssShareLinkageProofMaterial',
            proofFamily: vssAggregateThresholdProofFamily,
            proofMaterialRoot: canonicalProofMaterial.proofMaterialRoot,
            descriptorBytes: canonicalProofMaterial.descriptorBytes,
        },
    };
};

export const createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle =
    async (input: {
        readonly setupContext: CollectiveBgvSetupContext;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly participantCount: number;
        readonly qSharePrimes: readonly number[];
        readonly ringDegree: number;
        readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
        readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
        readonly localTrusteeRosterPosition: number;
        readonly localRecipientShareCredentials: readonly VssPublicRecipientShareCredential[];
        readonly committedMaterialSeed: VssCommittedMaterialSeedProvider;
        readonly computeVssCommittedMaterialCommitment: VssCommittedMaterialCommitmentComputer;
        readonly aggregateThresholdProofRandomness: VssAggregateThresholdProofRandomnessProvider;
        readonly generateVssShareLinkageProof: VssAggregateThresholdProofComputer;
    }): Promise<LocalTrusteeVssPublicAggregateThresholdCommitmentBundle> => {
        const recipientRosterPosition = input.localTrusteeRosterPosition;
        if (
            !Number.isSafeInteger(recipientRosterPosition) ||
            recipientRosterPosition < 0 ||
            recipientRosterPosition >= input.participantCount
        ) {
            throw new Error(
                'Local aggregate threshold commitment requires a valid recipient roster position.',
            );
        }
        if (
            input.localRecipientShareCredentials.some(
                (credential) =>
                    credential.recipientRosterPosition !==
                    recipientRosterPosition,
            )
        ) {
            throw new Error(
                'Local aggregate threshold commitment accepts credentials for exactly one recipient.',
            );
        }

        const recipientIdentity = recipientIdentityFromCommitmentSet(
            input.recipientShareCommitmentSet,
            recipientRosterPosition,
        );
        const recipientPoint = recipientRosterPosition + 1;

        const recipientRecords: VssPublicAggregateThresholdCommitment[] = [];
        const aggregateCredentials: VssPublicAggregateThresholdCredential[] =
            [];
        const aggregateOpeningCredentials: LocalTrusteeVssPublicAggregateOpeningCredential[] =
            [];
        input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
            const sourceCredentials = input.localRecipientShareCredentials
                .filter(
                    (credential) => credential.rnsLimbIndex === rnsLimbIndex,
                )
                .sort(
                    (left, right) =>
                        left.sourceTrusteeRosterPosition -
                        right.sourceTrusteeRosterPosition,
                );
            if (sourceCredentials.length !== input.participantCount) {
                throw new Error(
                    'Local aggregate threshold commitment requires one source recipient-share credential per trustee and RNS limb.',
                );
            }
            sourceCredentials.forEach(
                (credential, sourceTrusteeRosterPosition) => {
                    const sourceRecord =
                        input.recipientShareCommitmentSet.sourceTrusteeRecords.find(
                            (candidate) =>
                                candidate.sourceTrusteeRosterPosition ===
                                sourceTrusteeRosterPosition,
                        );
                    const publicRecipientShareRecord =
                        sourceRecord?.recipientShareCommitments.find(
                            (candidate) =>
                                candidate.recipientRosterPosition ===
                                    recipientRosterPosition &&
                                candidate.rnsLimbIndex === rnsLimbIndex,
                        );
                    if (
                        credential.sourceTrusteeRosterPosition !==
                            sourceTrusteeRosterPosition ||
                        credential.sourceTrusteeIdentity !==
                            sourceRecord?.sourceTrusteeIdentity ||
                        credential.rnsPrime !== rnsPrime ||
                        credential.shareValues.length !== input.ringDegree ||
                        credential.shareValues.some(
                            (coefficient) =>
                                !Number.isSafeInteger(coefficient) ||
                                coefficient < 0 ||
                                coefficient >= rnsPrime,
                        ) ||
                        credential.shareCommitmentRoot !==
                            publicRecipientShareRecord?.shareCommitmentRoot ||
                        credential.shareOpeningRoot !==
                            publicRecipientShareRecord.shareOpeningRoot ||
                        deriveCanonicalObjectHash(credential.commitment) !==
                            credential.shareCommitmentRoot
                    ) {
                        throw new Error(
                            'Local recipient-share credentials must match every accepted public recipient-share commitment.',
                        );
                    }
                },
            );

            // The threshold share is the modular sum of every source's recipient
            // share for this recipient and limb; the integer wrap of that sum is
            // the carry witness the aggregate proof binds.
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
                const wrapWitness = Number(summed / prime);
                if (!Number.isSafeInteger(wrapWitness)) {
                    throw new Error(
                        'Aggregate threshold commitment wrap witnesses must be safe integers.',
                    );
                }
                wrapWitnesses[coefficientPosition] = wrapWitness;
            }
            const commitmentContext = {
                objectType: 'VssPublicAggregateThresholdCommitmentContext',
                ...setupContextFields(input.setupContext),
                recipientIdentity,
                recipientRosterPosition,
                recipientTrusteePoint: recipientPoint,
                rnsLimbIndex,
                rnsPrime,
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
            };
            recipientRecords.push(record);
            aggregateOpeningCredentials.push({
                objectType: 'LocalTrusteeVssPublicAggregateOpeningCredential',
                recipientIdentity,
                recipientRosterPosition,
                recipientTrusteePoint: recipientPoint,
                rnsLimbIndex,
                rnsPrime,
                aggregateCommitmentRoot: computation.commitmentRoot,
                aggregateOpeningRoot: computation.openingRoot,
                aggregateCommitmentMessageValuesLeHex:
                    coefficientVectorToLittleEndianHex(aggregateMessage),
                aggregateMaterialSeedHex: materialSeedHex,
            });
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

        const aggregateThresholdProofOutputs: Awaited<
            ReturnType<typeof createVssAggregateThresholdProofRecord>
        >[] = [];
        for (const aggregateCredential of aggregateCredentials) {
            aggregateThresholdProofOutputs.push(
                await createVssAggregateThresholdProofRecord({
                    setupContext: input.setupContext,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    ringDegree: input.ringDegree,
                    coefficientCommitmentSet: input.coefficientCommitmentSet,
                    recipientShareCommitmentSet:
                        input.recipientShareCommitmentSet,
                    aggregateCredential,
                    aggregateThresholdProofRandomness:
                        input.aggregateThresholdProofRandomness,
                    generateVssShareLinkageProof:
                        input.generateVssShareLinkageProof,
                }),
            );
        }
        const aggregateThresholdProofs = aggregateThresholdProofOutputs.map(
            (output) => output.proofRecord,
        );

        return {
            publicAggregateThresholdCommitmentContribution: {
                objectType: 'VssPublicAggregateThresholdCommitmentContribution',
                trusteeIdentity: recipientIdentity,
                trusteeRosterPosition: recipientRosterPosition,
                recipientRecords,
                aggregateThresholdProofs,
            },
            aggregateThresholdProofMaterials:
                aggregateThresholdProofOutputs.map(
                    (output) => output.proofMaterial,
                ),
            localTrusteeAggregateOpeningCredentialHandoff: {
                objectType:
                    'LocalTrusteeVssPublicAggregateOpeningCredentialHandoff',
                trusteeIdentity: recipientIdentity,
                trusteeRosterPosition: recipientRosterPosition,
                aggregateOpeningCredentials,
            },
        };
    };

const aggregateProofReferenceIsCanonical = (
    proof: VssAggregateThresholdProofRecord,
): boolean =>
    proof.proofFamily === vssAggregateThresholdProofFamily &&
    proof.proofBytesEncoding === canonicalProofMaterialEncoding &&
    protocolHashPattern.test(proof.proofBytesHash) &&
    protocolHashPattern.test(proof.proofMaterialRoot) &&
    proof.proofMaterialRoot ===
        deriveCanonicalObjectHash({
            objectType: 'SetupProofMaterialReference',
            proofFamily: vssAggregateThresholdProofFamily,
            proofBytesHash: proof.proofBytesHash,
        });

export const assembleVssPublicAggregateThresholdCommitmentSet = (input: {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly publicAggregateThresholdCommitmentContributions: readonly VssPublicAggregateThresholdCommitmentContribution[];
}): VssPublicAggregateThresholdCommitmentSet => {
    if (
        input.recipientShareCommitmentSet.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        input.recipientShareCommitmentSet.participantCount !==
            input.participantCount ||
        input.recipientShareCommitmentSet.rnsLimbCount !==
            input.qSharePrimes.length ||
        input.recipientShareCommitmentSet.ringDegree !== input.ringDegree ||
        input.publicAggregateThresholdCommitmentContributions.length !==
            input.participantCount
    ) {
        throw new Error(
            'Public aggregate threshold contributions must match the accepted recipient-share commitment dimensions.',
        );
    }

    const contributions = [
        ...input.publicAggregateThresholdCommitmentContributions,
    ].sort(
        (left, right) =>
            left.trusteeRosterPosition - right.trusteeRosterPosition,
    );
    contributions.forEach((contribution, trusteeRosterPosition) => {
        const trusteeIdentity = recipientIdentityFromCommitmentSet(
            input.recipientShareCommitmentSet,
            trusteeRosterPosition,
        );
        if (
            contribution.trusteeRosterPosition !== trusteeRosterPosition ||
            contribution.trusteeIdentity !== trusteeIdentity ||
            contribution.recipientRecords.length !==
                input.qSharePrimes.length ||
            contribution.aggregateThresholdProofs.length !==
                input.qSharePrimes.length
        ) {
            throw new Error(
                'Public aggregate threshold contributions must cover every recipient and RNS limb exactly once.',
            );
        }
        input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
            const record = contribution.recipientRecords[rnsLimbIndex];
            const proof = contribution.aggregateThresholdProofs[rnsLimbIndex];
            if (
                record?.recipientIdentity !== trusteeIdentity ||
                record.recipientRosterPosition !== trusteeRosterPosition ||
                record.recipientTrusteePoint !== trusteeRosterPosition + 1 ||
                record.rnsLimbIndex !== rnsLimbIndex ||
                record.rnsPrime !== rnsPrime ||
                deriveCanonicalObjectHash(record.commitment) !==
                    record.aggregateCommitmentRoot ||
                proof?.recipientRosterPosition !== trusteeRosterPosition ||
                proof.rnsLimbIndex !== rnsLimbIndex ||
                !aggregateProofReferenceIsCanonical(proof)
            ) {
                throw new Error(
                    'Public aggregate threshold contribution coordinates and commitments must be canonical.',
                );
            }
        });
    });

    const recipientRecords = contributions.flatMap(
        (contribution) => contribution.recipientRecords,
    );
    const setWithoutRoot = {
        objectType: 'VssPublicAggregateThresholdCommitmentSet',
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        recipientRecords,
    };

    return {
        ...setWithoutRoot,
        aggregateThresholdCommitmentRoot:
            deriveCanonicalObjectHash(setWithoutRoot),
        aggregateThresholdProofs: contributions.flatMap(
            (contribution) => contribution.aggregateThresholdProofs,
        ),
    };
};
