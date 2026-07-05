// Compact VSS public material assembly. The trustees' per-coefficient secret
// polynomial evaluations are committed with a single covered-message compact
// commitment per (source trustee, RNS limb, Shamir coefficient), and the whole
// set is bound by canonical object roots. The heavy cryptography lives in the
// kernel commands; this module orchestrates the per-coefficient commitment
// computation and binds the roots the accepted-setup verifier recomputes.
import { deriveCanonicalObjectHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type {
    SameSecretConsistencyStatementSet,
    SameSecretProofSet,
} from './same-secret-consistency-records.js';
import {
    setupProofMaterialRecordTransportMetadataFields,
    setupProofMaterialReferenceFields,
    setupProofMaterialTransportChunks,
    setupProofMaterialTransportMetadata,
    setupTransportedProofMaterialFields,
    type TransportedSetupProofMaterialSet,
} from './setup-proof-material-transport.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

// Two base-3^17 message digits per coefficient. The kernel validates that the
// canonical digit columns reproduce the message coefficients, so they must be
// derived exactly this way (little-endian digits, transposed into columns).
const vssPublicMessageDigitBase = 3 ** 17;
const vssPublicMessageDigitCount = 2;

const vssPublicCanonicalMessageDigitColumns = (
    messageCoefficients: readonly number[],
): number[][] => {
    const ringDegree = messageCoefficients.length;
    const columns: number[][] = Array.from(
        { length: vssPublicMessageDigitCount },
        () => new Array<number>(ringDegree).fill(0),
    );
    messageCoefficients.forEach((coefficient, coefficientIndex) => {
        let remaining = coefficient;
        for (
            let digitIndex = 0;
            digitIndex < vssPublicMessageDigitCount;
            digitIndex += 1
        ) {
            columns[digitIndex][coefficientIndex] =
                remaining % vssPublicMessageDigitBase;
            remaining = Math.floor(remaining / vssPublicMessageDigitBase);
        }
    });

    return columns;
};

export type VssPublicCommitmentOpeningInput = {
    readonly commitmentRole:
        | 'coefficient'
        | 'recipient-share'
        | 'aggregate-threshold-share';
    readonly commitmentContext: Record<string, unknown>;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly messageCoefficientBound?: number;
    readonly messageCoefficients: readonly number[];
    readonly messageDigitColumns: readonly (readonly number[])[];
    readonly randomnessByColumn: readonly (readonly number[])[];
};

export type VssPublicCommitmentLimbValue = {
    readonly commitmentModulusIndex: number;
    readonly modulus: number;
    readonly coordinates: readonly number[];
};

export type VssPublicCommitmentValue = {
    readonly objectType: 'VssPublicCommitment';
    readonly objectVersion: number;
    readonly commitmentRole: string;
    readonly commitmentContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly outputCoordinateCount: number;
    readonly randomnessColumnCount: number;
    readonly commitmentLimbs: readonly VssPublicCommitmentLimbValue[];
};

export type VssPublicCommitmentComputation = {
    readonly commitment: VssPublicCommitmentValue;
    readonly commitmentRoot: ProtocolHash;
    readonly openingRoot: ProtocolHash;
};

// The kernel-backed compact commitment computation (bound to the WASM
// `ComputeVssPublicCommitmentFromOpening` command by the SDK layer). Injected
// so the protocol layer never reimplements the certified commitment.
export type VssPublicCommitmentComputer = (
    input: VssPublicCommitmentOpeningInput,
) => VssPublicCommitmentComputation;

// Typed compact commitment set outputs. These are the exact objects the
// accepted-setup verifier recomputes canonical roots over, so downstream
// builders (share-linkage statement and proof material) read them type-safely
// instead of casting through untyped records.
export type VssPublicCoefficientCommitment = {
    readonly objectType: 'VssPublicCoefficientCommitment';
    readonly objectVersion: number;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly coefficientOpeningRoot: ProtocolHash;
    readonly commitment: VssPublicCommitmentValue;
};

export type VssPublicSourceCoefficientCommitments = {
    readonly objectType: string;
    readonly objectVersion: number;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly coefficientCommitments: readonly VssPublicCoefficientCommitment[];
    readonly sourceCoefficientCommitmentRoot: ProtocolHash;
};

export type VssPublicCoefficientCommitmentSet = {
    readonly objectType: string;
    readonly objectVersion: number;
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
    readonly objectVersion: number;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shareCommitmentRoot: ProtocolHash;
    readonly shareOpeningRoot: ProtocolHash;
    readonly commitment: VssPublicCommitmentValue;
};

export type VssPublicSourceRecipientShareCommitments = {
    readonly objectType: string;
    readonly objectVersion: number;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientShareCommitments: readonly VssPublicRecipientShareCommitment[];
    readonly sourceRecipientShareCommitmentRoot: ProtocolHash;
};

export type VssPublicRecipientShareCommitmentSet = {
    readonly objectType: string;
    readonly objectVersion: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
    readonly sourceTrusteeRecords: readonly VssPublicSourceRecipientShareCommitments[];
    readonly recipientShareCommitmentRoot: ProtocolHash;
};

export type VssPublicAggregateThresholdCommitment = {
    readonly objectType: 'VssPublicAggregateThresholdCommitment';
    readonly objectVersion: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly aggregateCommitmentRoot: ProtocolHash;
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly commitment: VssPublicCommitmentValue;
    readonly sourceShareCommitmentRoots: readonly ProtocolHash[];
    readonly sourceShareOpeningRoots: readonly ProtocolHash[];
};

export type VssPublicAggregateThresholdCommitmentSet = {
    readonly objectType: string;
    readonly objectVersion: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
    readonly recipientRecords: readonly VssPublicAggregateThresholdCommitment[];
    readonly aggregateThresholdCommitmentRoot: ProtocolHash;
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

type VssPublicCoefficientOpeningRandomnessProvider = (input: {
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly ringDegree: number;
}) => readonly (readonly number[])[];

// The source trustee's per-coefficient opening witness (message plus the exact
// commitment randomness). Carried out of the coefficient-set builder so the
// share-linkage proof opens the same commitments the set bound, rather than
// re-deriving randomness and risking a mismatch.
export type VssPublicCoefficientCredential = {
    readonly sourceTrusteeRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientMessage: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
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

const setupContextFields = (
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
    readonly coefficientOpeningRandomness: VssPublicCoefficientOpeningRandomnessProvider;
    readonly computeVssPublicCommitment: VssPublicCommitmentComputer;
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
                                'Source trustee coefficient openings must cover every compact VSS coefficient coordinate.',
                            );
                        }
                        if (opening.rnsPrime !== rnsPrime) {
                            throw new Error(
                                'Source trustee coefficient opening RNS primes must match qSharePrimes.',
                            );
                        }
                        const commitmentContext = {
                            objectType:
                                'VssPublicCoefficientCommitmentContext',
                            objectVersion: 1,
                            ...setupContextFields(input.setupContext),
                            sourceTrusteeIdentity:
                                sourceTrusteeOpeningState.sourceTrusteeIdentity,
                            sourceTrusteeRosterPosition:
                                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                            rnsLimbIndex,
                            rnsPrime,
                            shamirCoefficientIndex,
                        };
                        const randomnessByColumn =
                            input.coefficientOpeningRandomness({
                                trusteeIdentity:
                                    sourceTrusteeOpeningState.sourceTrusteeIdentity,
                                trusteeRosterPosition:
                                    sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                                rnsLimbIndex,
                                rnsPrime,
                                shamirCoefficientIndex,
                                ringDegree: input.ringDegree,
                            });
                        const computation = input.computeVssPublicCommitment({
                            commitmentRole: 'coefficient',
                            commitmentContext,
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            rnsLimbIndex,
                            rnsPrime,
                            ringDegree: input.ringDegree,
                            messageCoefficientBound: rnsPrime,
                            messageCoefficients: opening.coefficientMessage,
                            messageDigitColumns:
                                vssPublicCanonicalMessageDigitColumns(
                                    opening.coefficientMessage,
                                ),
                            randomnessByColumn,
                        });
                        coefficientCommitments.push({
                            objectType: 'VssPublicCoefficientCommitment',
                            objectVersion: 1,
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
                            randomnessByColumn,
                        });
                    }
                });

                const sourceRecordWithoutRoot = {
                    objectType: 'VssPublicSourceCoefficientCommitments',
                    objectVersion: 1,
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
        objectVersion: 1,
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

type VssPublicRecipientShareOpeningRandomnessProvider = (input: {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
}) => readonly (readonly number[])[];

type VssPublicRecipientShareCredential = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shareValues: readonly number[];
    readonly carries: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
    readonly shareCommitmentRoot: ProtocolHash;
    readonly shareOpeningRoot: ProtocolHash;
    readonly commitment: VssPublicCommitmentValue;
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
    readonly recipientShareOpeningRandomness: VssPublicRecipientShareOpeningRandomnessProvider;
    readonly computeVssPublicCommitment: VssPublicCommitmentComputer;
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
                                    'Source trustee coefficient openings must cover every compact VSS coefficient coordinate.',
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
                        const randomnessByColumn =
                            input.recipientShareOpeningRandomness({
                                sourceTrusteeIdentity:
                                    sourceTrusteeOpeningState.sourceTrusteeIdentity,
                                sourceTrusteeRosterPosition:
                                    sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                                recipientRosterPosition,
                                rnsLimbIndex,
                                rnsPrime,
                                ringDegree: input.ringDegree,
                            });
                        const commitmentContext = {
                            objectType:
                                'VssPublicRecipientShareCommitmentContext',
                            objectVersion: 1,
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
                        const computation = input.computeVssPublicCommitment({
                            commitmentRole: 'recipient-share',
                            commitmentContext,
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            rnsLimbIndex,
                            rnsPrime,
                            ringDegree: input.ringDegree,
                            messageCoefficientBound: rnsPrime,
                            messageCoefficients: shareValues,
                            messageDigitColumns:
                                vssPublicCanonicalMessageDigitColumns(
                                    shareValues,
                                ),
                            randomnessByColumn,
                        });
                        recipientShareCommitments.push({
                            objectType: 'VssPublicRecipientShareCommitment',
                            objectVersion: 1,
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
                            randomnessByColumn,
                            shareCommitmentRoot: computation.commitmentRoot,
                            shareOpeningRoot: computation.openingRoot,
                            commitment: computation.commitment,
                        });
                    });
                }

                const sourceRecordWithoutRoot = {
                    objectType: 'VssPublicSourceRecipientShareCommitments',
                    objectVersion: 1,
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
        objectVersion: 1,
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

// The aggregate threshold commitment for one recipient at one RNS limb is the
// coordinate-wise SUM of every source trustee's recipient-share commitment to
// that recipient at that limb. The compact commitment is linear, so the summed
// commitment opens to the summed share under the summed randomness, which is
// exactly what the accepted-setup verifier recomputes. This is a client-side
// sum, never a fresh compute-command call: a commitment of the summed share
// under zero randomness would not equal the sum of the source commitments and
// would fail the verifier. Each commitment modulus is a ~2^47 data prime and the
// running remainder stays below it, so the plain-number modular sum is exact.
const vssPublicSummedAggregateCommitment = (input: {
    readonly commitmentContext: Record<string, unknown>;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly sourceCommitments: readonly VssPublicCommitmentValue[];
}): VssPublicCommitmentValue => {
    const [firstCommitment] = input.sourceCommitments;
    if (firstCommitment === undefined) {
        throw new Error(
            'Aggregate threshold commitment requires at least one source recipient-share commitment.',
        );
    }
    const commitmentContextHash = deriveCanonicalObjectHash({
        objectType: 'VssPublicCommitmentContext',
        objectVersion: 1,
        commitmentRole: 'aggregate-threshold-share',
        commitmentContext: input.commitmentContext,
    });
    const commitmentLimbs = firstCommitment.commitmentLimbs.map(
        (limb, limbPosition) => {
            const { modulus } = limb;
            const coordinates = limb.coordinates.map(
                (_coordinate, coordinateIndex) =>
                    input.sourceCommitments.reduce(
                        (accumulatedCoordinate, sourceCommitment) =>
                            (accumulatedCoordinate +
                                sourceCommitment.commitmentLimbs[limbPosition]
                                    .coordinates[coordinateIndex]) %
                            modulus,
                        0,
                    ),
            );

            return {
                commitmentModulusIndex: limb.commitmentModulusIndex,
                modulus,
                coordinates,
            };
        },
    );

    return {
        objectType: 'VssPublicCommitment',
        objectVersion: 1,
        commitmentRole: 'aggregate-threshold-share',
        commitmentContextHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        rnsLimbIndex: input.rnsLimbIndex,
        rnsPrime: input.rnsPrime,
        ringDegree: input.ringDegree,
        outputCoordinateCount: firstCommitment.outputCoordinateCount,
        randomnessColumnCount: firstCommitment.randomnessColumnCount,
        commitmentLimbs,
    };
};

export const createVssPublicAggregateThresholdCommitmentSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly recipientShareCredentials: readonly VssPublicRecipientShareCredential[];
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
            const commitmentContext = {
                objectType: 'VssPublicAggregateThresholdCommitmentContext',
                objectVersion: 1,
                ...setupContextFields(input.setupContext),
                recipientIdentity,
                recipientRosterPosition,
                recipientTrusteePoint: recipientPoint,
                rnsLimbIndex,
                rnsPrime,
                sourceShareCommitmentRoots,
                sourceShareOpeningRoots,
            };
            const commitment = vssPublicSummedAggregateCommitment({
                commitmentContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                rnsLimbIndex,
                rnsPrime,
                ringDegree: input.ringDegree,
                sourceCommitments: sourceCredentials.map(
                    (credential) => credential.commitment,
                ),
            });
            const aggregateOpeningRoot = deriveCanonicalObjectHash({
                objectType: 'VssPublicAggregateThresholdOpening',
                objectVersion: 1,
                commitmentRole: 'aggregate-threshold-share',
                commitmentContext,
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                rnsLimbIndex,
                rnsPrime,
                ringDegree: input.ringDegree,
                sourceShareOpeningRoots,
            });
            recipientRecords.push({
                objectType: 'VssPublicAggregateThresholdCommitment',
                objectVersion: 1,
                recipientIdentity,
                recipientRosterPosition,
                recipientTrusteePoint: recipientPoint,
                rnsLimbIndex,
                rnsPrime,
                aggregateCommitmentRoot: deriveCanonicalObjectHash(commitment),
                aggregateOpeningRoot,
                commitment,
                sourceShareCommitmentRoots,
                sourceShareOpeningRoots,
            });
        });
    }

    const setWithoutRoot = {
        objectType: 'VssPublicAggregateThresholdCommitmentSet',
        objectVersion: 1,
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
    };
};

export type VssShareLinkageStatement = {
    readonly objectType: string;
    readonly objectVersion: number;
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

// The share-linkage statement binds the three compact commitment set roots and,
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
                        'Compact VSS share linkage statement inputs must contain matching source records.',
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
                    objectVersion: 1,
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
        objectVersion: 1,
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

const vssShareLinkageProofFamily = 'vss-share-linkage';
const vssShareLinkageProofBytesHashDomain =
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

// The kernel-backed compact share-linkage proof (bound to the WASM
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
                'Compact VSS share linkage proof requires a coefficient credential for every covered coordinate.',
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
                'Compact VSS share linkage proof requires a recipient-share credential for every covered coordinate.',
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
                'Compact VSS share linkage proof requires matching coefficient and recipient source records.',
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
                'Compact VSS share linkage proof requires a recipient-share commitment for every covered coordinate.',
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
                    'Compact VSS share linkage proof record requires at least one covered recipient.',
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
                'compact VSS share linkage proofBytesHex',
            );
            const proofRecordWithoutRoot = {
                objectType: 'VssShareLinkageProofRecord',
                objectVersion: 1,
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
        objectVersion: 1,
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

// The single threshold-share commitment form on the compact path: it binds the
// aggregate threshold commitment set to the share-linkage statement and proof
// material, so the accepted-setup verifier recomputes this root over the compact
// roots it already verified rather than trusting a separate threshold object.
export const createThresholdShareCommitmentBinding = (input: {
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly statement: VssShareLinkageStatement;
    readonly aggregateThresholdCommitmentSet: VssPublicAggregateThresholdCommitmentSet;
    readonly shareLinkageProofMaterialSetRoot: ProtocolHash;
}): Record<string, unknown> => {
    const bindingWithoutRoot = {
        objectType: 'ThresholdShareCommitmentBinding',
        objectVersion: 1,
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

// Compact same-secret bridge constants. These are bound into the bridge
// statement (and thus its recomputed root), so they must match the kernel
// verifier byte for byte.
const sameSecretProofFamily = 'same-secret-linkage-anchor';
const sameSecretRelation =
    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs';
const sameSecretBridgeRelation =
    'target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof';
const sameSecretBridgeIntegerSupport =
    'the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb';
const sameSecretBridgeSignedRepresentativeConvention =
    'coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime';
const vssPublicCommitmentBinaryFormat =
    'sealed-lattice-vss-public-commitment-binary-v1';
const sameSecretBridgeTargetBasisLimbOrder =
    'target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime';
const sameSecretBridgeProofFamily = 'same-secret-bridge';
const sameSecretBridgeProofBytesHashDomain =
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
    readonly objectVersion: number;
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
    readonly objectVersion: number;
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

// The compact same-secret bridge statement set: per source trustee, it ties the
// compact target-basis constant coefficient commitments to the accepted
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
                    'Compact same-secret bridge requires a same-secret statement and proof per source trustee.',
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
                        'Compact same-secret bridge requires a constant coefficient commitment per target limb.',
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
                objectVersion: 1,
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
                targetBasisLimbOrder:
                    sameSecretBridgeTargetBasisLimbOrder,
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
        objectVersion: 1,
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

// The kernel-backed compact same-secret bridge proof (bound to the WASM
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
// secret the data-basis same-secret proof binds. The bridge proves the compact
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

// The compact same-secret bridge proof material set: one succinct bridge proof
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
                'Compact same-secret bridge proof requires constant coefficient commitment randomness per target limb.',
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
                'compact same-secret bridge proofBytesHex',
            );
            const proofRecordWithoutRoot = {
                objectType: 'VssSameSecretBridgeProofRecord',
                objectVersion: 1,
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
        objectVersion: 1,
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
        coefficientCommitmentRoot:
            statementSet.coefficientCommitmentRoot,
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

type JsonRecord = Record<string, unknown>;

// Standard RFC 4648 base64 with padding, the inverse of the local
// encodeStandardBase64 the compact proof records use for their embedded proof
// bytes. Decoding recovers the exact proof bytes so the transport hashes bind
// the same object the embedded record committed to.
const bytesFromStandardBase64 = (
    encoded: string,
    fieldName: string,
): Uint8Array => {
    if (encoded.length % 4 !== 0) {
        throw new Error(
            `${fieldName} must have a base64 length multiple of 4.`,
        );
    }
    const paddingLength = encoded.endsWith('==')
        ? 2
        : encoded.endsWith('=')
          ? 1
          : 0;
    const symbolCount = encoded.length - paddingLength;
    const byteLength = (encoded.length / 4) * 3 - paddingLength;
    const bytes = new Uint8Array(byteLength);
    let byteIndex = 0;
    let accumulator = 0;
    let accumulatedBits = 0;
    for (let symbolIndex = 0; symbolIndex < symbolCount; symbolIndex += 1) {
        const symbolValue = standardBase64Alphabet.indexOf(
            encoded[symbolIndex],
        );
        if (symbolValue < 0) {
            throw new Error(`${fieldName} must be valid standard base64.`);
        }
        accumulator = (accumulator << 6) | symbolValue;
        accumulatedBits += 6;
        if (accumulatedBits >= 8) {
            accumulatedBits -= 8;
            bytes[byteIndex] = (accumulator >> accumulatedBits) & 0xff;
            byteIndex += 1;
        }
    }

    return bytes;
};

export type TransportedVssShareLinkageProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedVssShareLinkageProofMaterialSet';
        readonly proofFamily: typeof vssShareLinkageProofFamily;
    }
>;

export type TransportedSameSecretBridgeProofMaterialSet = Readonly<
    TransportedSetupProofMaterialSet & {
        readonly objectType: 'SetupTransportedSameSecretBridgeProofMaterialSet';
        readonly proofFamily: typeof sameSecretBridgeProofFamily;
    }
>;

type ProofMaterialTransportParameters = Readonly<{
    readonly proofFamily: string;
    readonly proofBytesHashDomain: string;
    readonly transportSetObjectType: string;
    readonly transportMaterialObjectType: string;
}>;

// Move every compact proof record's embedded base64 proof bytes onto the shared
// setup proof-material transport. Each record keeps its identity fields but drops
// proofBytesBase64 for the transport reference fields and a recomputed
// proofRecordRoot, exactly as the kernel verifier rebuilds it, and its proof
// bytes travel as streamable chunks in the returned transported material set.
// The proof material set root is rebound over the rewritten records because it
// canonically binds the per-record proof-bytes encoding. This mirrors the kernel
// fixture move helpers so a transported set verifies identically to the embedded
// set it replaces, while staying small enough for the canonical string encoder
// at production roster sizes.
const moveProofBytesToTransport = (
    proofMaterialSet: JsonRecord,
    parameters: ProofMaterialTransportParameters,
): Readonly<{
    readonly proofMaterialSet: JsonRecord;
    readonly transportedProofMaterialSet: TransportedSetupProofMaterialSet;
}> => {
    const embeddedProofRecords = proofMaterialSet.proofRecords;
    if (!Array.isArray(embeddedProofRecords)) {
        throw new TypeError(
            `${parameters.proofFamily} proof material set proofRecords must be an array.`,
        );
    }

    const transportedProofMaterials: JsonRecord[] = [];
    const transportedProofRecords = embeddedProofRecords.map(
        (proofRecordValue, proofIndex) => {
            const proofRecord = proofRecordValue as JsonRecord;
            const proofBytesBase64 = proofRecord.proofBytesBase64;
            if (
                typeof proofBytesBase64 !== 'string' ||
                proofBytesBase64.length === 0
            ) {
                throw new TypeError(
                    `${parameters.proofFamily} proofRecords.${String(proofIndex)}.proofBytesBase64 must be non-empty.`,
                );
            }
            const proofBytes = bytesFromStandardBase64(
                proofBytesBase64,
                `${parameters.proofFamily} proofRecords.${String(proofIndex)}.proofBytesBase64`,
            );
            const expectedProofBytesHash = hash512Hex(
                parameters.proofBytesHashDomain,
                [proofBytes],
            );
            if (proofRecord.proofBytesHash !== expectedProofBytesHash) {
                throw new Error(
                    `${parameters.proofFamily} proofRecords.${String(proofIndex)}.proofBytesHash must match proofBytesBase64 before transport.`,
                );
            }
            const proofMaterialTransport = setupProofMaterialTransportMetadata(
                parameters.proofFamily,
                proofBytes,
                `${parameters.proofFamily} proofRecords.${String(proofIndex)}.proofBytesBase64 must produce at least one transported chunk.`,
            );
            const proofMaterialRoot = deriveCanonicalObjectHash({
                objectType: 'SetupProofMaterialReference',
                objectVersion: 1,
                proofFamily: parameters.proofFamily,
                proofBytesHash: proofRecord.proofBytesHash,
                ...setupProofMaterialReferenceFields(proofMaterialTransport),
            });
            transportedProofMaterials.push({
                objectType: parameters.transportMaterialObjectType,
                objectVersion: 1,
                proofFamily: parameters.proofFamily,
                ...setupTransportedProofMaterialFields(
                    proofMaterialTransport,
                    proofMaterialRoot,
                ),
                chunks: setupProofMaterialTransportChunks(
                    proofMaterialTransport,
                ),
            });

            const {
                proofBytesBase64: omittedProofBytesBase64,
                proofRecordRoot: omittedProofRecordRoot,
                ...proofRecordIdentity
            } = proofRecord;
            void omittedProofBytesBase64;
            void omittedProofRecordRoot;
            const transportedProofRecordWithoutRoot = {
                ...proofRecordIdentity,
                proofBytesEncoding: 'binary-chunked-proof-bytes',
                proofMaterialRoot,
                ...setupProofMaterialRecordTransportMetadataFields(
                    proofMaterialTransport,
                ),
            };

            return {
                ...transportedProofRecordWithoutRoot,
                proofRecordRoot: deriveCanonicalObjectHash(
                    transportedProofRecordWithoutRoot,
                ),
            };
        },
    );

    const {
        proofMaterialSetRoot: omittedProofMaterialSetRoot,
        ...proofMaterialSetIdentity
    } = proofMaterialSet;
    void omittedProofMaterialSetRoot;
    const transportedProofMaterialSetWithoutRoot = {
        ...proofMaterialSetIdentity,
        proofRecords: transportedProofRecords,
    };

    return {
        proofMaterialSet: {
            ...transportedProofMaterialSetWithoutRoot,
            proofMaterialSetRoot: deriveCanonicalObjectHash(
                transportedProofMaterialSetWithoutRoot,
            ),
        },
        transportedProofMaterialSet: {
            objectType: parameters.transportSetObjectType,
            objectVersion: 1,
            proofFamily: parameters.proofFamily,
            proofMaterials: transportedProofMaterials,
        },
    };
};

export type BinaryChunkedVssShareLinkageProofMaterialTransport =
    Readonly<{
        readonly proofMaterialSet: JsonRecord;
        readonly transportedVssShareLinkageProofMaterial: TransportedVssShareLinkageProofMaterialSet;
    }>;

export const createBinaryChunkedVssShareLinkageProofMaterialTransport = (
    proofMaterialSet: JsonRecord,
): BinaryChunkedVssShareLinkageProofMaterialTransport => {
    const moved = moveProofBytesToTransport(proofMaterialSet, {
        proofFamily: vssShareLinkageProofFamily,
        proofBytesHashDomain: vssShareLinkageProofBytesHashDomain,
        transportSetObjectType:
            'SetupTransportedVssShareLinkageProofMaterialSet',
        transportMaterialObjectType:
            'SetupTransportedVssShareLinkageProofMaterial',
    });

    return {
        proofMaterialSet: moved.proofMaterialSet,
        transportedVssShareLinkageProofMaterial:
            moved.transportedProofMaterialSet as TransportedVssShareLinkageProofMaterialSet,
    };
};

export type BinaryChunkedSameSecretBridgeProofMaterialTransport =
    Readonly<{
        readonly proofMaterialSet: JsonRecord;
        readonly transportedSameSecretBridgeProofMaterial: TransportedSameSecretBridgeProofMaterialSet;
    }>;

export const createBinaryChunkedSameSecretBridgeProofMaterialTransport =
    (
        proofMaterialSet: JsonRecord,
    ): BinaryChunkedSameSecretBridgeProofMaterialTransport => {
        const moved = moveProofBytesToTransport(proofMaterialSet, {
            proofFamily: sameSecretBridgeProofFamily,
            proofBytesHashDomain: sameSecretBridgeProofBytesHashDomain,
            transportSetObjectType:
                'SetupTransportedSameSecretBridgeProofMaterialSet',
            transportMaterialObjectType:
                'SetupTransportedSameSecretBridgeProofMaterial',
        });

        return {
            proofMaterialSet: moved.proofMaterialSet,
            transportedSameSecretBridgeProofMaterial:
                moved.transportedProofMaterialSet as TransportedSameSecretBridgeProofMaterialSet,
        };
    };
