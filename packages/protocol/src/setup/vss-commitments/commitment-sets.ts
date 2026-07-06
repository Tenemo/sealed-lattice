// VSS public material assembly. The trustees' per-coefficient secret
// polynomial evaluations are committed with a single covered-message
// commitment per (source trustee, RNS limb, Shamir coefficient), and the whole
// set is bound by canonical object roots. The heavy cryptography lives in the
// kernel commands; this module orchestrates the per-coefficient commitment
// computation and binds the roots the accepted-setup verifier recomputes.
import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

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

// The kernel-backed commitment computation (bound to the WASM
// `ComputeVssPublicCommitmentFromOpening` command by the SDK layer). Injected
// so the protocol layer never reimplements the certified commitment.
export type VssPublicCommitmentComputer = (
    input: VssPublicCommitmentOpeningInput,
) => VssPublicCommitmentComputation;

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
    readonly commitment: VssPublicCommitmentValue;
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
    readonly commitment: VssPublicCommitmentValue;
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
    readonly commitment: VssPublicCommitmentValue;
    readonly sourceShareCommitmentRoots: readonly ProtocolHash[];
    readonly sourceShareOpeningRoots: readonly ProtocolHash[];
};

export type VssPublicAggregateThresholdCommitmentSet = {
    readonly objectType: string;
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

type VssPublicRecipientShareOpeningRandomnessProvider = (input: {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
}) => readonly (readonly number[])[];

export type VssPublicRecipientShareCredential = {
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

// The aggregate threshold commitment for one recipient at one RNS limb is the
// coordinate-wise SUM of every source trustee's recipient-share commitment to
// that recipient at that limb. The commitment is linear, so the summed
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
