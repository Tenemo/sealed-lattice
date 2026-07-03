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
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

// Two base-3^17 message digits per coefficient. The kernel validates that the
// canonical digit columns reproduce the message coefficients, so they must be
// derived exactly this way (little-endian digits, transposed into columns).
const compactVssMessageDigitBase = 3 ** 17;
const compactVssMessageDigitCount = 2;

const compactVssCanonicalMessageDigitColumns = (
    messageCoefficients: readonly number[],
): number[][] => {
    const ringDegree = messageCoefficients.length;
    const columns: number[][] = Array.from(
        { length: compactVssMessageDigitCount },
        () => new Array<number>(ringDegree).fill(0),
    );
    messageCoefficients.forEach((coefficient, coefficientIndex) => {
        let remaining = coefficient;
        for (
            let digitIndex = 0;
            digitIndex < compactVssMessageDigitCount;
            digitIndex += 1
        ) {
            columns[digitIndex][coefficientIndex] =
                remaining % compactVssMessageDigitBase;
            remaining = Math.floor(remaining / compactVssMessageDigitBase);
        }
    });

    return columns;
};

export type CompactVssCommitmentOpeningInput = {
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

export type CompactVssCommitmentLimbValue = {
    readonly commitmentModulusIndex: number;
    readonly modulus: number;
    readonly coordinates: readonly number[];
};

export type CompactVssCommitmentValue = {
    readonly objectType: 'CompactVssCommitment';
    readonly objectVersion: number;
    readonly commitmentRole: string;
    readonly commitmentContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly outputCoordinateCount: number;
    readonly randomnessColumnCount: number;
    readonly commitmentLimbs: readonly CompactVssCommitmentLimbValue[];
};

export type CompactVssCommitmentComputation = {
    readonly commitment: CompactVssCommitmentValue;
    readonly commitmentRoot: ProtocolHash;
    readonly openingRoot: ProtocolHash;
};

// The kernel-backed compact commitment computation (bound to the WASM
// `ComputeCompactVssCommitmentFromOpening` command by the SDK layer). Injected
// so the protocol layer never reimplements the certified commitment.
export type CompactVssCommitmentComputer = (
    input: CompactVssCommitmentOpeningInput,
) => CompactVssCommitmentComputation;

// Typed compact commitment set outputs. These are the exact objects the
// accepted-setup verifier recomputes canonical roots over, so downstream
// builders (share-linkage statement and proof material) read them type-safely
// instead of casting through untyped records.
export type CompactVssCoefficientCommitment = {
    readonly objectType: 'CompactVssCoefficientCommitment';
    readonly objectVersion: number;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
    readonly coefficientOpeningRoot: ProtocolHash;
    readonly commitment: CompactVssCommitmentValue;
};

export type CompactVssSourceCoefficientCommitments = {
    readonly objectType: string;
    readonly objectVersion: number;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly coefficientCommitments: readonly CompactVssCoefficientCommitment[];
    readonly sourceCoefficientCommitmentRoot: ProtocolHash;
};

export type CompactVssCoefficientCommitmentSet = {
    readonly objectType: string;
    readonly objectVersion: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly ringDegree: number;
    readonly sourceTrusteeRecords: readonly CompactVssSourceCoefficientCommitments[];
    readonly coefficientCommitmentRoot: ProtocolHash;
};

export type CompactVssRecipientShareCommitment = {
    readonly objectType: 'CompactVssRecipientShareCommitment';
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
    readonly commitment: CompactVssCommitmentValue;
};

export type CompactVssSourceRecipientShareCommitments = {
    readonly objectType: string;
    readonly objectVersion: number;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientShareCommitments: readonly CompactVssRecipientShareCommitment[];
    readonly sourceRecipientShareCommitmentRoot: ProtocolHash;
};

export type CompactVssRecipientShareCommitmentSet = {
    readonly objectType: string;
    readonly objectVersion: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
    readonly sourceTrusteeRecords: readonly CompactVssSourceRecipientShareCommitments[];
    readonly recipientShareCommitmentRoot: ProtocolHash;
};

export type CompactVssAggregateThresholdCommitment = {
    readonly objectType: 'CompactVssAggregateThresholdCommitment';
    readonly objectVersion: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly aggregateCommitmentRoot: ProtocolHash;
    readonly aggregateOpeningRoot: ProtocolHash;
    readonly commitment: CompactVssCommitmentValue;
    readonly sourceShareCommitmentRoots: readonly ProtocolHash[];
    readonly sourceShareOpeningRoots: readonly ProtocolHash[];
};

export type CompactVssAggregateThresholdCommitmentSet = {
    readonly objectType: string;
    readonly objectVersion: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly rnsLimbCount: number;
    readonly ringDegree: number;
    readonly recipientRecords: readonly CompactVssAggregateThresholdCommitment[];
    readonly aggregateThresholdCommitmentRoot: ProtocolHash;
};

export type CompactVssCoefficientOpening = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientMessage: readonly number[];
};

export type CompactVssSourceTrusteeOpeningState = {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly coefficientOpenings: readonly CompactVssCoefficientOpening[];
};

type CompactVssCoefficientOpeningRandomnessProvider = (input: {
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
export type CompactVssCoefficientCredential = {
    readonly sourceTrusteeRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientMessage: readonly number[];
    readonly randomnessByColumn: readonly (readonly number[])[];
};

type CompactVssCoefficientCommitmentBundle = {
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly coefficientCredentials: readonly CompactVssCoefficientCredential[];
};

type CompactVssSetupContextFields = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly setupParametersHash: ProtocolHash;
    readonly setupEpoch: string;
};

const setupContextFields = (
    setupContext: CollectiveBgvSetupContext,
): CompactVssSetupContextFields => ({
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

export const createCompactVssCoefficientCommitmentSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningStates: readonly CompactVssSourceTrusteeOpeningState[];
    readonly coefficientOpeningRandomness: CompactVssCoefficientOpeningRandomnessProvider;
    readonly computeCompactVssCommitment: CompactVssCommitmentComputer;
}): CompactVssCoefficientCommitmentBundle => {
    const coefficientCredentials: CompactVssCoefficientCredential[] = [];
    const sourceTrusteeRecords = [...input.sourceTrusteeOpeningStates]
        .sort(
            (left, right) =>
                left.sourceTrusteeRosterPosition -
                right.sourceTrusteeRosterPosition,
        )
        .map(
            (
                sourceTrusteeOpeningState,
            ): CompactVssSourceCoefficientCommitments => {
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
                const coefficientCommitments: CompactVssCoefficientCommitment[] =
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
                                'CompactVssCoefficientCommitmentContext',
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
                        const computation = input.computeCompactVssCommitment({
                            commitmentRole: 'coefficient',
                            commitmentContext,
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            rnsLimbIndex,
                            rnsPrime,
                            ringDegree: input.ringDegree,
                            messageCoefficientBound: rnsPrime,
                            messageCoefficients: opening.coefficientMessage,
                            messageDigitColumns:
                                compactVssCanonicalMessageDigitColumns(
                                    opening.coefficientMessage,
                                ),
                            randomnessByColumn,
                        });
                        coefficientCommitments.push({
                            objectType: 'CompactVssCoefficientCommitment',
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
                    objectType: 'CompactVssSourceCoefficientCommitments',
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
        objectType: 'CompactVssCoefficientCommitmentSet',
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

type CompactVssRecipientShareOpeningRandomnessProvider = (input: {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
}) => readonly (readonly number[])[];

type CompactVssRecipientShareCredential = {
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
    readonly commitment: CompactVssCommitmentValue;
};

type CompactVssRecipientShareCommitmentBundle = {
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly recipientShareCredentials: readonly CompactVssRecipientShareCredential[];
};

// The recipient's Shamir share of a source trustee's coefficient polynomial,
// evaluated at the recipient's canonical point (recipientRosterPosition + 1) and
// decomposed into the residue (the committed share value) and the integer carry
// the kernel's share-linkage proof binds. Computed in BigInt because the lifted
// pre-reduction share can exceed the safe-integer range.
const compactVssRecipientShareValuesAndCarries = (input: {
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

export const createCompactVssRecipientShareCommitmentSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningStates: readonly CompactVssSourceTrusteeOpeningState[];
    readonly recipientShareOpeningRandomness: CompactVssRecipientShareOpeningRandomnessProvider;
    readonly computeCompactVssCommitment: CompactVssCommitmentComputer;
}): CompactVssRecipientShareCommitmentBundle => {
    const recipientShareCredentials: CompactVssRecipientShareCredential[] = [];
    const sourceTrusteeRecords = [...input.sourceTrusteeOpeningStates]
        .sort(
            (left, right) =>
                left.sourceTrusteeRosterPosition -
                right.sourceTrusteeRosterPosition,
        )
        .map(
            (
                sourceTrusteeOpeningState,
            ): CompactVssSourceRecipientShareCommitments => {
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
                const recipientShareCommitments: CompactVssRecipientShareCommitment[] =
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
                            compactVssRecipientShareValuesAndCarries({
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
                                'CompactVssRecipientShareCommitmentContext',
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
                        const computation = input.computeCompactVssCommitment({
                            commitmentRole: 'recipient-share',
                            commitmentContext,
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            rnsLimbIndex,
                            rnsPrime,
                            ringDegree: input.ringDegree,
                            messageCoefficientBound: rnsPrime,
                            messageCoefficients: shareValues,
                            messageDigitColumns:
                                compactVssCanonicalMessageDigitColumns(
                                    shareValues,
                                ),
                            randomnessByColumn,
                        });
                        recipientShareCommitments.push({
                            objectType: 'CompactVssRecipientShareCommitment',
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
                    objectType: 'CompactVssSourceRecipientShareCommitments',
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
        objectType: 'CompactVssRecipientShareCommitmentSet',
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
const compactVssSummedAggregateCommitment = (input: {
    readonly commitmentContext: Record<string, unknown>;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly sourceCommitments: readonly CompactVssCommitmentValue[];
}): CompactVssCommitmentValue => {
    const [firstCommitment] = input.sourceCommitments;
    if (firstCommitment === undefined) {
        throw new Error(
            'Aggregate threshold commitment requires at least one source recipient-share commitment.',
        );
    }
    const commitmentContextHash = deriveCanonicalObjectHash({
        objectType: 'CompactVssCommitmentContext',
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
        objectType: 'CompactVssCommitment',
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

export const createCompactVssAggregateThresholdCommitmentSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly recipientShareCredentials: readonly CompactVssRecipientShareCredential[];
}): CompactVssAggregateThresholdCommitmentSet => {
    const credentialsByCoordinate = new Map<
        string,
        CompactVssRecipientShareCredential[]
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

    const recipientRecords: CompactVssAggregateThresholdCommitment[] = [];
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
                objectType: 'CompactVssAggregateThresholdCommitmentContext',
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
            const commitment = compactVssSummedAggregateCommitment({
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
                objectType: 'CompactVssAggregateThresholdOpening',
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
                objectType: 'CompactVssAggregateThresholdCommitment',
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
        objectType: 'CompactVssAggregateThresholdCommitmentSet',
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

export type CompactVssShareLinkageStatement = {
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
export const createCompactVssShareLinkageStatement = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
}): CompactVssShareLinkageStatement => {
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
                    objectType: 'CompactVssShareLinkageSourceStatement',
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
        objectType: 'CompactVssShareLinkageStatement',
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

const compactVssShareLinkageProofFamily = 'compact-vss-share-linkage';
const compactVssShareLinkageProofBytesHashDomain =
    'sealed-lattice/setup/compact-vss-share-linkage/proof-bytes-v1';
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

export type CompactVssShareLinkageProofContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
    readonly shareLinkageStatementRoot: ProtocolHash;
};

// The kernel-backed compact share-linkage proof (bound to the WASM
// `GenerateCompactVssShareLinkageProof` command by the SDK). Injected so the
// protocol layer assembles the witness but never runs the certified prover.
export type CompactVssShareLinkageProofComputer = (input: {
    readonly context: CompactVssShareLinkageProofContext;
    readonly ringDegree: number;
    readonly compactVssShareLinkage: Record<string, unknown>;
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
type CompactVssShareLinkageProofRandomnessProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
    readonly proofRecordIndex: number;
}) => { readonly seedHex: string; readonly nonceHex: string };

const compactVssShareLinkageCoordinateKey = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): string =>
    `${String(sourceTrusteeRosterPosition)}:${String(rnsLimbIndex)}:${String(shamirCoefficientIndex)}`;

const compactVssRecipientShareCoordinateKey = (
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
export const createCompactVssShareLinkageProofMaterialSet = (input: {
    readonly statement: CompactVssShareLinkageStatement;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly coefficientCredentials: readonly CompactVssCoefficientCredential[];
    readonly recipientShareCredentials: readonly CompactVssRecipientShareCredential[];
    readonly shareLinkageProofRandomness: CompactVssShareLinkageProofRandomnessProvider;
    readonly generateCompactVssShareLinkageProof: CompactVssShareLinkageProofComputer;
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
            compactVssShareLinkageCoordinateKey(
                credential.sourceTrusteeRosterPosition,
                credential.rnsLimbIndex,
                credential.shamirCoefficientIndex,
            ),
            credential,
        ]),
    );
    const recipientShareCredentialByCoordinate = new Map(
        input.recipientShareCredentials.map((credential) => [
            compactVssRecipientShareCoordinateKey(
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
    ): CompactVssCoefficientCredential => {
        const credential = coefficientCredentialByCoordinate.get(
            compactVssShareLinkageCoordinateKey(
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
    ): CompactVssRecipientShareCredential => {
        const credential = recipientShareCredentialByCoordinate.get(
            compactVssRecipientShareCoordinateKey(
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
            const compactVssShareLinkage = {
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
            const generatedProof = input.generateCompactVssShareLinkageProof({
                context: {
                    ceremonyId: statement.ceremonyId,
                    manifestHash: statement.manifestHash,
                    rosterHash: statement.rosterHash,
                    trusteeIdentity: compactVssShareLinkageProofFamily,
                    trusteeRosterPosition: 0,
                    setupEpoch: statement.setupEpoch,
                    shareLinkageStatementRoot: statement.statementRoot,
                },
                ringDegree,
                compactVssShareLinkage,
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
                objectType: 'CompactVssShareLinkageProofRecord',
                objectVersion: 1,
                proofFamily: compactVssShareLinkageProofFamily,
                linkageItems,
                compactVssShareLinkage,
                proofBytesHash: hash512Hex(
                    compactVssShareLinkageProofBytesHashDomain,
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
        objectType: 'CompactVssShareLinkageProofMaterialSet',
        objectVersion: 1,
        proofFamily: compactVssShareLinkageProofFamily,
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
export const createCompactThresholdShareCommitmentBinding = (input: {
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly statement: CompactVssShareLinkageStatement;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly shareLinkageProofMaterialSetRoot: ProtocolHash;
}): Record<string, unknown> => {
    const bindingWithoutRoot = {
        objectType: 'CompactThresholdShareCommitmentBinding',
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
const compactSameSecretBridgeRelation =
    'target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof';
const compactSameSecretBridgeIntegerSupport =
    'the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb';
const compactSameSecretBridgeSignedRepresentativeConvention =
    'coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime';
const compactVssCommitmentBinaryFormat =
    'sealed-lattice-compact-vss-commitment-binary-v1';
const compactSameSecretBridgeTargetBasisLimbOrder =
    'target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime';
const compactSameSecretBridgeProofFamily = 'compact-same-secret-bridge';
const compactSameSecretBridgeProofBytesHashDomain =
    'sealed-lattice/setup/compact-same-secret-bridge/proof-bytes-v1';

export type CompactVssSameSecretBridgeTargetConstantRoot = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly coefficientCommitmentRoot: ProtocolHash;
};

export type CompactVssSameSecretBridgeTargetConstantCommitment = {
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly shamirCoefficientIndex: number;
    readonly commitment: CompactVssCommitmentValue;
};

export type CompactVssSameSecretBridgeStatement = {
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
    readonly compactCommitmentEncoding: string;
    readonly targetBasisLimbOrder: string;
    readonly targetConstantCoefficientCommitmentRoots: readonly CompactVssSameSecretBridgeTargetConstantRoot[];
    readonly targetConstantCoefficientCommitments: readonly CompactVssSameSecretBridgeTargetConstantCommitment[];
    readonly relation: string;
    readonly compactSameSecretBridgeStatementRoot: ProtocolHash;
};

export type CompactVssSameSecretBridgeStatementSet = {
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
    readonly compactCoefficientCommitmentRoot: ProtocolHash;
    readonly sameSecretConsistencyRoot: ProtocolHash;
    readonly sameSecretProofSetRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
    readonly integerSupport: string;
    readonly signedRepresentativeConvention: string;
    readonly compactCommitmentEncoding: string;
    readonly targetBasisLimbOrder: string;
    readonly statementRecords: readonly CompactVssSameSecretBridgeStatement[];
    readonly compactSameSecretBridgeStatementSetRoot: ProtocolHash;
};

// The compact same-secret bridge statement set: per source trustee, it ties the
// compact target-basis constant coefficient commitments to the accepted
// data-basis same-secret proof, so the verifier recomputes the shared roots and
// checks one bridge proof per trustee proves both bases open to one secret.
export const createCompactVssSameSecretBridgeStatementSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
}): CompactVssSameSecretBridgeStatementSet => {
    const { coefficientCommitmentSet } = input;
    const { ringDegree, participantCount, rnsLimbCount, thresholdDegree } =
        coefficientCommitmentSet;
    const statementRecords = coefficientCommitmentSet.sourceTrusteeRecords.map(
        (
            coefficientSourceRecord,
            sourceTrusteeRosterPosition,
        ): CompactVssSameSecretBridgeStatement => {
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
            const targetConstantCoefficientCommitmentRoots: CompactVssSameSecretBridgeTargetConstantRoot[] =
                [];
            const targetConstantCoefficientCommitments: CompactVssSameSecretBridgeTargetConstantCommitment[] =
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
                objectType: 'CompactVssSameSecretBridgeStatement',
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
                integerSupport: compactSameSecretBridgeIntegerSupport,
                signedRepresentativeConvention:
                    compactSameSecretBridgeSignedRepresentativeConvention,
                compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
                targetBasisLimbOrder:
                    compactSameSecretBridgeTargetBasisLimbOrder,
                targetConstantCoefficientCommitmentRoots,
                targetConstantCoefficientCommitments,
                relation: compactSameSecretBridgeRelation,
            };

            return {
                ...statementWithoutRoot,
                compactSameSecretBridgeStatementRoot:
                    deriveCanonicalObjectHash(statementWithoutRoot),
            };
        },
    );

    const statementSetWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeStatementSet',
        objectVersion: 1,
        proofFamily: sameSecretProofFamily,
        ...setupContextFields(input.setupContext),
        targetBasisHash: input.targetBasisHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        ringDegree,
        participantCount,
        targetRnsLimbCount: rnsLimbCount,
        thresholdDegree,
        compactCoefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        sameSecretConsistencyRoot:
            input.sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: input.sameSecretProofs.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            input.sameSecretConsistency.sameSecretProofFamilyBindingRoot,
        integerSupport: compactSameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            compactSameSecretBridgeSignedRepresentativeConvention,
        compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
        targetBasisLimbOrder: compactSameSecretBridgeTargetBasisLimbOrder,
        statementRecords,
    };

    return {
        ...statementSetWithoutRoot,
        compactSameSecretBridgeStatementSetRoot: deriveCanonicalObjectHash(
            statementSetWithoutRoot,
        ),
    };
};

export type CompactSameSecretBridgeProofContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
    readonly setupEpoch: string;
    readonly compactSameSecretBridgeStatementRoot: ProtocolHash;
    readonly sameSecretStatementRoot: ProtocolHash;
    readonly sameSecretProofRoot: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
};

// The kernel-backed compact same-secret bridge proof (bound to the WASM
// `GenerateCompactSameSecretBridgeProof` command by the SDK). Injected so the
// protocol layer assembles the witness but never runs the certified prover.
export type CompactSameSecretBridgeProofComputer = (input: {
    readonly context: CompactSameSecretBridgeProofContext;
    readonly ringDegree: number;
    readonly compactSameSecretBridge: Record<string, unknown>;
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
type CompactSameSecretBridgeSecretProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
}) => { readonly secretCoefficients: readonly number[] };

type CompactSameSecretBridgeProofRandomnessProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
}) => { readonly seedHex: string; readonly nonceHex: string };

// Optional per-trustee transported same-secret proof material, present only when
// the data-basis same-secret proof is delivered by transport rather than
// embedded; the bridge proof binds it so both bases reference one proof.
type CompactSameSecretBridgeTransportedProofMaterialProvider = (input: {
    readonly sourceTrusteeRosterPosition: number;
}) => Record<string, unknown> | undefined;

// The compact same-secret bridge proof material set: one succinct bridge proof
// per source trustee. The verifier recomputes the statement roots and the proof
// bytes hash and checks each proof, so this builder assembles the witness (the
// trustee secret, its sign indicators, and the per-limb constant-coefficient
// commitment randomness) and binds the proof bytes.
export const createCompactVssSameSecretBridgeProofMaterialSet = (input: {
    readonly statementSet: CompactVssSameSecretBridgeStatementSet;
    readonly coefficientCredentials: readonly CompactVssCoefficientCredential[];
    readonly bridgeSecret: CompactSameSecretBridgeSecretProvider;
    readonly bridgeProofRandomness: CompactSameSecretBridgeProofRandomnessProvider;
    readonly transportedSameSecretProofMaterial?: CompactSameSecretBridgeTransportedProofMaterialProvider;
    readonly generateCompactSameSecretBridgeProof: CompactSameSecretBridgeProofComputer;
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
            const compactSameSecretBridge = {
                compactSameSecretBridgeStatementRoot:
                    statementRecord.compactSameSecretBridgeStatementRoot,
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
            const generatedProof = input.generateCompactSameSecretBridgeProof({
                context: {
                    ceremonyId: statementSet.ceremonyId,
                    manifestHash: statementSet.manifestHash,
                    rosterHash: statementSet.rosterHash,
                    trusteeIdentity: statementRecord.trusteeIdentity,
                    trusteeRosterPosition: sourceTrusteeRosterPosition,
                    setupEpoch: statementSet.setupEpoch,
                    compactSameSecretBridgeStatementRoot:
                        statementRecord.compactSameSecretBridgeStatementRoot,
                    sameSecretStatementRoot:
                        statementRecord.sameSecretStatementRoot,
                    sameSecretProofRoot: statementRecord.sameSecretProofRoot,
                    sameSecretProofFamilyBindingRoot:
                        statementRecord.sameSecretProofFamilyBindingRoot,
                },
                ringDegree: statementRecord.ringDegree,
                compactSameSecretBridge,
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
                objectType: 'CompactVssSameSecretBridgeProofRecord',
                objectVersion: 1,
                proofFamily: compactSameSecretBridgeProofFamily,
                compactSameSecretBridgeStatementRoot:
                    statementRecord.compactSameSecretBridgeStatementRoot,
                proofBytesHash: hash512Hex(
                    compactSameSecretBridgeProofBytesHashDomain,
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
        objectType: 'CompactVssSameSecretBridgeProofMaterialSet',
        objectVersion: 1,
        proofFamily: compactSameSecretBridgeProofFamily,
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
        compactCoefficientCommitmentRoot:
            statementSet.compactCoefficientCommitmentRoot,
        sameSecretConsistencyRoot: statementSet.sameSecretConsistencyRoot,
        sameSecretProofSetRoot: statementSet.sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            statementSet.sameSecretProofFamilyBindingRoot,
        compactSameSecretBridgeStatementSetRoot:
            statementSet.compactSameSecretBridgeStatementSetRoot,
        proofRecords,
    };

    return {
        ...proofMaterialSetWithoutRoot,
        proofMaterialSetRoot: deriveCanonicalObjectHash(
            proofMaterialSetWithoutRoot,
        ),
    };
};
