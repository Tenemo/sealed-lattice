import {
    canonicalJson,
    deriveProtocolHash,
    hash512Hex,
} from '@sealed-lattice/crypto';
import type {
    BallotPolynomialSet,
    FieldElement,
    PvssBallotAlgebraInput,
    ShamirPolynomial,
} from '@sealed-lattice/types';

import {
    fieldModulus,
    normalizeFieldElement,
} from '../plaintext-oracle/field.js';
import { createShamirPolynomial } from '../plaintext-oracle/shamir.js';
import { normalizePlaintextScoreBallot } from '../plaintext-oracle/top-k.js';

import {
    requireNoRefusals,
    validatePollAndThreshold,
    validateRosterEntries,
} from './common.js';

const textEncoder = new TextEncoder();
const coefficientDerivationDomain =
    'sealed-lattice-internal/pvss-ballot-fixture-coefficient-v1';

// TEST/FIXTURE-ONLY deterministic secret sharing: real ballots would draw the
// non-constant coefficients from fresh randomness. `hash % modulus` has a slight
// modulo bias (2^512 is not a multiple of 65537); acceptable only because these
// are reproducible fixtures, not live secrets.
const deriveFieldElementFromHash = (hashHex: string): FieldElement => {
    const hashValue = BigInt(`0x${hashHex}`);

    return Number(hashValue % BigInt(fieldModulus));
};

const deriveDeterministicCoefficient = (
    input: PvssBallotAlgebraInput,
    optionIndex: number,
    coefficientIndex: number,
): FieldElement =>
    deriveFieldElementFromHash(
        hash512Hex(coefficientDerivationDomain, [
            textEncoder.encode(
                canonicalJson({
                    ceremonyId: input.ceremonyId,
                    duplicateBallotPolicyHash: input.duplicateBallotPolicyHash,
                    electionManifestHash: input.electionManifestHash,
                    fixtureEntropy: input.fixtureEntropy,
                    rosterHash: input.rosterHash,
                    pollSpecHash: input.pollSpecHash,
                    thresholdProfileHash: input.thresholdProfileHash,
                    voterIdentity: input.voterIdentity,
                    voterRosterPosition: input.voterRosterPosition,
                    optionIndex,
                    coefficientIndex,
                }),
            ),
        ]),
    );

export const deriveBallotPolynomialSetHash = (
    polynomialSet: Omit<BallotPolynomialSet, 'ballotPolynomialSetHash'>,
): string =>
    deriveProtocolHash('BallotPolynomialSetHash', {
        objectType: 'BallotPolynomialSet',
        normalizedBallot: polynomialSet.normalizedBallot,
        optionPolynomials: polynomialSet.optionPolynomials,
        pvssThreshold: polynomialSet.pvssThreshold,
    });

export const deriveBallotPolynomialSet = (
    input: PvssBallotAlgebraInput,
): BallotPolynomialSet => {
    if (input.fixtureEntropy.length === 0) {
        throw new RangeError(
            'Ballot polynomial fixture entropy must be explicit and non-empty.',
        );
    }

    requireNoRefusals([
        ...validatePollAndThreshold(input.pollSpec, input.thresholdProfile),
        ...validateRosterEntries(input.rosterEntries, input.thresholdProfile),
    ]);

    const voterRosterEntry = input.rosterEntries.find(
        (entry) => entry.participantIdentity === input.voterIdentity,
    );
    if (voterRosterEntry?.rosterPosition !== input.voterRosterPosition) {
        throw new RangeError(
            'Ballot voter identity and roster position must match the frozen roster.',
        );
    }
    if (
        input.scoreBallot.voterIdentity !== undefined &&
        input.scoreBallot.voterIdentity !== input.voterIdentity
    ) {
        throw new RangeError(
            'Score ballot voter identity must match the ballot algebra input.',
        );
    }

    const normalizedBallot = normalizePlaintextScoreBallot(
        input.pollSpec,
        input.scoreBallot,
    );
    const optionPolynomials = normalizedBallot.scores.map(
        (score, optionIndex) => {
            // One Shamir polynomial per option: constant term = the score, with
            // (pvssThreshold - 1) non-constant coefficients, so the polynomial
            // has degree pvssThreshold - 1 and any `threshold` shares
            // reconstruct the score.
            const coefficients = Array.from(
                { length: input.thresholdProfile.pvssThreshold - 1 },
                (_unused, coefficientIndex) =>
                    deriveDeterministicCoefficient(
                        input,
                        optionIndex,
                        coefficientIndex + 1,
                    ),
            );
            const polynomial: ShamirPolynomial = createShamirPolynomial(
                normalizeFieldElement(score),
                coefficients,
            );

            return {
                optionIndex,
                optionOrdinal: optionIndex + 1,
                polynomial,
            };
        },
    );
    const polynomialPayload = {
        normalizedBallot:
            input.voterIdentity === normalizedBallot.voterIdentity
                ? normalizedBallot
                : {
                      scores: normalizedBallot.scores,
                      voterIdentity: input.voterIdentity,
                  },
        optionPolynomials,
        pvssThreshold: input.thresholdProfile.pvssThreshold,
    };

    return {
        ...polynomialPayload,
        ballotPolynomialSetHash:
            deriveBallotPolynomialSetHash(polynomialPayload),
    };
};
