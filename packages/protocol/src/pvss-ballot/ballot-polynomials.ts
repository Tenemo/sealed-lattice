import {
    canonicalJson,
    deriveProtocolDigest,
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

const deriveFieldElementFromDigest = (digestHex: string): FieldElement => {
    const digestValue = BigInt(`0x${digestHex}`);

    return Number(digestValue % BigInt(fieldModulus));
};

const deriveDeterministicCoefficient = (
    input: PvssBallotAlgebraInput,
    optionIndex: number,
    coefficientIndex: number,
): FieldElement =>
    deriveFieldElementFromDigest(
        hash512Hex(coefficientDerivationDomain, [
            textEncoder.encode(
                canonicalJson({
                    ceremonyId: input.ceremonyId,
                    duplicateBallotPolicyDigest:
                        input.duplicateBallotPolicyDigest,
                    electionManifestDigest: input.electionManifestDigest,
                    fixtureEntropy: input.fixtureEntropy,
                    rosterDigest: input.rosterDigest,
                    pollSpecDigest: input.pollSpecDigest,
                    thresholdProfileDigest: input.thresholdProfileDigest,
                    voterIdentity: input.voterIdentity,
                    voterRosterPosition: input.voterRosterPosition,
                    optionIndex,
                    coefficientIndex,
                }),
            ),
        ]),
    );

export const deriveBallotPolynomialSetDigest = (
    polynomialSet: Omit<BallotPolynomialSet, 'ballotPolynomialSetDigest'>,
): string =>
    deriveProtocolDigest('BallotPackageDigest', {
        objectType: 'BallotPolynomialSet',
        normalizedBallot: polynomialSet.normalizedBallot,
        optionPolynomials: polynomialSet.optionPolynomials,
        pvssThreshold: polynomialSet.pvssThreshold,
    });

export const deriveBallotPolynomialSet = (
    input: PvssBallotAlgebraInput,
): BallotPolynomialSet => {
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
        ballotPolynomialSetDigest:
            deriveBallotPolynomialSetDigest(polynomialPayload),
    };
};
