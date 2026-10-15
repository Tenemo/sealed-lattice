import { describe, expect, it } from 'vitest';

import { compileCommittedOfferCensus } from '#tests/committed-offer-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { sourceReadBytes } from '#tests/encrypted-registration-source-model.js';
import {
    ascii,
    item,
    itemType,
    tuple,
    variable,
} from '#tests/node/protocol/reference/canonical-tuple.js';
import { goalThresholds } from '#tests/node/protocol/reference/product-goals.js';
import { compilePreparationResources } from '#tests/preparation-resource-model.js';
import { isProofChallengeInput } from '#tests/proof-hash-domain-model.js';
import {
    compilePublicEvaluationHashCensus,
    parsePublicEvaluationHashInput,
} from '#tests/public-evaluation-hash-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import { listSupportedProfiles } from '#tests/supported-profile-model.js';
import {
    protocolHashPrefix,
    framed,
} from '#tests/word-proof-reference/transcript.js';

describe('committed offer equations and degree bounds', () => {
    it('keeps every profile within the strict degree and integer-lifting bounds', () => {
        for (const profile of listSupportedProfiles()) {
            const value = compileCommittedOfferCensus(profile);
            expect(value.agreementPoints).toBeGreaterThan(
                value.degreeShiftIdentityDegree,
            );
            expect(2n * value.aggregateLimbMagnitudeBound).toBeLessThan(
                value.proofFieldModulus,
            );
            expect(value.committedDigitMagnitudeBound).toBeLessThan(1n << 114n);
            expect(value.generatedAggregateLimbBytes).toBe(13n);
            expect(value.maximumAggregateLimbBytes).toBeLessThanOrEqual(15n);
            expect(value.evaluationQueries).toBe(429);
            expect(
                value.falseQuotientAgreementNumerator *
                    value.evaluationDistanceDenominator,
            ).toBeLessThan(
                (value.evaluationDistanceDenominator -
                    value.evaluationDistanceNumerator) *
                    value.falseQuotientAgreementDenominator,
            );
        }
    });

    it('uses the least evaluation query count that matches the existing exponent', () => {
        const target = 193n ** 704n;
        const targetDenominator = 256n ** 704n;
        expect(161n ** 429n * targetDenominator).toBeLessThanOrEqual(
            target * 256n ** 429n,
        );
        expect(161n ** 428n * targetDenominator).toBeGreaterThan(
            target * 256n ** 428n,
        );
        expect(95n * 8n).toBeLessThan(3n * 256n);
    });

    it('bounds every complete organizer work unit and continuation across the supported family', () => {
        const chunk = 1n << 20n;
        const budget = ((1n << 31n) * 15n) / 16n;
        for (const profile of listSupportedProfiles()) {
            const schedule =
                compilePreparationResources(profile).organizerSchedule;
            const selected = BigInt(
                goalThresholds(profile.participantCount).resultReleaseThreshold,
            );
            const body = compileContributionBodyCensus(profile);
            const aggregate = compileCommittedOfferCensus(profile);
            const wire = compileSetupSelectionWireCensus(
                profile.participantCount,
            );
            const offer =
                sourceReadBytes +
                body.polynomialPayloadBytes +
                body.maximumProofBytes +
                body.headerBytes +
                wire.offerEnvelopeBytes +
                wire.signatureBytes +
                3n * chunk;
            const data = aggregate.generatedAggregateBytes + 2n * chunk;
            const evaluation =
                body.polynomialPayloadBytes -
                body.streamedPolynomialPayloadBytes +
                2n * aggregate.maximumEvaluationProofBytes +
                4n * chunk;
            const proof = aggregate.maximumEvaluationProofBytes + chunk;

            // Each call completes an offer, publishes the aggregate, completes
            // an evaluation, or verifies the final aggregate. Continuing this
            // same collection stage does not create another productive visit.
            expect(schedule.calls.length).toBeGreaterThan(0);
            expect(BigInt(schedule.calls.length)).toBeLessThanOrEqual(
                2n * selected + 2n,
            );
            for (const bytes of schedule.calls)
                expect(bytes).toBeLessThanOrEqual(budget);
            // Even at the last evaluation or final read, a fresh call can
            // replay all prior proofs and finish the next indivisible unit.
            expect(schedule.prelude + offer).toBeLessThanOrEqual(budget);
            expect(
                schedule.prelude + (selected - 1n) * proof + evaluation,
            ).toBeLessThanOrEqual(budget);
            expect(
                schedule.prelude + selected * proof + data,
            ).toBeLessThanOrEqual(budget);
            expect(schedule.calls.reduce((sum, bytes) => sum + bytes, 0n)).toBe(
                schedule.prelude +
                    schedule.continuationReadBytes +
                    selected * (offer + evaluation) +
                    2n * data,
            );
            const continuations = BigInt(schedule.calls.length - 1);
            expect(schedule.replayBytes % proof).toBe(0n);
            expect(schedule.replayBytes).toBeLessThanOrEqual(
                continuations * selected * proof,
            );
            expect(schedule.continuationReadBytes).toBe(
                continuations * schedule.prelude + schedule.replayBytes,
            );
        }
    });

    it('keeps aggregate transcripts and their manifest preimages in the challenged public domain', () => {
        const profile = listSupportedProfiles()[0];
        const value = compileCommittedOfferCensus(profile);
        const role = Buffer.concat([
            Buffer.from('sealed-lattice/setup-aggregate'),
            Buffer.alloc(64, 7),
        ]);
        const hash = compilePublicEvaluationHashCensus(profile);
        const messages = [
            framed([
                Buffer.from('bounded-proof/verifier-message'),
                role,
                Buffer.alloc(64),
                Buffer.alloc(Number(hash.messageBytes)),
                Buffer.alloc(4),
            ]),
            Buffer.concat([
                protocolHashPrefix,
                framed([
                    Buffer.from('bounded-proof/message-root'),
                    role,
                    Buffer.alloc(64),
                    Buffer.alloc(4),
                    Buffer.alloc(128),
                    Buffer.alloc(4),
                    Buffer.alloc(48),
                ]),
            ]),
            tuple([
                ascii('sealed-lattice/published-aggregate'),
                item(
                    itemType.rawBytes,
                    variable(
                        Buffer.alloc(64 + Number(value.aggregateManifestBytes)),
                    ),
                ),
            ]),
        ];
        for (const input of messages) {
            expect(parsePublicEvaluationHashInput(input)).toBeDefined();
            expect(
                isProofChallengeInput(
                    input,
                    new Set(['00'.repeat(64), 'ab'.repeat(64)]),
                ),
            ).toBe(true);
            expect(
                parsePublicEvaluationHashInput(
                    input.subarray(0, input.length - 1),
                ),
            ).toBeUndefined();
            expect(
                parsePublicEvaluationHashInput(
                    Buffer.concat([input, Buffer.of(0)]),
                ),
            ).toBeUndefined();
        }
        expect(hash.groups[0].width).toBe(16n * value.committedColumns);
        expect(hash.groups[hash.groups.length - 1].leaves).toBe(8n);
    });
});
