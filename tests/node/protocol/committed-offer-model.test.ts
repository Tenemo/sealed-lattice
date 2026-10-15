import { describe, expect, it } from 'vitest';

import { compileCommittedOfferCensus } from '#tests/committed-offer-model.js';
import {
    ascii,
    item,
    itemType,
    tuple,
    variable,
} from '#tests/node/protocol/reference/canonical-tuple.js';
import { compilePreparationResources } from '#tests/preparation-resource-model.js';
import { isProofChallengeInput } from '#tests/proof-hash-domain-model.js';
import {
    compilePublicEvaluationHashCensus,
    parsePublicEvaluationHashInput,
} from '#tests/public-evaluation-hash-model.js';
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
        for (const profile of listSupportedProfiles()) {
            const schedule =
                compilePreparationResources(profile).organizerSchedule;
            expect(schedule.calls.length).toBeGreaterThan(0);
            expect(schedule.calls.length).toBeLessThanOrEqual(3);
            for (const bytes of schedule.calls)
                expect(bytes).toBeLessThanOrEqual(((1n << 31n) * 15n) / 16n);
            expect(schedule.continuationReadBytes).toBeGreaterThanOrEqual(
                schedule.replayBytes,
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
