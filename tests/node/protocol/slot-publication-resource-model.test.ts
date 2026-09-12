import { describe, expect, it } from 'vitest';

import { compileSlotPublicationResourceCensus } from '#tests/slot-publication-resource-model.js';

describe('complete slot-publication metadata', () => {
    it('bounds every supported profile and retains distinct corrupt evidence carriers', () => {
        for (let participants = 3; participants <= 20; participants++) {
            const value = compileSlotPublicationResourceCensus(participants);
            expect(value.otherWitnesses).toBe(
                BigInt(Math.floor((participants - 1) / 3)),
            );
            for (const bytes of [
                value.closeBodyBytes,
                value.emptyBodyBytes,
                value.witnessBodyBytes,
                value.closedBodyBytes,
            ])
                expect(bytes).toBeLessThanOrEqual(2048n);
            expect(value.maximumEvidenceMetadataBytes).toBeLessThan(1_572_864n);
            expect(value.maximumWitnessCarrierBytes).toBeGreaterThanOrEqual(
                value.ordinaryWitnessBytes,
            );
        }
        expect(
            compileSlotPublicationResourceCensus(20).closedBodyBytes,
        ).toBeGreaterThan(1024n);
    });
});
