import { describe, expect, it } from 'vitest';

import * as publicApi from '../../dist/index.js';

const expectedPublicKeys = [
    'deriveLifecycleLabels',
    'deriveThresholdProfile',
    'evaluateActionCapability',
    'isValidLifecycleTransition',
    'validatePollSpec',
    'verifyTranscriptCoreFixture',
];

describe('protocol-shell public package API in browsers', () => {
    it('exposes only safe runtime functions', () => {
        expect(Object.keys(publicApi).sort()).toEqual(expectedPublicKeys);
        expect('thresholdDecrypt' in publicApi).toBe(false);
        expect('rawHEAdd' in publicApi).toBe(false);
        expect('rawNTT' in publicApi).toBe(false);
    });

    it('runs the deterministic protocol-shell shell without WASM-specific APIs', () => {
        const thresholdProfile = publicApi.deriveThresholdProfile({ n: 20 });

        expect(thresholdProfile.qRelease).toBe(14);
        expect(
            publicApi.validatePollSpec({
                ceremonyId: 'browser-ceremony',
                question: 'Question',
                options: ['A', 'B', 'C'],
                kTop: 2,
            }),
        ).toMatchObject({ ok: true });
        expect(
            publicApi.evaluateActionCapability('DeriveAggregateContribution', {
                lifecycleState: 'VotingClosed',
                thresholdProfile,
                pollSpecValid: true,
                setupCompleteCount: thresholdProfile.qSetupComplete,
                turnoutCount: thresholdProfile.qRelease,
            }),
        ).toEqual({
            allowed: true,
            action: 'DeriveAggregateContribution',
        });
    });
});
