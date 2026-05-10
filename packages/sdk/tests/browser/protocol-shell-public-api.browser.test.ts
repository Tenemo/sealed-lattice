import { describe, expect, it } from 'vitest';

import {
    deriveLifecycleLabels,
    deriveThresholdProfile,
    evaluateActionCapability,
    isValidLifecycleTransition,
    validatePollSpec,
    verifyTranscriptCoreFixture,
} from '../../dist/index.js';
import * as publicApi from '../../dist/index.js';

describe('protocol-shell public package API in browsers', () => {
    it('exposes callable safe runtime functions and keeps obvious raw APIs absent', () => {
        expect(typeof deriveLifecycleLabels).toBe('function');
        expect(typeof deriveThresholdProfile).toBe('function');
        expect(typeof evaluateActionCapability).toBe('function');
        expect(typeof isValidLifecycleTransition).toBe('function');
        expect(typeof validatePollSpec).toBe('function');
        expect(typeof verifyTranscriptCoreFixture).toBe('function');
        expect('thresholdDecrypt' in publicApi).toBe(false);
        expect('rawHEAdd' in publicApi).toBe(false);
        expect('rawNTT' in publicApi).toBe(false);
    });

    it('runs the deterministic protocol-shell shell without WASM-specific APIs', () => {
        const thresholdProfile = publicApi.deriveThresholdProfile({
            rosterSize: 20,
        });

        expect(thresholdProfile.releaseQuorum).toBe(14);
        expect(
            publicApi.validatePollSpec({
                pollId: 'browser-poll',
                question: 'Question',
                options: ['A', 'B', 'C'],
                topOptionCount: 2,
            }),
        ).toMatchObject({ ok: true });
        expect(
            publicApi.evaluateActionCapability('DeriveAggregateContribution', {
                lifecycleState: 'VotingClosed',
                thresholdProfile,
                pollSpecValid: true,
                setupCompleteCount: thresholdProfile.setupCompletionQuorum,
                turnoutCount: thresholdProfile.releaseQuorum,
            }),
        ).toEqual({
            allowed: true,
            action: 'DeriveAggregateContribution',
        });
    });
});
