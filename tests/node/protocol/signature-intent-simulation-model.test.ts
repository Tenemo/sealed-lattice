import { describe, expect, it } from 'vitest';

import {
    createSignatureIntentSimulation,
    signatureIntentJointDistribution,
} from '#tests/signature-intent-simulation-model.js';

const message = { key: 'original-key', context: 'ballot', body: 'envelope' };

describe('signing-intent oracle simulation', () => {
    it('matches the complete distribution despite reordered first evaluations', () => {
        const real = signatureIntentJointDistribution('retained-coins');
        expect(real).toHaveLength(16);
        expect(real.reduce((sum, [, count]) => sum + count, 0)).toBe(16);
        expect(signatureIntentJointDistribution('cached-oracle')).toEqual(real);
    });

    it.each(['retained-coins', 'cached-oracle'] as const)(
        'preserves interrupted and completed responses in %s',
        (mode) => {
            const model = createSignatureIntentSimulation(mode, [2, 3]);
            model.begin('first-intent', message);
            const first = model.evaluate('first-intent', message);
            model.interrupt('first-intent');
            expect(() => model.commit('first-intent')).toThrow();
            expect(model.evaluate('first-intent', message)).toBe(first);
            model.commit('first-intent');
            model.interrupt('first-intent');
            expect(model.evaluate('first-intent', message)).toBe(first);
            model.begin('independent-intent', message);
            expect(model.evaluate('independent-intent', message)).not.toBe(
                first,
            );
            expect(model.counts()).toEqual({
                randomDraws: 2,
                signingEvaluations: 3,
                oracleQueries: mode === 'cached-oracle' ? 2 : 0,
            });
        },
    );

    it('does not let a simulator cache restore lost participant authority', () => {
        const model = createSignatureIntentSimulation('cached-oracle', [0, 1]);
        model.begin('intent', message);
        model.evaluate('intent', message);
        model.loseRequiredState('intent');
        expect(() => model.evaluate('intent', message)).toThrow();
        expect(() => model.begin('intent', message)).toThrow();
        expect(model.counts().oracleQueries).toBe(1);
    });

    it('refuses a changed key, purpose or body before querying the oracle', () => {
        const model = createSignatureIntentSimulation('cached-oracle', [0]);
        model.begin('intent', message);
        for (const changed of [
            { ...message, key: 'replacement-key' },
            { ...message, context: 'opening' },
            { ...message, body: 'different-envelope' },
        ])
            expect(() => model.evaluate('intent', changed)).toThrow();
        expect(model.counts().oracleQueries).toBe(0);
        expect(model.evaluate('intent', message)).toBeDefined();
        expect(model.counts().oracleQueries).toBe(1);
    });
});
