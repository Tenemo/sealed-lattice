import { describe, expect, it } from 'vitest';

import { createSignatureIntentSimulation } from '#tests/signature-intent-simulation-model.js';

const message = { key: 'original-key', context: 'ballot', body: 'envelope' };

describe('signing-intent oracle simulation', () => {
    it('agrees when intent creation and first evaluation have different orders', () => {
        const trace = (mode: 'deterministic' | 'cached-oracle') => {
            const model = createSignatureIntentSimulation(mode);
            model.begin('first', message);
            const second = { ...message, body: 'another-envelope' };
            model.begin('second', second);
            const initial = model.evaluate('second', second);
            model.interrupt('second');
            return [
                initial,
                model.evaluate('second', second),
                model.evaluate('first', message),
            ];
        };
        const actual = trace('deterministic');
        expect(actual[0]).toBe(actual[1]);
        expect(actual[0]).not.toBe(actual[2]);
        expect(trace('cached-oracle')).toEqual(actual);
    });

    it.each(['deterministic', 'cached-oracle'] as const)(
        'preserves interrupted and completed responses in %s',
        (mode) => {
            const model = createSignatureIntentSimulation(mode);
            model.begin('first-intent', message);
            const first = model.evaluate('first-intent', message);
            model.interrupt('first-intent');
            expect(() => model.commit('first-intent')).toThrow();
            expect(model.evaluate('first-intent', message)).toBe(first);
            model.commit('first-intent');
            model.interrupt('first-intent');
            expect(model.evaluate('first-intent', message)).toBe(first);
            model.begin('independent-intent', message);
            expect(model.evaluate('independent-intent', message)).toBe(first);
            expect(model.counts()).toEqual({
                signingEvaluations: 3,
                oracleQueries: mode === 'cached-oracle' ? 2 : 0,
            });
        },
    );

    it('does not let a simulator cache restore lost participant authority', () => {
        const model = createSignatureIntentSimulation('cached-oracle');
        model.begin('intent', message);
        model.evaluate('intent', message);
        model.loseRequiredState('intent');
        expect(() => model.evaluate('intent', message)).toThrow();
        expect(() => model.begin('intent', message)).toThrow();
        expect(model.counts().oracleQueries).toBe(1);
    });

    it('refuses a changed key, purpose or body before querying the oracle', () => {
        const model = createSignatureIntentSimulation('cached-oracle');
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
