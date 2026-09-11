import assert from 'node:assert/strict';

import { describe, expect, it } from 'vitest';

import { createSlotPublicationModel } from '#tests/slot-publication-model.js';

type Model = ReturnType<typeof createSlotPublicationModel>;
type Token = NonNullable<ReturnType<Model['originate']>>;

const publish = (model: Model, token: Token) => {
    for (const member of model.committees[token.author])
        assert.equal(model.witness(member, token, token.body), true);
    const certificate = model.certificate(token);
    assert.equal(model.publish(certificate), true);
    return certificate;
};

describe('permanent per-slot publication decisions', () => {
    it('includes every honest first attempt and classifies only authenticated bodies', () => {
        const model = createSlotPublicationModel(10, [], 'poll-a');
        model.fixture('default-ballot', true);
        model.fixture('invalid-proof', false);
        const first = model.originate(0, 'default-ballot')!;
        const invalid = model.originate(1, 'invalid-proof')!;
        expect(model.witness(2, invalid, 'corrupted-transport')).toBe(false);
        const values = [publish(model, first), publish(model, invalid)];
        expect(model.requestClose(1)).toBe(false);
        expect(model.originate(2, null)).toBeUndefined();
        expect(model.requestClose(0)).toBe(true);
        expect(model.requestClose(0)).toBe(false);
        expect(model.originate(0, null)).toBeUndefined();
        expect(model.observeClose(2)).toBe(true);
        expect(model.originate(2, 'default-ballot')).toBeUndefined();
        for (let author = 2; author < 10; author++) {
            model.observeClose(author);
            values.push(publish(model, model.originate(author, null)!));
        }
        expect(model.close(values)).toEqual([
            { author: 0, body: 'default-ballot', classification: 'accepted' },
            { author: 1, body: 'invalid-proof', classification: 'invalid' },
            ...Array.from({ length: 8 }, (_, index) => ({
                author: index + 2,
                body: null,
                classification: 'missing',
            })),
        ]);
        expect(model.close([...values].reverse())).toEqual(model.close(values));
        expect(model.close(values.slice(1))).toBeUndefined();
        expect(model.close([...values.slice(1), values[1]])).toBeUndefined();
    });

    it('preserves a corrupt author’s completed first publication after later equivocation', () => {
        const model = createSlotPublicationModel(10, [0, 1, 2], 'poll-a');
        model.fixture('first', true);
        model.fixture('second', true);
        const first = model.originate(0, 'first')!;
        const original = publish(model, first);
        model.requestClose(0);
        const later = [
            model.originate(0, 'second')!,
            model.originate(0, null)!,
        ];
        const laterCertificates = later.map((token) => {
            const responses = model.committees[0].map((member) =>
                model.witness(member, token, token.body),
            );
            return { certificate: model.certificate(token), responses };
        });
        for (const result of laterCertificates) {
            expect(result.responses).toEqual([true, true, true, false]);
            expect(model.verifyCertificate(result.certificate)).toBe(false);
            expect(model.publish(result.certificate)).toBe(false);
        }
        expect(model.verifyCertificate(original)).toBe(true);
        expect(model.publish(original)).toBe(true);
    });

    it('refuses forged, incomplete, duplicated and cross-action certificate carriers', () => {
        const model = createSlotPublicationModel(10, [], 'poll-a');
        model.fixture('body', true);
        const token = model.originate(0, 'body')!;
        const certificate = model.certificate(token);
        expect(model.verifyCertificate(certificate)).toBe(false);
        publish(model, token);
        expect(
            model.verifyCertificate({
                ...certificate,
                witnesses: [0, 1, 2, 2],
            }),
        ).toBe(false);
        expect(
            model.verifyCertificate({
                ...certificate,
                token: { ...token, author: 1 },
            }),
        ).toBe(false);
        const other = createSlotPublicationModel(10, [], 'poll-b');
        other.fixture('body', true);
        other.originate(0, 'body');
        expect(other.verifyCertificate(certificate)).toBe(false);
    });

    it('exposes the remaining origin-to-publication gap before any honest witness acts', () => {
        const make = (choice: 'first' | 'second' | null) => {
            const model = createSlotPublicationModel(10, [0, 1, 2], 'poll-a');
            model.fixture('first', true);
            model.fixture('second', true);
            const first = model.originate(0, 'first')!;
            const second = model.originate(0, 'second')!;
            model.requestClose(0);
            const empty = model.originate(0, null)!;
            const prefix = [first, second, empty];
            const selected = prefix.find((token) => token.body === choice)!;
            const values = [publish(model, selected)];
            for (let author = 1; author < 10; author++) {
                model.observeClose(author);
                values.push(publish(model, model.originate(author, null)!));
            }
            return { prefix, inventory: model.close(values)! };
        };
        const variants = [make('first'), make('second'), make(null)];
        expect(variants.map((value) => value.prefix)).toEqual(
            Array(3).fill(variants[0].prefix),
        );
        expect(variants.map((value) => value.inventory[0].body)).toEqual([
            'first',
            'second',
            null,
        ]);
        expect(variants.map((value) => value.inventory.slice(1))).toEqual(
            Array(3).fill(variants[0].inventory.slice(1)),
        );
    });

    it('uses local close knowledge and retains an earlier in-progress attempt', () => {
        const model = createSlotPublicationModel(10, [], 'poll-a');
        model.fixture('first', true);
        model.fixture('replacement', true);
        expect(model.observeClose(1)).toBe(false);
        expect(model.beginAttempt(1, 'first')).toBe(true);
        expect(model.beginAttempt(1, 'replacement')).toBe(false);
        model.requestClose(0);
        expect(model.originate(2, null)).toBeUndefined();
        const delayed = model.originate(2, 'first');
        expect(delayed).toBeDefined();
        model.observeClose(1);
        expect(model.originate(1, null)).toBeUndefined();
        expect(model.originate(1, 'replacement')).toBeUndefined();
        const original = model.originate(1, 'first');
        expect(original).toBeDefined();
        expect(model.verifyCertificate(publish(model, original!))).toBe(true);
        model.observeClose(3);
        expect(model.beginAttempt(3, 'first')).toBe(false);
        expect(model.originate(3, 'first')).toBeUndefined();
        expect(model.originate(3, null)).toBeDefined();
    });
});
