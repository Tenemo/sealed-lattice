import type { FieldElement } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    addFieldElements,
    decodeFieldElement,
    encodeFieldElement,
    exponentiateFieldElement,
    fieldModulus,
    invertFieldElement,
    multiplyFieldElements,
    subtractFieldElements,
} from '../../src/plaintext-oracle/index';

import { fieldVectors } from './plaintext-oracle-test-vectors';

describe('plaintext oracle field arithmetic', () => {
    it('matches canonical field encoding and inverse vectors', () => {
        expect(fieldVectors.modulus).toBe(fieldModulus);

        for (const vector of fieldVectors.encodings) {
            expect(encodeFieldElement(vector.value)).toBe(vector.bytesHex);
            expect(decodeFieldElement(vector.bytesHex)).toBe(vector.value);
        }

        for (const vector of fieldVectors.inverseCases) {
            expect(invertFieldElement(vector.value)).toBe(vector.inverse);
            expect(multiplyFieldElements(vector.value, vector.inverse)).toBe(
                vector.product,
            );
        }
    });

    it('satisfies finite-field invariants over edge-heavy examples', () => {
        const examples: readonly FieldElement[] = [
            0, 1, 2, 3, 17, 32768, 32769, 65536,
        ];

        for (const left of examples) {
            for (const right of examples) {
                expect(addFieldElements(left, right)).toBe(
                    addFieldElements(right, left),
                );
                expect(multiplyFieldElements(left, right)).toBe(
                    multiplyFieldElements(right, left),
                );
                expect(
                    subtractFieldElements(addFieldElements(left, right), right),
                ).toBe(left);
            }

            if (left !== 0) {
                expect(
                    multiplyFieldElements(left, invertFieldElement(left)),
                ).toBe(1);
                expect(exponentiateFieldElement(left, fieldModulus - 1)).toBe(
                    1,
                );
            }
        }
    });

    it('rejects malformed field encodings and invalid inversions', () => {
        expect(() => decodeFieldElement('')).toThrow(
            'exactly three lowercase hex bytes',
        );
        expect(() => decodeFieldElement('010001')).toThrow('0..65536');
        expect(() => invertFieldElement(0)).toThrow('Zero has no inverse');
    });
});
