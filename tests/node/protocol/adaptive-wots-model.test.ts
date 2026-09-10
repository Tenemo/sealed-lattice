import { describe, expect, it } from 'vitest';

import {
    adaptiveWotsBound,
    adaptiveChainStateControl,
    adaptiveChainViews,
    wotsMessageSource,
} from '#tests/adaptive-wots-model.js';
import { compileStatelessSignatureWork } from '#tests/stateless-signature-work-model.js';

describe('Adaptive WOTS chain argument', () => {
    it('counts the verifier oracle result in the compared quantum states', () => {
        for (const domain of [16, 64] as const) {
            const value = adaptiveChainStateControl(domain);
            expect(value.samples).toBe(2 * domain ** 2);
            expect(value.denominator).toBe(domain ** 2);
            expect(BigInt(value.distance) * BigInt(domain)).toBeLessThanOrEqual(
                16n * BigInt(value.samples) * BigInt(value.denominator),
            );
            expect(value.realSuccess).toBeLessThanOrEqual(
                2 * value.stagedSuccess + 2 * value.distance,
            );
            expect(value.realSuccess).not.toBe(value.stagedSuccess);
        }
    });
    it('matches chain laws and extracts a real base-query match from staged verification', () => {
        const value = adaptiveChainViews();
        expect(value.image.reduce((sum, view) => sum + view.real, 0n)).toBe(
            32n,
        );
        expect(
            value.image.reduce((sum, view) => sum + view.programmed, 0n),
        ).toBe(128n);
        for (const view of value.image)
            expect(view.programmed).toBe(4n * view.real);
        expect(value.views.reduce((sum, view) => sum + view.staged, 0n)).toBe(
            384n,
        );
        expect(value.views.reduce((sum, view) => sum + view.search, 0n)).toBe(
            384n,
        );
        for (const view of value.views) expect(view.staged).toBe(view.search);
        expect(value.validStaged).toBeGreaterThan(0);
        expect(value.unjustifiedRealVerifier).toBeGreaterThan(0);
        expect(value.hiddenGroups).toBeGreaterThan(0);
    });
    it('exposes why two distinct signing messages exceed the one-time contract', () => {
        const { low, high, forged, exposed } =
            adaptiveChainViews().twoMessageExposure;
        expect(exposed).toEqual(Array<number>(67).fill(0));
        expect(forged).not.toEqual(low);
        expect(forged).not.toEqual(high);
        expect(forged.every((digit, index) => digit >= exposed[index])).toBe(
            true,
        );
    });
    it('matches the source tree-shift schedule and fixes one child object per address', () => {
        const work = compileStatelessSignatureWork(),
            maximum = (1n << work.totalHeight) - 1n;
        const indices = [
            0n,
            1n,
            15n,
            16n,
            0x123456789abcdefan,
            maximum,
            ...Array.from({ length: 68 }, (_, bit) => 1n << BigInt(bit)),
        ];
        for (const index of indices) {
            let tree = index >> 4n,
                leaf = index & 15n,
                previousTree = 0n;
            for (let layer = 0n; layer < 17n; layer++) {
                const value = wotsMessageSource(index, layer);
                expect(value.address).toEqual({ layer, tree, leaf });
                expect(value.message).toEqual(
                    layer === 0n
                        ? { kind: 'forest', tree, leaf }
                        : {
                              kind: 'subtree',
                              layer: layer - 1n,
                              tree: previousTree,
                          },
                );
                previousTree = tree;
                leaf = tree & 15n;
                tree >>= 4n;
            }
        }
        for (let layer = 1n; layer < work.layers; layer++) {
            const lower = (1n << (layer * 4n)) - 1n,
                maximumTree =
                    (1n << (work.totalHeight - (layer + 1n) * 4n)) - 1n;
            for (const tree of [0n, maximumTree])
                for (const leaf of [0n, 1n, 15n]) {
                    const index =
                        (tree << ((layer + 1n) * 4n)) | (leaf << (layer * 4n));
                    expect(wotsMessageSource(index, layer)).toEqual(
                        wotsMessageSource(index | lower, layer),
                    );
                }
        }
        expect(() => wotsMessageSource(maximum + 1n, 0n)).toThrow(RangeError);
        expect(() => wotsMessageSource(0n, 17n)).toThrow(RangeError);
    });
    it('includes the selected-chain verification allowance before applying the bound', () => {
        const value = adaptiveWotsBound(0n, 1n, 4096n);
        expect(value.queries).toBe(1n);
        expect(value.bound).toEqual({ numerator: 19n, denominator: 512n });
        expect(adaptiveWotsBound(1n, 1n, 4096n).bound).toEqual({
            numerator: 27n,
            denominator: 256n,
        });
        const work = compileStatelessSignatureWork();
        expect(
            adaptiveWotsBound(
                1n << 80n,
                work.winternitz - 1n,
                1n << (8n * work.nodeBytes),
            ).verificationQueries,
        ).toBe(15n);
        expect(adaptiveWotsBound(10n, 15n, 16n).bound).toEqual({
            numerator: 1n,
            denominator: 1n,
        });
        expect(() => adaptiveWotsBound(0n, 0n, 4096n)).toThrow(RangeError);
    });
});
