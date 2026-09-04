import { describe, expect, it } from 'vitest';

import {
    findFirstCensusMismatch,
    renderDocumentationCensus,
} from '#tools/ci/generate-documentation-census.js';

describe('documentation census generator', () => {
    const rendered = renderDocumentationCensus();

    it('renders deterministically with the current model owners', () => {
        expect(renderDocumentationCensus()).toBe(rendered);
        for (const heading of [
            '## Threshold completion census',
            '## Threshold key-aggregation structural census',
            '## Public encrypted-sharing structural census',
            '## Bounded-integer sharing privacy census',
            '## Threshold key-aggregation resource floor',
            '## Public encrypted-sharing proof screen',
            '## Specialized setup PIOP screen',
            '## Threshold release flooding bound',
            '## Generic commit-and-open setup-proof floor',
            '## Participant visit dependency census',
            '## Exact ranking arithmetic census',
            '## Packed ranking graph census',
        ]) {
            expect(rendered).toContain(`\n${heading}\n`);
        }
        expect(rendered).toContain('| 10 | 3 | 7 | 4 | 10 | 4 | 4 | 6 | 0 |');
        expect(rendered).toContain(
            '| Authorized release subsets checked | `210` |',
        );
        expect(rendered).toContain(
            '| Setup transfer corpus floor | `3,335,454,720` |',
        );
        expect(rendered).toContain(
            '| Fully resident evaluation plus relinearization above the absolute bound | yes |',
        );
        expect(rendered).toContain(
            '| One-key-pass-per-operation local reads | `7,132,676,096` |',
        );
        expect(rendered).toContain(
            '| Public encrypted-sharing setup floor before proofs | `2,204,958,720` |',
        );
        expect(rendered).toContain('| Share-encryption modulus bits | `144` |');
        expect(rendered).toContain(
            '| Share plaintext prime Proth witness | `3` |',
        );
        expect(rendered).toContain(
            '| Optimistic Ligero proof per contributor | `74,378,926` |',
        );
        expect(rendered).toContain(
            '| Encoded proof oracle per contributor | `23,685,758,976` |',
        );
        expect(rendered).toContain(
            '| Optimistic proof bytes per contributor | `706,320` |',
        );
        expect(rendered).toContain(
            '| Exact dominant noise-budget floor at 80 statistical bits | `106` |',
        );
        expect(rendered).toContain(
            '| Successful-result visits for an early release author | `10` |',
        );
        expect(rendered).toContain(
            '| Setup plus proof subtotal | `6,026,526,720` |',
        );
        expect(rendered).toContain(
            '| Ordered pair-difference lanes | `90` | `380` |',
        );
        expect(rendered).toContain(
            '| Ciphertext multiplications | `59` | `69` |',
        );
        expect(rendered).not.toMatch(/\d{4}-\d{2}-\d{2}T/u);
        expect(rendered.endsWith('\n')).toBe(true);
    });

    it('locates the first stale line of a stored census', () => {
        expect(findFirstCensusMismatch(rendered, rendered)).toBeUndefined();
        expect(
            findFirstCensusMismatch(rendered.replace(/\n/gu, '\r\n'), rendered),
        ).toBeUndefined();
        const lines = rendered.split('\n');
        const target = lines.findIndex((line) => line.startsWith('| 10 |'));
        expect(target).toBeGreaterThan(0);
        lines[target] = `${lines[target] ?? ''} stale`;
        expect(findFirstCensusMismatch(lines.join('\n'), rendered)).toBe(
            target + 1,
        );
        expect(findFirstCensusMismatch(`${rendered}extra\n`, rendered)).toBe(
            lines.length,
        );
    });
});
