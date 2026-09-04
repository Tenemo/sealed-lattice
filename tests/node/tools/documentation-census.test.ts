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
            '## Candidate setup-proof field census',
            '## Share-encryption cross-modulus census',
            '## Polynomial oracle boundary census',
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
            '| Setup transfer corpus floor | `2,945,187,840` |',
        );
        expect(rendered).toContain(
            '| Fully resident evaluation plus relinearization above the absolute bound | no |',
        );
        expect(rendered).toContain(
            '| Fully resident evaluation plus all keys above the absolute bound | yes |',
        );
        expect(rendered).toContain(
            '| One-key-pass-per-operation local reads | `6,025,379,840` |',
        );
        expect(rendered).toContain(
            '| Public encrypted-sharing setup floor before proofs | `1,912,012,800` |',
        );
        expect(rendered).toContain('| Share-encryption modulus bits | `144` |');
        expect(rendered).toContain(
            '| Share plaintext prime Proth witness | `3` |',
        );
        expect(rendered).toContain(
            '| Optimistic Ligero proof per contributor | `69,369,183` |',
        );
        expect(rendered).toContain(
            '| Encoded proof oracle per contributor | `21,948,334,080` |',
        );
        expect(rendered).toContain(
            '| Shared views between the two one-mask witnesses | `0` |',
        );
        expect(rendered).toContain('| Pocklington witnesses checked | `3` |');
        expect(rendered).toContain(
            '| Minimum no-wrap proof-field bits | `160` |',
        );
        expect(rendered).toContain(
            '| Signed quotient storage bits per coefficient | `16` |',
        );
        expect(rendered).toContain(
            '| Exact dominant noise-budget floor at 80 statistical bits | `106` |',
        );
        expect(rendered).toContain(
            '| Successful-result visits for an early release author | `10` |',
        );
        expect(rendered).toContain(
            '| Setup plus proof subtotal | `5,456,855,040` |',
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
