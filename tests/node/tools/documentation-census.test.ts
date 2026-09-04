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
            '## Threshold key-aggregation resource floor',
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
            '| Public setup corpus floor | `2,799,001,600` |',
        );
        expect(rendered).toContain(
            '| Exact dominant noise-budget floor at 80 statistical bits | `106` |',
        );
        expect(rendered).toContain(
            '| Successful-result visits for an early release author | `10` |',
        );
        expect(rendered).toContain(
            '| Setup plus proof subtotal | `5,203,025,920` |',
        );
        expect(rendered).toContain('`467`');
        expect(rendered).toContain('`987`');
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
