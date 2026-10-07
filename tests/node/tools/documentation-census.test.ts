import { describe, expect, it } from 'vitest';

import {
    findFirstCensusMismatch,
    linkPrivateOwners,
    renderDocumentationCensus,
} from '#tools/ci/generate-documentation-census.js';

describe('documentation census generator', () => {
    const rendered = renderDocumentationCensus();

    it('renders deterministically with the current model owners', () => {
        expect(renderDocumentationCensus()).toBe(rendered);
        for (const heading of [
            '## Threshold completion census',
            '## Threshold key-aggregation structural census',
            '## Recipient-key uniqueness census',
            '## Commitment equivocation finite model',
            '### Assumption group limits',
            '## Bounded polynomial proof census',
            '## Small-limb proof-field census',
            '## Fixed-modulus BFV noise census',
            '## Certificate custody census',
            '## Roster proposal census',
            '## Contribution body census',
            '## Common-matrix sampling census',
            '## Wide-challenge compiler census',
            '## Common-agreement degree census',
            '## Exact RNS arithmetic census',
            '## Setup contribution operator census',
            '## Linked release relation census',
            '## Linked ballot encryption census',
            '## Wide sharing and release lifting census',
            '## Threshold release flooding bound',
        ]) {
            expect(rendered).toContain(`\n${heading}\n`);
        }
        expect(rendered).toContain('| 10 | 3 | 7 | 4 | 5 | yes | 4 | 4 | 0 |');
        expect(rendered).toContain('| 3 | 0 | 3 | 2 | 2 | no | 3 | 3 | 0 |');
        expect(rendered).toContain(
            '| Authorized release subsets checked | `210` |',
        );
        expect(rendered).toContain(
            '| Exact dominant noise-budget floor at 80 statistical bits | `106` |',
        );
        expect(rendered).not.toMatch(/\d{4}-\d{2}-\d{2}T/u);
        expect(rendered.endsWith('\n')).toBe(true);
    });

    it('resolves private citations only through the link table', () => {
        expect(rendered).not.toContain('](private:');
        const text =
            'See [the ledger](private:security-ledger) and [the paths](private:stage-paths).';
        expect(linkPrivateOwners(text, undefined)).toBe(
            'See the ledger and the paths.',
        );
        expect(
            linkPrivateOwners(text, {
                'security-ledger': 'ledger.md#ledger',
                'stage-paths': 'paths.md#paths',
            }),
        ).toBe(
            'See [the ledger](ledger.md#ledger) and [the paths](paths.md#paths).',
        );
        expect(() =>
            linkPrivateOwners(text, { 'security-ledger': 'ledger.md#ledger' }),
        ).toThrow('The census link table has no stage-paths.');
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
