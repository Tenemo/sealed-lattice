import { beforeAll, describe, expect, it } from 'vitest';

import {
    findFirstCensusMismatch,
    linkPrivateOwners,
    renderDocumentationCensus,
} from '#tools/ci/generate-documentation-census.js';

describe('documentation census generator', () => {
    let rendered: string;
    beforeAll(() => {
        rendered = renderDocumentationCensus();
    });

    it('renders the section of each model owner', () => {
        expect(rendered.match(/^#{2,3} .+$/gmu)).toEqual([
            '## Threshold completion census',
            '## Threshold key-aggregation structural census',
            '## Bounded polynomial proof census',
            '## Wide sharing and release lifting census',
            '## Linked ballot encryption census',
            '## Ballot body census',
            '## Authentication frames and completed prefix',
            '## Proof hash byte and permutation work',
            '## Release verification attempts',
            '## Proof verifier query bounds',
            '## Sparse-support sampling comparison',
            '## Recipient-key arithmetic bounds',
            '## Original-source arithmetic bounds',
            '## Generated setup arithmetic bounds',
            '## Source coefficient normalization comparison',
            '## Proof simulator randomness budgets',
            '## Buffered field-sampling observations',
            '## Operation randomness seeds',
            '## Private randomness scope inventory',
            '## Registration source randomness and hash work',
            '## Participant ballot custody',
            '## Participant close custody',
            '## Participant release custody',
            '## Linked release relation census',
            '## Setup contribution operator census',
            '## Relation integer-lifting census',
            '## Exact RNS arithmetic census',
            '## Common-agreement degree census',
            '## Wide-challenge compiler census',
            '## Proof compiler chronology',
            '## Full word-proof encoding census',
            '## Browser word-prover resource census',
            '## Contribution generation and sampling census',
            '## Recipient key census',
            '## Registration enrollment census',
            '## First-oracle checkpoint census',
            '## Selected opening transform census',
            '## Contribution body census',
            '## Setup selection and registration binding screen',
            '### FHE key source generation screen',
            '## Setup aggregate cache census',
            '## Shared participant custody census',
            '## Participant vault key work',
            '## Committed offers and published aggregates',
            '## Setup selection wire and resources',
            '## Complete ordinary workflow resource screen',
            '## Scalar evaluation storage screen',
            '## Roster proposal census',
            '## Common-matrix sampling census',
            '## Fixed sponge initialization census',
            '## Certificate custody census',
            '## Fixed-modulus BFV noise census',
            '## Supported profile census',
            '## Composed security ledger',
            '### FHE Ring-LWE',
            '### Evaluation-key circular security',
            '### Share-encryption Ring-LWE',
            '### Auxiliary Ring-LWE',
            '### Joint population limits',
            '### Full-interval error checks',
            '## Proof-field coefficient-fold bounds',
            '## Small-limb proof-field census',
            '## Simulator recipient-key availability',
            '## Close-response census',
            '## Threshold release flooding bound',
            '## Close wire census',
        ]);
        expect(rendered).toContain('| 10 | 3 | 7 | 4 | 5 | yes | 4 | 4 | 0 |');
        expect(rendered).toContain('| 3 | 0 | 3 | 2 | 2 | no | 3 | 3 | 0 |');
        expect(rendered).toContain(
            '| Authorized release subsets checked | `210` |',
        );
        expect(rendered).toContain('| Security target bits | `128` |');
        expect(rendered).toContain(
            '| Exact dominant noise-budget bound at the selected 96 statistical bits | `123` |',
        );
        expect(rendered).toContain(
            '| Hypothetical exact dominant noise-budget bound at 128 statistical bits | `155` |',
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
