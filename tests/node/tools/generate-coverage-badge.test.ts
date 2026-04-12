import { describe, expect, it } from 'vitest';

import {
    buildCoverageBadge,
    colorForCoverage,
    createCoverageArtifacts,
    getTotalLinesMetric,
    normalizeCoverageKey,
    normalizeCoverageSummary,
    type CoverageEntry,
    type CoverageMetric,
    type CoverageSummary,
} from '../../../tools/generate-coverage-badge';

const createMetric = (pct: number): CoverageMetric => ({
    covered: 0,
    pct,
    skipped: 0,
    total: 0,
});

const createEntry = (pct: number): CoverageEntry => ({
    lines: createMetric(pct),
});

describe('coverage badge generator', () => {
    it.each([
        [95, 'brightgreen'],
        [94.9, 'green'],
        [90, 'green'],
        [89.9, 'yellowgreen'],
        [80, 'yellowgreen'],
        [79.9, 'yellow'],
        [70, 'yellow'],
        [69.9, 'orange'],
        [60, 'orange'],
        [59.9, 'red'],
    ])('maps %d%% coverage to %s', (percent, expectedColor) => {
        expect(colorForCoverage(percent)).toBe(expectedColor);
    });

    it('normalizes absolute coverage keys under the repo root', () => {
        expect(
            normalizeCoverageKey(
                'C:\\Repo\\sealed-lattice\\src\\crypto.ts',
                'C:\\Repo\\sealed-lattice',
            ),
        ).toBe('src/crypto.ts');
        expect(
            normalizeCoverageKey(
                'c:/repo/sealed-lattice/tests/file.test.ts',
                'C:\\Repo\\sealed-lattice',
            ),
        ).toBe('tests/file.test.ts');
        expect(normalizeCoverageKey('total', 'C:\\Repo\\sealed-lattice')).toBe(
            'total',
        );
        expect(
            normalizeCoverageKey(
                '../outside/file.ts',
                'C:\\Repo\\sealed-lattice',
            ),
        ).toBe('../outside/file.ts');
    });

    it('sorts normalized summaries with total first', () => {
        const summary: CoverageSummary = {
            'C:\\Repo\\sealed-lattice\\src\\z.ts': createEntry(12),
            total: createEntry(91),
            'c:/repo/sealed-lattice/src/a.ts': createEntry(85),
            '../outside.ts': createEntry(30),
        };

        const normalized = normalizeCoverageSummary(
            summary,
            'C:\\Repo\\sealed-lattice',
        );

        expect(Object.keys(normalized)).toEqual([
            'total',
            '../outside.ts',
            'src/a.ts',
            'src/z.ts',
        ]);
        expect(normalized['src/a.ts']).toBe(
            summary['c:/repo/sealed-lattice/src/a.ts'],
        );
    });

    it('throws when total coverage metrics are missing', () => {
        expect(() => getTotalLinesMetric({})).toThrow(
            'Coverage summary is missing total metrics',
        );
        expect(() => getTotalLinesMetric({ total: {} })).toThrow(
            'Coverage summary is missing total.lines metrics',
        );
    });

    it('builds a rounded badge from total line coverage', () => {
        expect(
            buildCoverageBadge({
                total: {
                    lines: createMetric(89.96),
                    statements: createMetric(10),
                },
            }),
        ).toEqual({
            color: 'green',
            label: 'coverage',
            message: '90%',
            schemaVersion: 1,
        });
    });

    it('creates normalized coverage artifacts for publishing', () => {
        const { badge, summary } = createCoverageArtifacts(
            {
                'C:\\Repo\\sealed-lattice\\src\\index.ts': createEntry(50),
                total: createEntry(96.4),
            },
            'C:\\Repo\\sealed-lattice',
        );

        expect(Object.keys(summary)).toEqual(['total', 'src/index.ts']);
        expect(summary['src/index.ts']).toEqual(createEntry(50));
        expect(badge).toEqual({
            color: 'brightgreen',
            label: 'coverage',
            message: '96.4%',
            schemaVersion: 1,
        });
    });
});
