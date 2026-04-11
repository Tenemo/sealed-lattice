import { describe, expect, it } from 'vitest';

import {
    buildCoverageBadge,
    getTotalLinesMetric,
    normalizeCoverageSummary,
    type CoverageSummary,
} from '#tools/generate-coverage-badge';

describe('coverage badge generation helpers', () => {
    it('throws a clear error when total metrics are missing', () => {
        expect(() => getTotalLinesMetric({})).toThrowError(
            'Coverage summary is missing total metrics',
        );
    });

    it('throws a clear error when total.lines metrics are missing', () => {
        expect(() =>
            getTotalLinesMetric({
                total: {
                    functions: {
                        total: 3,
                        covered: 3,
                        skipped: 0,
                        pct: 100,
                    },
                },
            }),
        ).toThrowError('Coverage summary is missing total.lines metrics');
    });

    it('normalizes mixed path separators and keeps keys sorted deterministically', () => {
        const repoRoot = 'C:\\work\\sealed-lattice';
        const summary: CoverageSummary = {
            'src\\relative.ts': {
                lines: { total: 1, covered: 1, skipped: 0, pct: 100 },
            },
            'c:/work/sealed-lattice/src/beta.ts': {
                lines: { total: 2, covered: 2, skipped: 0, pct: 100 },
            },
            total: {
                lines: { total: 10, covered: 9, skipped: 0, pct: 90 },
            },
            'C:\\work\\sealed-lattice\\src\\alpha.ts': {
                lines: { total: 3, covered: 2, skipped: 0, pct: 66.7 },
            },
        };

        const normalizedSummary = normalizeCoverageSummary(summary, repoRoot);

        expect(Object.keys(normalizedSummary)).toEqual([
            'total',
            'src/alpha.ts',
            'src/beta.ts',
            'src/relative.ts',
        ]);
    });

    it('builds the badge from normalized total line coverage', () => {
        const repoRoot = 'C:\\work\\sealed-lattice';
        const summary: CoverageSummary = {
            total: {
                lines: { total: 20, covered: 18, skipped: 0, pct: 89.95 },
            },
            'C:\\work\\sealed-lattice\\src\\index.ts': {
                lines: { total: 20, covered: 18, skipped: 0, pct: 89.95 },
            },
        };

        const normalizedSummary = normalizeCoverageSummary(summary, repoRoot);
        const badge = buildCoverageBadge(normalizedSummary);

        expect(badge).toEqual({
            schemaVersion: 1,
            label: 'coverage',
            message: '90%',
            color: 'green',
        });
    });
});
