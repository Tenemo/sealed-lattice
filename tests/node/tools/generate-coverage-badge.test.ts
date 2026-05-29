import { describe, expect, it } from 'vitest';

import {
    buildCoverageBadge,
    colorForCoverage,
    createCoverageArtifacts,
    normalizeCoverageKey,
    totalLineMetric,
    validateCoverageScope,
    type CoverageEntry,
    type CoverageSummary,
} from '#tools/ci/generate-coverage-badge';

const coverageEntry = (linePercent: number): CoverageEntry => ({
    lines: {
        covered: linePercent,
        pct: linePercent,
        skipped: 0,
        total: 100,
    },
});

const coverageSummaryWithEntries = (
    entries: Readonly<Record<string, CoverageEntry>>,
    totalLinePercent = 57.84,
): CoverageSummary => ({
    total: coverageEntry(totalLinePercent),
    ...entries,
});

describe('coverage badge generation', () => {
    it('uses Shields colors at the documented threshold boundaries', () => {
        expect(colorForCoverage(100)).toBe('brightgreen');
        expect(colorForCoverage(95)).toBe('brightgreen');
        expect(colorForCoverage(94.99)).toBe('green');
        expect(colorForCoverage(90)).toBe('green');
        expect(colorForCoverage(89.99)).toBe('yellowgreen');
        expect(colorForCoverage(80)).toBe('yellowgreen');
        expect(colorForCoverage(79.99)).toBe('yellow');
        expect(colorForCoverage(70)).toBe('yellow');
        expect(colorForCoverage(69.99)).toBe('orange');
        expect(colorForCoverage(60)).toBe('orange');
        expect(colorForCoverage(59.99)).toBe('red');
    });

    it('normalizes absolute and Windows coverage keys to repository-relative keys', () => {
        expect(
            normalizeCoverageKey(
                'C:\\repo\\sealed-lattice\\packages\\sdk\\src\\index.ts',
                'C:\\repo\\sealed-lattice',
            ),
        ).toBe('packages/sdk/src/index.ts');
        expect(
            normalizeCoverageKey(
                '/repo/sealed-lattice/tools/ci/check-package-boundaries.ts',
                '/repo/sealed-lattice',
            ),
        ).toBe('tools/ci/check-package-boundaries.ts');
        expect(normalizeCoverageKey('total', '/repo/sealed-lattice')).toBe(
            'total',
        );
    });

    it('builds deterministic badge and normalized summary artifacts', () => {
        const projectRoot = 'C:\\repo\\sealed-lattice';
        const rawSummary = coverageSummaryWithEntries({
            'C:\\repo\\sealed-lattice\\packages\\sdk\\src\\index.ts':
                coverageEntry(91.2),
            'C:\\repo\\sealed-lattice\\tools\\ci\\check-package-boundaries.ts':
                coverageEntry(75),
        });

        const { badge, summary } = createCoverageArtifacts(
            rawSummary,
            projectRoot,
            {
                requiredEntryPaths: [
                    'packages/sdk/src/index.ts',
                    'tools/ci/check-package-boundaries.ts',
                ],
            },
        );

        expect(badge).toEqual({
            schemaVersion: 1,
            label: 'node source coverage',
            message: '57.8%',
            color: 'red',
        });
        expect(Object.keys(summary)).toEqual([
            'total',
            'packages/sdk/src/index.ts',
            'tools/ci/check-package-boundaries.ts',
        ]);
    });

    it('rejects missing total metrics and missing required source entries', () => {
        expect(() => totalLineMetric({})).toThrow(/missing total metrics/u);
        expect(() =>
            totalLineMetric({
                total: {
                    statements: {
                        covered: 1,
                        pct: 100,
                        skipped: 0,
                        total: 1,
                    },
                },
            }),
        ).toThrow(/missing total\.lines/u);

        expect(() =>
            validateCoverageScope(
                coverageSummaryWithEntries({
                    'packages/sdk/src/index.ts': coverageEntry(100),
                }),
                [
                    'packages/sdk/src/index.ts',
                    'tools/ci/stage-public-package.mjs',
                ],
            ),
        ).toThrow(/tools\/ci\/stage-public-package\.mjs/u);
    });

    it('formats whole-number and rounded decimal percentages', () => {
        expect(buildCoverageBadge(coverageSummaryWithEntries({}, 60))).toEqual({
            schemaVersion: 1,
            label: 'node source coverage',
            message: '60%',
            color: 'orange',
        });
        expect(
            buildCoverageBadge(coverageSummaryWithEntries({}, 79.96)),
        ).toEqual({
            schemaVersion: 1,
            label: 'node source coverage',
            message: '80%',
            color: 'yellowgreen',
        });
    });
});
