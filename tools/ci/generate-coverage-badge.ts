import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { isDirectlyInvokedModule } from '#tools/internal/entry-point.js';

export type CoverageMetric = {
    readonly covered: number;
    readonly pct: number;
    readonly skipped: number;
    readonly total: number;
};

export type CoverageEntry = {
    readonly branches?: CoverageMetric;
    readonly branchesTrue?: CoverageMetric;
    readonly functions?: CoverageMetric;
    readonly lines?: CoverageMetric;
    readonly statements?: CoverageMetric;
};

export type CoverageSummary = Readonly<Record<string, CoverageEntry>>;

export type ShieldsBadge = {
    readonly color: string;
    readonly label: string;
    readonly message: string;
    readonly schemaVersion: 1;
};

export type CoverageArtifactsOptions = {
    readonly requiredEntryPaths?: readonly string[];
};

export const defaultRequiredCoverageEntryPaths = [
    'packages/crypto/src/canonical-json.ts',
    'packages/protocol/src/lifecycle/thresholds.ts',
    'packages/protocol/src/ballot-privacy/objects.ts',
    'packages/sdk/src/index.ts',
    'packages/wasm/src/transcript-core-bridge.ts',
    'tools/ci/check-package-boundaries.ts',
    'tools/ci/stage-public-package.mjs',
] as const;

const repositoryRoot = process.cwd();
const coverageSummaryPath = path.resolve(
    repositoryRoot,
    'coverage',
    'coverage-summary.json',
);
const badgeOutputPath = path.resolve(
    repositoryRoot,
    'docs',
    'public',
    'coverage-badge.json',
);
const summaryOutputPath = path.resolve(
    repositoryRoot,
    'docs',
    'public',
    'coverage-summary.json',
);

const repositoryRootPrefix = (repositoryRootPath: string): string =>
    repositoryRootPath.endsWith('/')
        ? repositoryRootPath
        : `${repositoryRootPath}/`;

export const colorForCoverage = (percent: number): string => {
    if (percent >= 95) {
        return 'brightgreen';
    }
    if (percent >= 90) {
        return 'green';
    }
    if (percent >= 80) {
        return 'yellowgreen';
    }
    if (percent >= 70) {
        return 'yellow';
    }
    if (percent >= 60) {
        return 'orange';
    }

    return 'red';
};

export const normalizeCoverageKey = (
    coverageKey: string,
    projectRoot: string,
): string => {
    if (coverageKey === 'total') {
        return coverageKey;
    }

    const normalizedProjectRoot = projectRoot.replace(/\\/gu, '/');
    const projectRootPrefix = repositoryRootPrefix(normalizedProjectRoot);
    const lowerProjectRootPrefix = projectRootPrefix.toLowerCase();
    const normalizedCoverageKey = coverageKey.replace(/\\/gu, '/');

    if (normalizedCoverageKey.startsWith(projectRootPrefix)) {
        return normalizedCoverageKey.slice(projectRootPrefix.length);
    }

    if (
        /^[A-Za-z]:\//u.test(normalizedCoverageKey) &&
        normalizedCoverageKey.toLowerCase().startsWith(lowerProjectRootPrefix)
    ) {
        return normalizedCoverageKey.slice(projectRootPrefix.length);
    }

    return normalizedCoverageKey;
};

export const normalizeCoverageSummary = (
    summary: CoverageSummary,
    projectRoot: string,
): CoverageSummary => {
    const normalizedEntries = Object.entries(summary).map(
        ([coverageKey, coverageEntry]) =>
            [
                normalizeCoverageKey(coverageKey, projectRoot),
                coverageEntry,
            ] as const,
    );

    normalizedEntries.sort(([leftCoverageKey], [rightCoverageKey]) => {
        if (leftCoverageKey === 'total') {
            return -1;
        }
        if (rightCoverageKey === 'total') {
            return 1;
        }

        return leftCoverageKey.localeCompare(rightCoverageKey);
    });

    return Object.fromEntries(normalizedEntries);
};

export const totalLineMetric = (summary: CoverageSummary): CoverageMetric => {
    const totalCoverageEntry = summary.total;
    if (totalCoverageEntry === undefined) {
        throw new Error('Coverage summary is missing total metrics.');
    }

    const totalLineCoverageMetric = totalCoverageEntry.lines;
    if (totalLineCoverageMetric === undefined) {
        throw new Error('Coverage summary is missing total.lines metrics.');
    }

    return totalLineCoverageMetric;
};

export const buildCoverageBadge = (summary: CoverageSummary): ShieldsBadge => {
    const lineCoveragePercent =
        Math.round(totalLineMetric(summary).pct * 10) / 10;

    return {
        schemaVersion: 1,
        label: 'node source coverage',
        message: `${lineCoveragePercent.toFixed(1).replace(/\.0$/u, '')}%`,
        color: colorForCoverage(lineCoveragePercent),
    };
};

export const validateCoverageScope = (
    summary: CoverageSummary,
    requiredEntryPaths: readonly string[] = defaultRequiredCoverageEntryPaths,
): void => {
    const missingEntryPaths = requiredEntryPaths.filter(
        (requiredEntryPath) => summary[requiredEntryPath] === undefined,
    );

    if (missingEntryPaths.length > 0) {
        throw new Error(
            `Coverage summary is missing required source entries: ${missingEntryPaths.join(', ')}`,
        );
    }
};

export const createCoverageArtifacts = (
    rawSummary: CoverageSummary,
    projectRoot: string,
    options: CoverageArtifactsOptions = {},
): {
    readonly badge: ShieldsBadge;
    readonly summary: CoverageSummary;
} => {
    const summary = normalizeCoverageSummary(rawSummary, projectRoot);
    validateCoverageScope(summary, options.requiredEntryPaths);

    return {
        badge: buildCoverageBadge(summary),
        summary,
    };
};

const writeJsonFile = async (
    outputPath: string,
    value: unknown,
): Promise<void> => {
    await writeFile(outputPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
};

/* v8 ignore start */
const main = async (): Promise<void> => {
    const rawSummary = JSON.parse(
        await readFile(coverageSummaryPath, 'utf8'),
    ) as CoverageSummary;
    const { badge, summary } = createCoverageArtifacts(
        rawSummary,
        repositoryRoot,
    );

    await mkdir(path.dirname(badgeOutputPath), { recursive: true });
    await Promise.all([
        writeJsonFile(badgeOutputPath, badge),
        writeJsonFile(summaryOutputPath, summary),
    ]);

    console.log(
        `Coverage badge written to ${path.relative(repositoryRoot, badgeOutputPath)}`,
    );
};

if (isDirectlyInvokedModule(import.meta.url)) {
    void main();
}
/* v8 ignore stop */
