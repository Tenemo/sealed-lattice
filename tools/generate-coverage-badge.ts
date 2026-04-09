import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export type CoverageMetric = {
    covered: number;
    pct: number;
    skipped: number;
    total: number;
};

export type CoverageEntry = {
    branches?: CoverageMetric;
    branchesTrue?: CoverageMetric;
    functions?: CoverageMetric;
    lines?: CoverageMetric;
    statements?: CoverageMetric;
};

export type CoverageSummary = Record<string, CoverageEntry>;

export type ShieldsBadge = {
    color: string;
    label: string;
    message: string;
    schemaVersion: 1;
};

const repoRoot = process.cwd();
const coverageSummaryPath = path.resolve(
    repoRoot,
    'coverage/coverage-summary.json',
);
const badgeOutputPath = path.resolve(
    repoRoot,
    'docs/public/coverage-badge.json',
);
const summaryOutputPath = path.resolve(
    repoRoot,
    'docs/public/coverage-summary.json',
);
const getRepoRootPrefix = (repoRootPath: string): string =>
    repoRootPath.endsWith('/') ? repoRootPath : `${repoRootPath}/`;

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
    key: string,
    projectRoot: string,
): string => {
    if (key === 'total') {
        return key;
    }

    const repoRootPath = projectRoot.replace(/\\/g, '/');
    const repoRootPrefix = getRepoRootPrefix(repoRootPath);
    const lowerRepoRootPrefix = repoRootPrefix.toLowerCase();
    const normalizedKey = key.replace(/\\/g, '/');
    if (normalizedKey.startsWith(repoRootPrefix)) {
        return normalizedKey.slice(repoRootPrefix.length);
    }

    if (
        /^[A-Za-z]:\//.test(normalizedKey) &&
        normalizedKey.toLowerCase().startsWith(lowerRepoRootPrefix)
    ) {
        return normalizedKey.slice(repoRootPrefix.length);
    }

    return normalizedKey;
};

export const normalizeCoverageSummary = (
    summary: CoverageSummary,
    projectRoot: string,
): CoverageSummary => {
    const normalizedEntries: [string, CoverageEntry][] = [];

    for (const [key, value] of Object.entries(summary)) {
        normalizedEntries.push([normalizeCoverageKey(key, projectRoot), value]);
    }

    normalizedEntries.sort(([leftKey], [rightKey]) => {
        if (leftKey === 'total') {
            return -1;
        }
        if (rightKey === 'total') {
            return 1;
        }

        return leftKey.localeCompare(rightKey);
    });

    const normalizedSummary: CoverageSummary = {};
    for (const [key, value] of normalizedEntries) {
        normalizedSummary[key] = value;
    }

    return normalizedSummary;
};

export const getTotalLinesMetric = (
    summary: CoverageSummary,
): CoverageMetric => {
    const total = summary.total;
    if (total === undefined) {
        throw new Error('Coverage summary is missing total metrics');
    }

    const totalLines = total.lines;
    if (totalLines === undefined) {
        throw new Error('Coverage summary is missing total.lines metrics');
    }

    return totalLines;
};

export const buildCoverageBadge = (summary: CoverageSummary): ShieldsBadge => {
    const totalLines = getTotalLinesMetric(summary);
    const percent = Number(totalLines.pct.toFixed(1));

    return {
        schemaVersion: 1,
        label: 'coverage',
        message: `${percent}%`,
        color: colorForCoverage(percent),
    };
};

export const createCoverageArtifacts = (
    rawSummary: CoverageSummary,
    projectRoot: string,
): {
    badge: ShieldsBadge;
    summary: CoverageSummary;
} => {
    const summary = normalizeCoverageSummary(rawSummary, projectRoot);
    const badge = buildCoverageBadge(summary);

    return { badge, summary };
};

const main = async (): Promise<void> => {
    const rawSummary = JSON.parse(
        await readFile(coverageSummaryPath, 'utf8'),
    ) as CoverageSummary;
    const { badge, summary } = createCoverageArtifacts(rawSummary, repoRoot);

    await mkdir(path.dirname(badgeOutputPath), { recursive: true });
    await writeFile(badgeOutputPath, `${JSON.stringify(badge, null, 2)}\n`);
    await writeFile(summaryOutputPath, `${JSON.stringify(summary, null, 2)}\n`);

    console.log(
        `Coverage badge written to ${path.relative(repoRoot, badgeOutputPath)}`,
    );
};

const scriptEntryPoint = process.argv[1];
const isMainModule =
    scriptEntryPoint !== undefined &&
    import.meta.url === pathToFileURL(scriptEntryPoint).href;

if (isMainModule) {
    void main();
}
