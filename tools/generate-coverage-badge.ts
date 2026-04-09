import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

type CoverageMetric = {
    covered: number;
    pct: number;
    skipped: number;
    total: number;
};

type CoverageEntry = {
    branches?: CoverageMetric;
    branchesTrue?: CoverageMetric;
    functions?: CoverageMetric;
    lines?: CoverageMetric;
    statements?: CoverageMetric;
};

type CoverageSummary = Record<string, CoverageEntry>;

type ShieldsBadge = {
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
const repoRootPath = repoRoot.replace(/\\/g, '/');
const repoRootPrefix = repoRootPath.endsWith('/')
    ? repoRootPath
    : `${repoRootPath}/`;
const lowerRepoRootPrefix = repoRootPrefix.toLowerCase();

const colorForCoverage = (percent: number): string => {
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

const normalizeCoverageKey = (key: string): string => {
    if (key === 'total') {
        return key;
    }

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

const normalizeCoverageSummary = (
    summary: CoverageSummary,
): CoverageSummary => {
    const normalizedEntries: [string, CoverageEntry][] = [];

    for (const [key, value] of Object.entries(summary)) {
        normalizedEntries.push([normalizeCoverageKey(key), value]);
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

const main = async (): Promise<void> => {
    const rawSummary = JSON.parse(
        await readFile(coverageSummaryPath, 'utf8'),
    ) as CoverageSummary;
    const summary = normalizeCoverageSummary(rawSummary);
    const totalLines = summary.total.lines;
    if (totalLines === undefined) {
        throw new Error('Coverage summary is missing total.lines metrics');
    }

    const percent = Number(totalLines.pct.toFixed(1));

    const badge: ShieldsBadge = {
        schemaVersion: 1,
        label: 'coverage',
        message: `${percent}%`,
        color: colorForCoverage(percent),
    };

    await mkdir(path.dirname(badgeOutputPath), { recursive: true });
    await writeFile(badgeOutputPath, `${JSON.stringify(badge, null, 2)}\n`);
    await writeFile(summaryOutputPath, `${JSON.stringify(summary, null, 2)}\n`);

    console.log(
        `Coverage badge written to ${path.relative(repoRoot, badgeOutputPath)}`,
    );
};

void main();
