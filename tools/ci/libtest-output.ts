export type LibtestResult = 'ok' | 'FAILED' | 'ignored';

type LibtestResultSummary = {
    readonly failedTestCount: number;
    readonly filteredOutTestCount: number;
    readonly ignoredTestCount: number;
    readonly measuredTestCount: number;
    readonly passedTestCount: number;
};

const runningTestsPattern = /^running (\d+) tests?$/u;
const finishedTestPattern = /^test (\S+) \.\.\. (ok|FAILED|ignored)\b/u;
const startedTestPattern = /^test (\S+) \.\.\.(?:\s|$)/u;
const resultOnlyPattern = /^(ok|FAILED|ignored)\b/u;
const slowTestNoticePattern = /\bhas been running for over \d+ seconds?\b/u;
const resultSummaryPattern =
    /^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out(?:;|$)/u;

export const parseLibtestRunningTestCount = (
    line: string,
): number | undefined => {
    const runningMatch = runningTestsPattern.exec(line.trim());

    return runningMatch?.[1] === undefined
        ? undefined
        : Number(runningMatch[1]);
};

export const parseLibtestFinishedTestLine = (
    line: string,
):
    | { readonly testName: string; readonly result: LibtestResult }
    | undefined => {
    const finishedMatch = finishedTestPattern.exec(line.trim());
    if (finishedMatch?.[1] === undefined || finishedMatch[2] === undefined) {
        return undefined;
    }

    return {
        testName: finishedMatch[1],
        result: finishedMatch[2] as LibtestResult,
    };
};

export const parseLibtestStartedTestName = (line: string): string | undefined =>
    startedTestPattern.exec(line.trim())?.[1];

export const parseLibtestStandaloneResult = (
    line: string,
): LibtestResult | undefined =>
    resultOnlyPattern.exec(line.trim())?.[1] as LibtestResult | undefined;

export const parseLibtestResultSummary = (
    line: string,
): LibtestResultSummary | undefined => {
    const summaryMatch = resultSummaryPattern.exec(line.trim());
    if (
        summaryMatch?.[1] === undefined ||
        summaryMatch[2] === undefined ||
        summaryMatch[3] === undefined ||
        summaryMatch[4] === undefined ||
        summaryMatch[5] === undefined
    ) {
        return undefined;
    }

    return {
        passedTestCount: Number(summaryMatch[1]),
        failedTestCount: Number(summaryMatch[2]),
        ignoredTestCount: Number(summaryMatch[3]),
        measuredTestCount: Number(summaryMatch[4]),
        filteredOutTestCount: Number(summaryMatch[5]),
    };
};

export const isLibtestSlowTestNotice = (line: string): boolean =>
    slowTestNoticePattern.test(line);
