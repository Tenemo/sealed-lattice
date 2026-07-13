export type LibtestResult = 'ok' | 'FAILED' | 'ignored';

const runningTestsPattern = /^running (\d+) tests?$/u;
const finishedTestPattern = /^test (\S+) \.\.\. (ok|FAILED|ignored)\b/u;
const startedTestPattern = /^test (\S+) \.\.\.(?:\s|$)/u;
const resultOnlyPattern = /^(ok|FAILED|ignored)\b/u;
const slowTestNoticePattern = /\bhas been running for over \d+ seconds?\b/u;

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

export const isLibtestSlowTestNotice = (line: string): boolean =>
    slowTestNoticePattern.test(line);
