import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

// One step's outcome in a renewal. Run directories are relative to the
// repository root, with forward slashes, so a record reads the same from
// every checkout whose logs are the repository's.
export type EvidenceRenewalStepRecord = Readonly<{
    name: string;
    exitCode: number;
    // A failure the renewal found although the command exited cleanly.
    failure?: string;
    startedAtIso: string;
    finishedAtIso: string;
    // The renewed checkout's commit.
    commit: string;
    // Every run the step's processes created.
    runs: readonly string[];
    // The step's own run among them.
    run?: string;
    monitorRun?: string;
    placement?: Readonly<{ affinityMask: string; priority: string }>;
    peakProcessTreeBytes?: number;
    // The renewal run that executed the step, absent for a step recorded
    // outside one.
    renewal?: string;
}>;

export const stepPassed = (record: EvidenceRenewalStepRecord): boolean =>
    record.exitCode === 0 && record.failure === undefined;

export const recordedStepEventType = 'renewal-step-recorded';

const repositoryRunPattern = /^logs\/\d{4}-\d{2}-\d{2}\/[^/\\]+$/u;

// The run directory relative to the repository root, as records hold it.
export const repositoryRelativeRun = (
    repositoryRoot: string,
    runDirectoryPath: string,
): string => {
    const relative = path
        .relative(repositoryRoot, runDirectoryPath)
        .split(path.sep)
        .join('/');
    if (!repositoryRunPattern.test(relative))
        throw new Error(
            `${runDirectoryPath} is not a run directory of this repository's logs.`,
        );
    return relative;
};

const parseStepRecord = (
    value: unknown,
    source: string,
): EvidenceRenewalStepRecord => {
    const fail = (problem: string): never => {
        throw new Error(`${source} holds a malformed step record: ${problem}`);
    };
    if (typeof value !== 'object' || value === null) fail('not an object.');
    const record = value as Record<string, unknown>;
    const text = (name: string, optional = false): string | undefined => {
        const field = record[name];
        if (field === undefined && optional) return undefined;
        if (typeof field !== 'string' || field.length === 0)
            fail(`${name} is not a nonempty string.`);
        return field as string;
    };
    const runPath = (name: string, field: unknown): string => {
        if (typeof field !== 'string' || !repositoryRunPattern.test(field))
            fail(`${name} is not a repository run directory.`);
        return field as string;
    };
    const time = (name: string): string => {
        const field = text(name) as string;
        if (Number.isNaN(Date.parse(field))) fail(`${name} is not a time.`);
        return field;
    };
    const name = text('name') as string;
    if (
        typeof record.exitCode !== 'number' ||
        !Number.isSafeInteger(record.exitCode)
    )
        fail('exitCode is not an integer.');
    const commit = text('commit') as string;
    if (!/^[0-9a-f]{40}$/u.test(commit)) fail('commit is not a commit.');
    if (!Array.isArray(record.runs)) fail('runs is not a list.');
    const runs = (record.runs as unknown[]).map((run) => runPath('runs', run));
    const run =
        record.run === undefined ? undefined : runPath('run', record.run);
    if (run !== undefined && !runs.includes(run))
        fail('run is not one of its runs.');
    const monitorRun =
        record.monitorRun === undefined
            ? undefined
            : runPath('monitorRun', record.monitorRun);
    const placement = record.placement;
    if (
        placement !== undefined &&
        (typeof placement !== 'object' ||
            placement === null ||
            typeof (placement as Record<string, unknown>).affinityMask !==
                'string' ||
            typeof (placement as Record<string, unknown>).priority !== 'string')
    )
        fail('placement is not a placement.');
    const peak = record.peakProcessTreeBytes;
    if (
        peak !== undefined &&
        (typeof peak !== 'number' || !Number.isSafeInteger(peak) || peak < 0)
    )
        fail('peakProcessTreeBytes is not a byte count.');
    const failure = text('failure', true);
    const renewal =
        record.renewal === undefined
            ? undefined
            : runPath('renewal', record.renewal);
    return {
        name,
        exitCode: record.exitCode as number,
        ...(failure === undefined ? {} : { failure }),
        startedAtIso: time('startedAtIso'),
        finishedAtIso: time('finishedAtIso'),
        commit,
        runs,
        ...(run === undefined ? {} : { run }),
        ...(monitorRun === undefined ? {} : { monitorRun }),
        ...(placement === undefined
            ? {}
            : {
                  placement:
                      placement as EvidenceRenewalStepRecord['placement'],
              }),
        ...(peak === undefined ? {} : { peakProcessTreeBytes: peak as number }),
        ...(renewal === undefined ? {} : { renewal }),
    };
};

// A renewal's step records by step name: from a renewal run directory's
// events, which keep every step a stopped renewal recorded, or from a record
// file of the form `{ "steps": [...] }`. A later record of a step replaces an
// earlier one.
export const readEvidenceRenewalRecord = async (
    source: string,
): Promise<ReadonlyMap<string, EvidenceRenewalStepRecord>> => {
    const records = new Map<string, EvidenceRenewalStepRecord>();
    let commit: string | undefined;
    const accept = (value: unknown) => {
        const record = parseStepRecord(value, source);
        if (commit !== undefined && record.commit !== commit)
            throw new Error(
                `${source} mixes commits ${commit} and ${record.commit}.`,
            );
        commit = record.commit;
        records.set(record.name, record);
    };
    if ((await stat(source)).isDirectory()) {
        const text = await readFile(path.join(source, 'events.jsonl'), 'utf8');
        // A line the renewal is still writing ends without a line break.
        const lines = text.split('\n');
        lines.pop();
        for (const line of lines) {
            const event = JSON.parse(line) as {
                details?: unknown;
                eventType?: unknown;
            };
            if (event.eventType !== recordedStepEventType) continue;
            accept(event.details);
        }
        return records;
    }
    const parsed = JSON.parse(await readFile(source, 'utf8')) as unknown;
    if (
        typeof parsed !== 'object' ||
        parsed === null ||
        !Array.isArray((parsed as { steps?: unknown }).steps)
    )
        throw new Error(`${source} lists no steps.`);
    const declaredCommit = (parsed as { commit?: unknown }).commit;
    if (declaredCommit !== undefined) {
        if (
            typeof declaredCommit !== 'string' ||
            !/^[0-9a-f]{40}$/u.test(declaredCommit)
        )
            throw new Error(`${source} names a malformed commit.`);
        commit = declaredCommit;
    }
    for (const value of (parsed as { steps: unknown[] }).steps) accept(value);
    return records;
};

// A run directory's date and name, which identify it in every checkout that
// shares the repository's logs, whatever path reached it.
const runKey = (runDirectoryPath: string): string =>
    `${path.basename(path.dirname(runDirectoryPath))}/${path.basename(runDirectoryPath)}`;

// Run directory names begin with their start time.
const runNamePrefix = (time: Date): string =>
    time.toISOString().replace(/:/gu, '-');

const utcDates = (from: Date, to: Date): string[] => {
    const dates: string[] = [];
    for (
        let day = Date.UTC(
            from.getUTCFullYear(),
            from.getUTCMonth(),
            from.getUTCDate(),
        );
        day <= to.getTime();
        day += 86_400_000
    )
        dates.push(new Date(day).toISOString().slice(0, 10));
    return dates;
};

// The runs, oldest first, that started in the inclusive interval from `since`
// through `until` (now by default) and whose metadata names the parent run.
// A run whose metadata has not yet been written names no parent.
export const listChildRuns = async (input: {
    readonly repositoryRoot: string;
    readonly parentRunDirectoryPath: string;
    readonly since: Date;
    readonly until?: Date;
}): Promise<readonly Readonly<{ run: string; scriptName: string }>[]> => {
    const parent = runKey(input.parentRunDirectoryPath);
    const earliest = runNamePrefix(input.since);
    const until = input.until ?? new Date();
    const latest = runNamePrefix(until);
    const children: { run: string; scriptName: string }[] = [];
    for (const date of utcDates(input.since, until)) {
        const dateDirectoryPath = path.join(input.repositoryRoot, 'logs', date);
        let names: string[];
        try {
            names = await readdir(dateDirectoryPath);
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
            throw error;
        }
        for (const name of names.sort()) {
            const timestamp = name.slice(0, earliest.length);
            if (timestamp < earliest || timestamp > latest) continue;
            let metadata: {
                parentRunDirectoryPath?: unknown;
                scriptName?: unknown;
            };
            try {
                metadata = JSON.parse(
                    await readFile(
                        path.join(dateDirectoryPath, name, 'metadata.json'),
                        'utf8',
                    ),
                ) as typeof metadata;
            } catch (error) {
                if (
                    error instanceof SyntaxError ||
                    (error as NodeJS.ErrnoException).code === 'ENOENT'
                )
                    continue;
                throw error;
            }
            if (
                typeof metadata.parentRunDirectoryPath === 'string' &&
                runKey(metadata.parentRunDirectoryPath) === parent &&
                typeof metadata.scriptName === 'string'
            )
                children.push({
                    run: `logs/${date}/${name}`,
                    scriptName: metadata.scriptName,
                });
        }
    }
    return children;
};
