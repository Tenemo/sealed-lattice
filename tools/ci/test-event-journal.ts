import { appendFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

type TestEventWriter = (
    event: string,
    details?: Readonly<Record<string, unknown>>,
) => void;

export const createTestEventWriter = (input: {
    readonly eventFilePath?: string;
    readonly now?: () => Date;
    readonly projectLabel: string;
}): TestEventWriter => {
    if (input.eventFilePath === undefined) {
        return (): void => undefined;
    }
    mkdirSync(path.dirname(input.eventFilePath), { recursive: true });
    const now = input.now ?? (() => new Date());
    const startedAtMilliseconds = performance.now();
    let sequence = 0;

    return (event, details = {}): void => {
        appendFileSync(
            input.eventFilePath!,
            `${JSON.stringify({
                ...details,
                elapsedMilliseconds: Math.round(
                    performance.now() - startedAtMilliseconds,
                ),
                event,
                objectVersion: 'sealed-lattice-test-diagnostic-event-v1',
                processIdentifier: process.pid,
                projectLabel: input.projectLabel,
                sequence: ++sequence,
                timestampIso: now().toISOString(),
            })}\n`,
            'utf8',
        );
    };
};
