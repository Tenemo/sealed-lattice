import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export type JsonCheckpointStore = {
    readonly directory: string;
    readonly read: (checkpointName: string) => unknown;
    readonly write: (checkpointName: string, value: unknown) => void;
};

const checkpointNamePattern = /^[a-z0-9-]+$/u;

export const defaultTestCheckpointDirectory = (): string =>
    path.resolve(process.cwd(), 'temp', 'test-checkpoints');

export const shouldResumeFromTestCheckpoints = (): boolean =>
    process.env.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS === '1';

const checkpointPath = (directory: string, checkpointName: string): string => {
    if (!checkpointNamePattern.test(checkpointName)) {
        throw new Error(`Invalid test checkpoint name: ${checkpointName}`);
    }

    return path.join(directory, `${checkpointName}.json`);
};

export const createJsonCheckpointStore = (
    input: {
        readonly directory?: string;
        readonly enabled?: boolean;
    } = {},
): JsonCheckpointStore => {
    const directory = input.directory ?? defaultTestCheckpointDirectory();
    const enabled = input.enabled ?? true;

    return {
        directory,
        read: (checkpointName) => {
            if (!enabled) {
                return undefined;
            }

            const filePath = checkpointPath(directory, checkpointName);
            if (!existsSync(filePath)) {
                return undefined;
            }

            return JSON.parse(readFileSync(filePath, 'utf8')) as unknown;
        },
        write: (checkpointName, value) => {
            if (!enabled) {
                return;
            }

            mkdirSync(directory, { recursive: true });
            writeFileSync(
                checkpointPath(directory, checkpointName),
                `${JSON.stringify(value, null, 2)}\n`,
                'utf8',
            );
        },
    };
};
