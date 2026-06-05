import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export const createTemporaryDirectory = (): Promise<string> =>
    mkdtemp(path.join(os.tmpdir(), 'sealed-lattice-check-progress-'));

export const waitForTimeout = (durationMilliseconds: number): Promise<void> =>
    new Promise((resolve) => {
        setTimeout(resolve, durationMilliseconds);
    });

export const ansiEscapePattern = new RegExp(
    String.raw`\u001B\[[0-?]*[ -/]*[@-~]`,
    'gu',
);
