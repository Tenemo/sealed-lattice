import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { encodeResearchProfileTable } from '#tests/research-profile-table-model.js';

const usage =
    'Usage: generate-research-profile-table.ts (--output <file> | --check <file>)';

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const argumentsList =
        rawArguments[0] === '--' ? rawArguments.slice(1) : rawArguments;
    if (argumentsList.length !== 2 || argumentsList[1] === undefined) {
        throw new Error(usage);
    }
    const targetPath = path.resolve(argumentsList[1]);
    const table = encodeResearchProfileTable();
    if (argumentsList[0] === '--output') {
        await writeFile(targetPath, table);
        process.stdout.write(
            `Wrote ${String(table.length)} bytes to ${targetPath}\n`,
        );
        return;
    }
    if (argumentsList[0] === '--check') {
        if (!table.equals(await readFile(targetPath))) {
            throw new Error(
                'The stored profile table is stale; regenerate it with --output.',
            );
        }
        process.stdout.write('The stored profile table matches the models.\n');
        return;
    }
    throw new Error(usage);
};

if (import.meta.main) await main();
